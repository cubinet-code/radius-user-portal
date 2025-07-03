import logging
import datetime
import time
import secrets
import socket
import uuid
import re
from flask import Flask, render_template, request, session, flash, abort, make_response
from flask_bootstrap import Bootstrap5
from apscheduler.schedulers.background import BackgroundScheduler
from flask_session import Session
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, Regexp
from cachelib import FileSystemCache
from flask_talisman import Talisman
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet

logging.basicConfig(level=logging.DEBUG)
logging.info("RADIUS User Portal starting up")

# Initialize Flask App
app = Flask(__name__)
app.config.from_pyfile("config.py")
app.secret_key = app.config.get("SECRET_KEY", secrets.token_hex(16))

# Portal IP address - default local socket IP
PORTAL_IP = app.config.get("PORTAL_IP", str(socket.gethostbyname(socket.gethostname())))
# Max Session duration in seconds - default 1 hour
RADIUS_SESSION_DURATION = app.config.get("DEFAULT_RADIUS_SESSION_DURATION", 3600)

# Circuit breaker variables for RADIUS failures
RADIUS_FAILURE_COUNT = 0
RADIUS_FAILURE_THRESHOLD = 5
RADIUS_BACKOFF_TIME = 60

# Input validation constants
MAX_USERNAME_LENGTH = 63  # RADIUS standard
MAX_PASSWORD_LENGTH = 128  # RADIUS standard
# RADIUS-compatible character pattern (configurable via config.py)
RADIUS_CHAR_PATTERN = re.compile(app.config.get('RADIUS_CHAR_PATTERN', r'^[a-zA-Z0-9@._-]+$'))

# Configure CacheLib session backend (replaces deprecated filesystem backend)
app.config['SESSION_CACHELIB'] = FileSystemCache(cache_dir='flask_session', threshold=500)

# Initialize Bootstrap5 integration
bootstrap = Bootstrap5(app)
# Initialize CSRF protection
csrf = CSRFProtect(app)
# Initialize the Flask Session
Session(app)
# Initialize Flask-Talisman for security headers including CSP
csp = {
    'default-src': "'self'",
    'script-src': "'self'",
    'style-src': "'self' 'unsafe-inline'",  # Bootstrap requires inline styles
    'img-src': "'self' data:",
    'font-src': "'self'",
    'connect-src': "'self'",
    'frame-ancestors': "'none'"
}
talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    force_https=False  # Allow HTTP for development
)
# Initialize the Background Session Scheduler
background_scheduler = BackgroundScheduler()
background_scheduler.start()

# Initialize the RADIUS Clients and backup if configured
srv_primary = Client(
    server=app.config["RADIUS_SERVER"],
    secret=bytes(app.config["RADIUS_SECRET"], "utf-8"),
    dict=Dictionary("dictionary"),
)
srv_primary.retries = 2
srv_primary.timeout = 2
srv_backup = None
if app.config.get("RADIUS_SERVER_BACKUP"):
    srv_backup = Client(
        server=app.config["RADIUS_SERVER_BACKUP"],
        secret=bytes(app.config["RADIUS_SECRET"], "utf-8"),
        dict=Dictionary("dictionary"),
    )
    srv_backup.retries = 2
    srv_backup.timeout = 2

# Start with primary server
srv = srv_primary


# Security headers are now handled by Flask-Talisman


class LoginForm(FlaskForm):
    """CSRF-protected login form with validation."""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(max=MAX_USERNAME_LENGTH, message=f'Username too long (max {MAX_USERNAME_LENGTH} characters)'),
        Regexp(RADIUS_CHAR_PATTERN, message='Username contains invalid characters')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(max=MAX_PASSWORD_LENGTH, message=f'Password too long (max {MAX_PASSWORD_LENGTH} characters)')
    ])
    submit = SubmitField('Login')


class LogoutForm(FlaskForm):
    """CSRF-protected logout form."""
    submit = SubmitField('Logout')


class ExtendForm(FlaskForm):
    """CSRF-protected session extension form."""
    duration = IntegerField('Duration', validators=[DataRequired()])
    submit = SubmitField('Extend Session')


def validate_input(username, password):
    """Validate username and password according to RADIUS standards."""
    errors = []
    
    # Check username length and characters
    if len(username) > MAX_USERNAME_LENGTH:
        errors.append(f"Username too long (max {MAX_USERNAME_LENGTH} characters)")
    if not RADIUS_CHAR_PATTERN.match(username):
        errors.append("Username contains invalid characters")
    
    # Check password length
    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password too long (max {MAX_PASSWORD_LENGTH} characters)")
    
    return errors


@app.route("/", methods=["GET", "POST"])
def index():
    logging.debug("Serving index request:" f" {request.method} for user:{request.form.get('username')} session:{session}")

    remote_ip = request.headers.get("X-Forwarded-For", str(request.remote_addr))
    
    # Initialize forms
    login_form = LoginForm()
    logout_form = LogoutForm()
    extend_form = ExtendForm()

    # Has the session ended since the last request?
    if request.method == "GET":
        if "end" in session and session["end"] < time.time():
            logging.info(f"Session expired for user {session.get('username', 'unknown')} from {remote_ip}")
            logout()

    if request.method == "POST":
        if "login" in request.form:
            if login_form.validate_on_submit():
                result = login(login_form.username.data, login_form.password.data, remote_ip)
                if result is True:
                    flash("Successfully logged in", "success")
                else:
                    flash(f"{result} ", "danger")
            else:
                # Form validation failed - flash errors but don't abort
                validation_errors = []
                for field, errors in login_form.errors.items():
                    for error in errors:
                        flash(f"{field}: {error}", "danger")
                        validation_errors.append(f"{field}: {error}")
                logging.warning(f"Login validation failed for user {request.form.get('username', 'unknown')} from {remote_ip}: {'; '.join(validation_errors)}")

        elif "logout" in request.form:
            if logout_form.validate_on_submit():
                if logout() is True:
                    flash("Successfully logged out", "success")
            else:
                logging.warning(f"Invalid logout request from user {session.get('username', 'unknown')} at {remote_ip}: CSRF validation failed")
                flash("Invalid logout request", "danger")

        elif "extend" in request.form and "duration" in session:
            if extend_form.validate_on_submit():
                session["start"] = time.time()
                session["end"] = session["start"] + session["duration"]
                # Reschedule background job if it exists
                try:
                    if "job_id" in session and background_scheduler.get_job(session["job_id"]):
                        background_scheduler.reschedule_job(
                            session["job_id"],
                            "default",
                            "date",
                            run_date=datetime.datetime.now() + datetime.timedelta(seconds=session["duration"]),
                        )
                    flash("Successfully extended session", "success")
                except Exception as e:
                    logging.error(f"Failed to reschedule background job for user {session.get('username', 'unknown')} (job_id: {session.get('job_id', 'N/A')}): {e}")
                    flash("Session extended but job rescheduling failed", "warning")
            else:
                logging.warning(f"Invalid session extend request from user {session.get('username', 'unknown')} at {remote_ip}: CSRF validation failed")
                flash("Invalid extend request", "danger")

    return render_template("index.html.jinja", session=session, ts=session.get("end", 0), remote_ip=remote_ip, 
                         login_form=login_form, logout_form=logout_form, extend_form=extend_form)


def logout():
    # Execute background job if it still exists
    try:
        if "job_id" in session and (job := background_scheduler.get_job(session["job_id"])):
            logging.debug(f"Logging out user {session.get('username', 'unknown')} and running logout job {session.get('job_id', 'N/A')}")
            job.modify(next_run_time=datetime.datetime.now())
        else:
            logging.debug(f"Logging out user {session.get('username', 'unknown')} but job {session.get('job_id', 'N/A')} not found")
    except Exception as e:
        logging.error(f"Error during logout job handling for user {session.get('username', 'unknown')} (job_id: {session.get('job_id', 'N/A')}): {e}")

    session.clear()
    return True


def login(username, password, remote_ip):
    global srv, RADIUS_FAILURE_COUNT

    # Circuit breaker check
    if RADIUS_FAILURE_COUNT >= RADIUS_FAILURE_THRESHOLD:
        logging.warning(f"Circuit breaker activated: {RADIUS_FAILURE_COUNT} consecutive RADIUS failures, blocking requests for {RADIUS_BACKOFF_TIME}s")
        return "RADIUS servers temporarily unavailable. Please try again later."

    req = srv.CreateAuthPacket()

    req["User-Name"] = username
    req["Password"] = req.PwCrypt(password)
    req["NAS-IP-Address"] = PORTAL_IP
    req["Calling-Station-Id"] = remote_ip
    req["Framed-IP-Address"] = remote_ip

    try:
        reply = srv.SendPacket(req)
        RADIUS_FAILURE_COUNT = 0  # Reset on success
        current_server = "primary" if srv == srv_primary else "backup"
        logging.debug(f"RADIUS {current_server} server ({getattr(srv, 'server', 'unknown')}) authentication successful for user {username}")
    except Exception as error:
        RADIUS_FAILURE_COUNT += 1
        current_server = "primary" if srv == srv_primary else "backup" 
        logging.error(f"RADIUS {current_server} server ({getattr(srv, 'server', 'unknown')}) failed for user {username}: {error} (failure #{RADIUS_FAILURE_COUNT})")
        
        if srv == srv_primary and srv_backup:
            srv = srv_backup
            logging.info(f"Switching to backup RADIUS server ({getattr(srv_backup, 'server', 'unknown')}) for user {username}")
            result = login(username, password, remote_ip)  # Store result
            flash(
                "Primary radius server timed out, switched to backup radius server",
                "warning",
            )
            return result  # Return the result
        elif srv == srv_backup:
            srv = srv_primary
            logging.error(f"Backup RADIUS server ({getattr(srv_backup, 'server', 'unknown')}) failed for user {username}, switched back to primary - no retry")
            flash(
                ("All radius servers timed out, switching back to primary server and not retrying"),
                "danger",
            )
        return str(error)

    logging.debug(f"Auth Reply: {reply}")

    if reply.code == pyrad.packet.AccessAccept:
        # Honor radius timeout attributes or use default session duration
        if reply.get("Session-Timeout"):
            session["duration"] = reply["Session-Timeout"][0]
            logging.debug(f"Using radius server attribute Session-Timeout: {session['duration']}")
        elif reply.get("Idle-Timeout"):
            session["duration"] = reply["Idle-Timeout"][0]
            logging.debug(f"Using radius server attribute Idle-Timeout: {session['duration']}")
        else:
            # Default session duration
            session["duration"] = RADIUS_SESSION_DURATION
            logging.debug(f"Using configured session timeout: {session['duration']}")

        # Handle missing Class attribute gracefully
        if "Class" in reply and reply["Class"]:
            session_id = reply["Class"][0].decode("utf-8").split(":")[2]
        else:
            # Generate a fallback session ID
            session_id = str(uuid.uuid4())
            logging.warning(f"No Class attribute in RADIUS reply, using generated session ID: {session_id}")

        session["username"] = username
        session["class"] = reply.get("Class", [])
        session["id"] = session_id
        session["ip"] = remote_ip
        session["start"] = time.time()
        session["end"] = session["start"] + session["duration"]

        current_server = "primary" if srv == srv_primary else "backup"
        logging.info(f"RADIUS session started: user={username}, session_id={session_id}, duration={session['duration']}s, ip={remote_ip}, server={current_server}({getattr(srv, 'server', 'unknown')})")

        # Starts and add a job to terminate the session after SESSION_DURATION seconds
        accounting_session(True, session["username"], session["id"], session["ip"])
        job = background_scheduler.add_job(
            accounting_session,
            "date",
            [False, session["username"], session["id"], session["ip"]],
            name=session_id,
            run_date=datetime.datetime.now() + datetime.timedelta(seconds=session["duration"]),
        )
        session["job_id"] = job.id
        return True

    # Access Reject from Server
    elif reply.code == pyrad.packet.AccessReject:
        current_server = "primary" if srv == srv_primary else "backup"
        logging.warning(f"RADIUS Access-Reject for user {username} from {remote_ip} on {current_server} server ({getattr(srv, 'server', 'unknown')})")
        return "Unknown user or incorrect password"

    # Other problem
    else:
        current_server = "primary" if srv == srv_primary else "backup"
        logging.error(f"Unknown RADIUS response code {reply.code} for user {username} from {current_server} server ({getattr(srv, 'server', 'unknown')})")
        return f"Unknown radius error: {reply.code}"


def accounting_session(start=True, username=None, session_id=None, ip=None):
    if not all([username, session_id, ip]):
        return False

    req = srv.CreateAcctPacket()

    req["User-Name"] = username
    req["NAS-IP-Address"] = PORTAL_IP
    req["Acct-Session-Id"] = session_id
    req["Calling-Station-Id"] = ip
    req["Framed-IP-Address"] = ip

    if start:
        req["Acct-Status-Type"] = "Start"
        logging.debug(f"Sending RADIUS Accounting-Start for user {username}, session_id {session_id}, ip {ip}")
    else:
        req["Acct-Status-Type"] = "Stop"
        logging.info(f"Sending RADIUS Accounting-Stop for user {username}, session_id {session_id}, ip {ip}")

    try:
        srv.SendPacket(req)
        action = "start" if start else "stop"
        logging.debug(f"RADIUS Accounting-{action} sent successfully for user {username}, session_id {session_id}")
    except Exception as error:
        action = "start" if start else "stop"
        current_server = "primary" if srv == srv_primary else "backup"
        logging.error(f"RADIUS Accounting-{action} failed for user {username}, session_id {session_id} on {current_server} server ({getattr(srv, 'server', 'unknown')}): {error}")
        return error

    return True


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, ssl_context=("server.cer", "server.key"), debug=False)
