import logging
import datetime
import time
import secrets
import socket
from flask import Flask, render_template, request, session, flash
from flask_bootstrap import Bootstrap5
from apscheduler.schedulers.background import BackgroundScheduler
from flask_session import Session
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet

logging.basicConfig(level=logging.DEBUG)

# Initialize Flask App
app = Flask(__name__)
app.config.from_pyfile("config.py")
app.secret_key = app.config.get("SECRET_KEY", secrets.token_hex(16))

# Portal IP address - default local socket IP
PORTAL_IP = app.config.get("PORTAL_IP", str(socket.gethostbyname(socket.gethostname())))
# Max Session duration in seconds - default 1 hour
RADIUS_SESSION_DURATION = app.config.get("DEFAULT_RADIUS_SESSION_DURATION", 3600)

# Initialize Bootstrap5 integration
bootstrap = Bootstrap5(app)
# Initialize the Flask Session
Session(app)
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


@app.route("/", methods=["GET", "POST"])
def index():
    logging.debug(
        "Serving index request:"
        f" {request.method} for user:{request.form.get('username')} session:{session}"
    )

    remote_ip = request.headers.get('X-Forwarded-For', str(request.remote_addr))
    
    # Has the session ended since the last request?
    if request.method == "GET":
        if "end" in session and session["end"] < time.time():
            logout()

    if request.method == "POST":
        if "login" in request.form:
            if not request.form["username"] or not request.form["password"]:
                flash("Please provide username and password", "warning")
            # Process login request
            else:
                result = login(request.form["username"], request.form["password"])
                if result is True:
                    flash("Succesfully logged in", "success")
                else:
                    flash(f"{result} ", "danger")

        elif "logout" in request.form:
            if logout() is True:
                flash("Succesfully logged out", "success")

        elif "extend" in request.form and "duration" in session:
            session["start"] = time.time()
            session["end"] = session["start"] + session["duration"]
            # Reschedule background job if it exists
            if "job_id" in session and background_scheduler.get_job(session["job_id"]):
                background_scheduler.reschedule_job(
                    session["job_id"],
                    "default",
                    "date",
                    run_date=datetime.datetime.now()
                    + datetime.timedelta(seconds=session["duration"]),
                )
            flash("Succesfully extended session", "success")

    return render_template(
        "index.html.jinja", session=session, ts=session.get("end", 0), remote_ip=remote_ip
    )


def logout():
    # Execute background job if it still exists
    if "job_id" in session and (job := background_scheduler.get_job(session["job_id"])):
        logging.debug(
            f"Logging out and running logout job {session.get('job_id', 'N/A')}"
        )
        job.modify(next_run_time=datetime.datetime.now())
    else:
        logging.debug(f"Logging out but job {session['job_id']} not found")

    session.clear()
    return True


def login(username, password):
    global srv

    remote_ip = request.headers.get('X-Forwarded-For', str(request.remote_addr))
    req = srv.CreateAuthPacket()

    req["User-Name"] = username
    req["Password"] = req.PwCrypt(password)
    req["NAS-IP-Address"] = PORTAL_IP
    req["Calling-Station-Id"] = remote_ip
    req["Framed-IP-Address"] = remote_ip

    try:
        reply = srv.SendPacket(req)
    except Exception as error:
        logging.error(
            "Radius Server timeout or error, switching to backup server and retrying"
            " backup"
        )
        if srv == srv_primary and srv_backup:
            srv = srv_backup
            login(username, password)
            flash(
                "Primary radius server timed out, switched to backup radius server",
                "warning",
            )
        elif srv == srv_backup:
            srv = srv_primary
            logging.error(
                "Backup radius server timeout or error, switched back to primary server"
                " and not retrying"
            )
            session.pop("_flashes", None)
            flash(
                (
                    "All radius servers timed out, switching back to primary server and"
                    " not retrying"
                ),
                "danger",
            )
        return error

    logging.debug(f"Auth Reply: {reply}")

    if reply.code == pyrad.packet.AccessAccept:
        # Honor radius timeout attributes or use default session duration
        if reply.get("Session-Timeout"):
            session["duration"] = reply["Session-Timeout"][0]
            logging.debug(
                f"Using radius server attribute Session-Timeout: {session['duration']}"
            )
        elif reply.get("Idle-Timeout"):
            session["duration"] = reply["Idle-Timeout"][0]
            logging.debug(
                f"Using radius server attribute Idle-Timeout: {session['duration']}"
            )
        else:
            # Default session duration
            session["duration"] = RADIUS_SESSION_DURATION
            logging.debug(f"Using configured session timeout: {session['duration']}")

        session_id = reply["Class"][0].decode("utf-8").split(":")[2]

        session["username"] = username
        session["class"] = reply["Class"]
        session["id"] = session_id
        session["ip"] = remote_ip
        session["start"] = time.time()
        session["end"] = session["start"] + session["duration"]

        logging.info(
            f"Radius Session {reply['Class']} started for {username} for"
            f" {session['duration']} seconds"
        )

        # Starts and add a job to terminate the session after SESSION_DURATION seconds
        accounting_session(True, session["username"], session["id"], session["ip"])
        job = background_scheduler.add_job(
            accounting_session,
            "date",
            [False, session["username"], session["id"], session["ip"]],
            name=session_id,
            run_date=datetime.datetime.now()
            + datetime.timedelta(seconds=session["duration"]),
        )
        session["job_id"] = job.id
        return True

    # Access Reject from Server
    elif reply.code == pyrad.packet.AccessReject:
        logging.warning(f"Access Denied for {username}")
        return "Unknown user or incorrect password"

    # Other problem
    else:
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
    else:
        req["Acct-Status-Type"] = "Stop"
        logging.info(
            f"Asking radius server to terminate session {session_id} for"
            f" {username} with request {req}"
        )

    try:
        srv.SendPacket(req)
    except Exception as error:
        logging.error(f"Accounting call radius server error: {error}")
        return error

    return True


if __name__ == "__main__":
    app.run(
        host="0.0.0.0", port=8443, ssl_context=("server.cer", "server.key"), debug=False
    )
