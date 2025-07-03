# Radius Session User Portal

![Alt text](/tests/screenshot.png?raw=true)

## Introduction

This flask app is a simple portal for managing radius sessions. It is intended to be used with the a Radius Server like a Cisco ISE.
It was originaly developed for a Cisco ISE deployment as a custom portal to start Radius sessions for use with a Cisco Secure Firewall Manager (CSFM or FMC). The ISE session then gets replicated via Cisco's PXGrid protocol to the CSFM/FMC. The FMC then uses the session information to allow for user based firewall rules.

## Current functionality

- After login, the user can see his current session, refresh or disconnect it.
- The user will either be disconnected after the session duration or can disconnect it manually.
- The session duration can be controlled by the config.py or by radius attributes sent by the radius server.
- Radius server redundancy is supported with automatic failover.
- Session managment is server side, Cookies are encrypted and signed.
- Circuit breaker pattern implemented for RADIUS server failure handling.
- UUID fallback for missing RADIUS Class attributes to prevent crashes.
- Robust error handling to prevent server hanging and infinite recursion issues.

## Security Features

- **Input Validation**: Username and password validation according to RADIUS standards (length limits and character restrictions)
- **CSRF Protection**: Cross-Site Request Forgery protection on all forms using Flask-WTF
- **Security Headers**: Comprehensive HTTP security headers including CSP, X-Frame-Options, HSTS, and more
- **IP Validation**: Configurable X-Forwarded-For header validation to prevent IP spoofing attacks
- **Rate Limiting**: Circuit breaker pattern for RADIUS server failures to prevent DoS attacks

## Dependencies

The application requires the following Python packages (automatically installed via `requirements.txt`):

- **Flask~=3.1.1** - Web framework
- **Flask-Session~=0.8.0** - Server-side session management using CacheLib backend
- **Bootstrap-Flask~=2.5.0** - Bootstrap integration for Flask
- **APScheduler~=3.11.0** - Background task scheduling for session management
- **pyrad~=2.4** - RADIUS client library
- **gunicorn~=23.0.0** - WSGI HTTP Server for production deployment
- **Flask-WTF~=1.2.1** - CSRF protection and form handling
- **WTForms~=3.2.1** - Form validation and rendering
- **cachelib~=0.13.0** - Caching library backend for session storage
- **flask-talisman~=1.1.0** - Security headers and CSP management

## Installation with Ansible

An Ansible script has been provided for a simple installation on a Debian based system. It will install all required packages and configure the app to run as a systemd service.

It will install the app to /opt/radius-user-portal and create a virtual environment in /opt/radius-user-portal/venv.

```bash
# Clone the code to /opt/radius-user-portal (This location is required by the Ansible script)
git clone https://github.com/cubinet-code/radius-user-portal.git

# If you dont have Ansible installed, install it with:
sudo apt install ansible
# or
pip install ansible

# Then run the playbook with:
ansible-playbook -i 127.0.0.1, ansible-portal.yaml -e ansible_connection=local
```

Ansible installs a temporary self signed certificate for testing. You should replace it with your own certificate. Please see below for instructions.

You also still need to edit config.py to [configure](#required-configuration) the portal itself.

## Renew/Reissue SSL certificate

SSL certificates can only be valid for 365 days. You can renew your certificate with the following command:

```bash
create_server_csr.sh
```

After you receive the certificate file as X.509 PEM encoded file, rename it to server.crt and copy it to the app directory:

```bash
cp server.cer.example server.cer
# then restart the service
systemctl restart portal.service
```

## NTP Synchronization

The user portal uses the local clock to calculate the session duration. It is therefore important that the clock is synchronized with NTP. You can check the status with the following command:

```bash
timedatectl status
```

If the clock is not synchronized, you can enable NTP with the following command:

```bash
# Update the NTP server in /etc/systemd/timesyncd.conf
vi /etc/systemd/timesyncd.conf
# Then enable NTP
sudo timedatectl set-ntp true
sudo timedatectl set-timezone 'Europe/Berlin'
# Restart the service
sudo systemctl restart systemd-timesyncd.service
```

## Manual Installation - Getting the code

```bash
git clone https://github.com/cubinet-code/radius-user-portal.git
```

Optional: If you would like to run as a systemd service please update gunicorn.service with your path:

```bash
cp portal.example.service portal.service
vi portal.service
```

This will install all required python modules in a virtual environment and enable systemd service if portal.services exists.

```bash
./install.sh
```

### Without systemd - Manualy run the app in development mode

This starts the app in debug mode on your local machine port 8443:

```bash
python portal.py
```

### Without systemd - Manualy run the app in production mode

This starts the app in production mode on a scalable server without debugs:

```bash
./run.sh
```

The service will run by default on port 8443. You can change this in the run.sh or portal.py script.

## Required Configuration

Copy the example configuration file config.example.py and edit it to your needs.

```bash
cp config.example.py config.py
```

As you should run a service dealing with user passwords SSL protected, also copy the OPENSSL configuration file and edit it to your needs:

```bash
cp server.example.cnf server.cnf
```

Then issue the CSR (certificate signing request) server.csr for signing by your CA:

```bash
create_server_csr.sh
```

After you receive the certificate file as X.509 PEM encoded file, rename it to server.crt and copy it to the app directory.

```bash
cp server.cer.example server.cer
# then restart the service
systemctl restart portal.service
```

## Control the session timout with your radius server

You can send the following radius attributes from your radius server to control the session duration:

```
Idle-Timeout = <Timout in seconds>
# or
Session-Timeout = <Timout in seconds>
```

## Configuration file reference

```python
# Configuration file for the User Portal application

#
# Radius Parameters
#

# Local IP address of the server which is used as NAS-IP-Address, default is the first IP address of the server
# PORTAL_IP = "192.168.1.100"

# Radius server IP address and secret
RADIUS_SERVER = "192.168.1.101"
# Radius secret must match your server
RADIUS_SECRET = "radiuskey"
# Define a backup server if needed
# RADIUS_SERVER_BACKUP = "192.168.1.102"

# The default session duration below can be overriden by your radius server
# with a Session-Timeout(27) or Idle-Timeout(28) attribute
DEFAULT_RADIUS_SESSION_DURATION = 60 * 60 * 4  # 4 hours

# Username character validation pattern for RADIUS compatibility
# Default includes alphanumeric and common symbols safe for Cisco systems
# You can customize this pattern based on your RADIUS server requirements
RADIUS_CHAR_PATTERN = r'^[a-zA-Z0-9!#$%&\'()*+,./:;=?@_{-]+$'

# Circuit breaker functionality for RADIUS server failures
# After 5 consecutive RADIUS failures, requests are blocked for 60 seconds
# These values are hardcoded in portal.py but can be modified if needed:
# RADIUS_FAILURE_THRESHOLD = 5  # Number of failures before circuit breaker activates
# RADIUS_BACKOFF_TIME = 60      # Seconds to wait before retrying

#
# Web Server Parameters
#

# Flask secret key for signing cookie sessions, please change!
SECRET_KEY = "secretkey"
# Logo url for the login page
# LOGO_URL = "https://www.example.com/logo.png"

# Use Boostrap assets from local server
BOOTSTRAP_SERVE_LOCAL = True
# Where to store the session data - using CacheLib backend (recommended)
SESSION_TYPE = "cachelib"
# Session storage is configured automatically in portal.py using FileSystemCache

```

### Environment Variables

The following environment variables can be used to configure the application when running in production:

```bash
# Server configuration
PORT=8443                    # Port to bind the server to (default: 8443)
WORKERS=1                    # Number of gunicorn worker processes (default: 1)
THREADS=4                    # Number of threads per worker (default: 4)
SERVE_HTTP=TRUE              # Run in HTTP mode without SSL (for reverse proxy setups)
FORWARDED_ALLOW_IPS=127.0.0.1 # IPs allowed to set X-Forwarded-For header (default: 127.0.0.1)

# Example usage:
export PORT=8000
export WORKERS=2
export THREADS=8
export SERVE_HTTP=TRUE
export FORWARDED_ALLOW_IPS="127.0.0.1,10.0.0.1"  # Multiple IPs separated by commas
./run.sh
```

### Security Configuration

#### X-Forwarded-For Header Security

**⚠️ IMPORTANT SECURITY CONSIDERATION**

The application uses the `X-Forwarded-For` header to determine client IP addresses, which are used for RADIUS authentication and potentially firewall rules. By default, Gunicorn only accepts this header from localhost (127.0.0.1,::1) and strips it from other sources for security, but this can be configured.

**Configuration Options:**

1. **Direct Internet Access**: If the application runs directly on the internet without a proxy:
   ```bash
   # Don't set FORWARDED_ALLOW_IPS or set it to empty
   export FORWARDED_ALLOW_IPS=""
   ```

2. **Behind a Reverse Proxy**: If using a reverse proxy (nginx, HAProxy, etc.):
   ```bash
   # Set to your reverse proxy's IP address
   export FORWARDED_ALLOW_IPS="127.0.0.1,10.0.0.1"
   ```

3. **Kubernetes/Container Environments**: Set to the pod network or load balancer IP:
   ```bash
   # Example for Kubernetes
   export FORWARDED_ALLOW_IPS="10.244.0.0/16"
   ```

**Security Impact:**
- Incorrect configuration allows attackers to spoof source IPs
- This could bypass IP-based firewall rules in your network infrastructure
- Always restrict `FORWARDED_ALLOW_IPS` to trusted proxy servers only

#### Input Validation and Security Features

The application includes comprehensive security measures:

**Input Validation:**
- Username length limited to 63 characters (RADIUS standard)
- Password length limited to 128 characters (RADIUS standard)
- Character validation: configurable pattern via `RADIUS_CHAR_PATTERN` in config.py
- Default pattern includes: alphanumeric, ! # $ % & ' ( ) * + , - . / : ; = ? @ _ { }
- Returns HTTP 400 Bad Request for invalid inputs instead of 500 errors

**CSRF Protection:**
- All forms protected with CSRF tokens using Flask-WTF
- Prevents Cross-Site Request Forgery attacks
- Automatically enabled in production, disabled in test environment

**Security Headers (via Flask-Talisman):**
- Content Security Policy (CSP) with nonce-based inline script protection
- X-Frame-Options: DENY to prevent clickjacking
- X-Content-Type-Options: nosniff to prevent MIME sniffing
- Referrer-Policy: strict-origin-when-cross-origin
- HSTS header for HTTPS connections (max-age=31536000; includeSubDomains)
- Removed deprecated X-XSS-Protection header (CSP provides better protection)

**Session Security:**
- Server-side sessions using CacheLib filesystem backend
- Sessions stored in `flask_session` directory with 500 item threshold
- Signed and encrypted session cookies
- Configurable session timeouts via RADIUS attributes

## Troubleshooting

This section covers common issues and their solutions for the RADIUS User Portal.

### Viewing Logs

#### Systemd Service Logs

If the portal is running as a systemd service, you can view logs using:

```bash
# View real-time logs
sudo journalctl -u portal.service -f

# View logs from the last hour
sudo journalctl -u portal.service --since "1 hour ago"

# View all logs for the portal service
sudo journalctl -u portal.service --no-pager

# View logs with specific priority (error, warning, info, debug)
sudo journalctl -u portal.service -p err
```

### Restarting the Server

#### Systemd Service

```bash
# Restart the portal service
sudo systemctl restart portal.service

# Check service status
sudo systemctl status portal.service

# Stop the service
sudo systemctl stop portal.service

# Start the service
sudo systemctl start portal.service

# Reload configuration without restarting
sudo systemctl reload portal.service
```

#### Manual Process

If running manually:

```bash
# Find the process ID
ps aux | grep portal.py

# Kill the process (replace <PID> with actual process ID)
kill <PID>

# Or force kill if needed
kill -9 <PID>

# Restart manually
cd /opt/radius-user-portal
./run.sh
```

#### Docker/Container

```bash
# Restart container
docker restart <container-name>

# In Kubernetes
kubectl rollout restart deployment/portal
```

### Common Issues and Solutions

#### 1. Server Hanging or Becoming Unresponsive

**Symptoms:**

- Browser shows "page taking too long to respond"
- Application becomes unresponsive
- High CPU usage

**Solutions:**

```bash
# Check system resources
top
htop
free -h

# Restart the service
sudo systemctl restart portal.service

# Check for errors in logs
sudo journalctl -u portal.service -p err --since "1 hour ago"
```

#### 2. RADIUS Authentication Failures

**Symptoms:**

- Users cannot log in
- "Authentication failed" messages
- RADIUS timeout errors
- Message "RADIUS servers temporarily unavailable" (circuit breaker activated)

**Solutions:**

```bash
# Test RADIUS connectivity
# Install radclient if not available: sudo apt install freeradius-utils
echo "User-Name=testuser,User-Password=testpass" | radclient -x <RADIUS_SERVER>:1812 auth <RADIUS_SECRET>

# Check RADIUS server configuration in config.py
grep -E "RADIUS_SERVER|RADIUS_SECRET" /opt/radius-user-portal/config.py

# Check network connectivity
ping <RADIUS_SERVER>
telnet <RADIUS_SERVER> 1812

# Check if circuit breaker is activated (check recent logs for failure patterns)
sudo journalctl -u portal.service --since "30 minutes ago" | grep -i "radius.*timeout\|radius.*error\|temporarily unavailable"

# If circuit breaker is active, wait 60 seconds or restart the service to reset failure count
sudo systemctl restart portal.service
```

**Note:** The application includes a circuit breaker mechanism that temporarily blocks RADIUS requests after 5 consecutive failures to prevent overwhelming failed RADIUS servers. This automatically resets after 60 seconds or when the service is restarted.

#### 3. SSL Certificate Issues

**Symptoms:**

- Browser security warnings
- SSL handshake failures
- Certificate expired errors

**Solutions:**

```bash
# Check certificate validity
openssl x509 -in /opt/radius-user-portal/server.cer -text -noout | grep -E "Not Before|Not After"

# Verify certificate and key match
openssl x509 -noout -modulus -in /opt/radius-user-portal/server.cer | openssl md5
openssl rsa -noout -modulus -in /opt/radius-user-portal/server.key | openssl md5

# Regenerate certificate if needed
cd /opt/radius-user-portal
./create_server_csr.sh
```

#### 4. Session Management Issues

**Symptoms:**

- Sessions not persisting
- Unexpected logouts
- Session duration problems
- KeyError exceptions related to missing RADIUS attributes

**Solutions:**

```bash
# Check session storage permissions
ls -la /opt/radius-user-portal/flask_session/

# Clear session data
sudo rm -rf /opt/radius-user-portal/flask_session/*

# Check NTP synchronization
timedatectl status

# Restart the service
sudo systemctl restart portal.service

# Check logs for missing RADIUS Class attribute warnings
sudo journalctl -u portal.service | grep -i "no class attribute\|generated session id"
```

**Note:** The application now gracefully handles missing RADIUS Class attributes by generating UUID-based session IDs as fallbacks, preventing crashes from incomplete RADIUS responses.

#### 5. High Memory Usage or Memory Leaks

**Symptoms:**

- Gradually increasing memory usage
- Out of memory errors
- System slowdown

**Solutions:**

```bash
# Monitor memory usage
watch -n 5 'free -h; ps aux | grep portal.py'

# Restart the service regularly (add to cron if needed)
sudo systemctl restart portal.service

# Check for memory leaks in logs
sudo journalctl -u portal.service | grep -i "memory\|oom\|killed"
```

#### 6. Permission Issues

**Symptoms:**

- File access errors
- Permission denied messages
- Service fails to start

**Solutions:**

```bash
# Check file permissions
ls -la /opt/radius-user-portal/

# Fix ownership if needed
sudo chown -R www-data:www-data /opt/radius-user-portal/

# Fix permissions
sudo chmod 755 /opt/radius-user-portal/
sudo chmod 644 /opt/radius-user-portal/*.py
sudo chmod 600 /opt/radius-user-portal/config.py
sudo chmod 600 /opt/radius-user-portal/server.key
```

#### 7. Input Validation and Security Errors

**Symptoms:**

- HTTP 400 Bad Request errors during login
- "Username contains invalid characters" messages
- "Username/Password too long" messages
- CSRF token missing errors

**Solutions:**

```bash
# Check if inputs meet validation requirements
# Username: max 63 chars, only alphanumeric + @._-
# Password: max 128 chars

# Check logs for validation errors
sudo journalctl -u portal.service | grep -i "validation\|csrf\|bad request"

# For CSRF errors, ensure:
# - Forms are properly rendered with CSRF tokens
# - Session cookies are being set correctly
# - No JavaScript modifying forms without CSRF tokens

# Check session storage permissions
ls -la /opt/radius-user-portal/flask_session/
sudo chown -R www-data:www-data /opt/radius-user-portal/flask_session/
```

**Note:** The application includes comprehensive input validation and CSRF protection. Validation errors return HTTP 400 instead of 500 for better security and user experience.

### Performance Monitoring

#### Check Application Performance

```bash
# Monitor process resources
ps aux | grep portal.py

# Check network connections
netstat -tulpn | grep :8443

# Monitor disk space
df -h

# Check system load
uptime
```

#### Enable Debug Mode (Development Only)

For debugging purposes, you can enable debug mode by modifying the configuration:

```python
# In config.py, add:
DEBUG = True
```

**Warning:** Never enable debug mode in production as it can expose sensitive information.

### Getting Help

1. **Check the logs first** - Most issues can be diagnosed from the log output
2. **Verify configuration** - Ensure all settings in `config.py` are correct
3. **Test connectivity** - Verify network access to RADIUS servers
4. **Check system resources** - Ensure adequate CPU, memory, and disk space
5. **Review recent changes** - Consider any recent configuration or system changes

If you continue to experience issues after following these troubleshooting steps, please check the project's GitHub repository for known issues and solutions.

## Kubernetes example manifest

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: portal
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/instance: portal
      app.kubernetes.io/name: portal
  template:
    metadata:
      labels:
        app.kubernetes.io/instance: portal
        app.kubernetes.io/name: portal
    spec:
      containers:
        - env:
            - name: PORT # Set desired tcp www port
              value: "8000"
            - name: SERVE_HTTP # Causes the server to startup in http mode for reverse proxy operation
              value: "TRUE"
            - name: FORWARDED_ALLOW_IPS # Restrict X-Forwarded-For header to trusted sources
              value: "10.244.0.0/16"  # Example: Kubernetes pod network CIDR
          image: ghcr.io/cubinet-code/radius-user-portal:latest
          imagePullPolicy: Always
          name: portal
          ports:
            - containerPort: 8000
              name: http
              protocol: TCP
          volumeMounts:
            - name: server-config # Mount config file from a configmap
              mountPath: /opt/radius-user-portal/config.py
              subPath: config.py
          resources: {}
          securityContext: {}
      securityContext:
        runAsUser: 1000
      volumes:
        - name: server-config # Mount config file from a configmap
          configMap:
            name: server-config
            items:
              - key: config.py
                path: config.py
```
