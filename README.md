# Radius Session User Portal

![Alt text](/tests/screenshot.png?raw=true)

## Introduction
This flask app is a simple portal for managing radius sessions. It is intended to be used with the a Radius Server like a Cisco ISE.
It was originaly developed for a Cisco ISE deployment as a custom portal to start Radius sessions for use with a Cisco Secure Firewall Manager (CSFM or FMC). The ISE session then gets replicated via Cisco's PXGrid protocol to the CSFM/FMC. The FMC then uses the session information to allow for user based firewall rules.

## Current functionality

- After login, the user can see his current session, refresh or disconnect it.
- The user will either be disconnected after the session duration or can disconnect it manually.
- The session duration can be controlled by the config.py or by radius attributes sent by the radius server.
- Radius server redundancy is supported.
- Session managment is server side, Cookies are encrypted and signed.

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

The service will run by default on port 8443. You can change this in the run.sh or app.py script.

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

#
# Web Server Parameters
#

# Flask secret key for signing cookie sessions, please change!
SECRET_KEY = "secretkey"
# Logo url for the login page
# LOGO_URL = "https://www.example.com/logo.png"

# Use Boostrap assets from local server
BOOTSTRAP_SERVE_LOCAL = True
# Where to store the session data
SESSION_TYPE = "filesystem"

```

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