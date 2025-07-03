# Configuration file for the User Portal application

#
# Radius Parameters
#

# Local IP address of the server which is used as NAS-IP-Address,
# default is the first IP address of the server
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

#
# Web Server Parameters
#

# Flask secret key for signing cookie sessions, please change!
SECRET_KEY = "secretkey"
# Logo url for the login page
# LOGO_URL = "https://www.example.com/logo.png"

# Use Boostrap assets from local server
BOOTSTRAP_SERVE_LOCAL = True
# Where to store the session data - using CacheLib backend
SESSION_TYPE = "cachelib"
# CacheLib configuration for filesystem sessions
# Note: This will be set programmatically in portal.py to use FileSystemCache
