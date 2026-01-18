"""Constants for the e-Boks integration."""
from datetime import timedelta

DOMAIN = "eboks"

# API Configuration
API_BASE_URL = "https://rest.e-boks.dk/mobile/1/xml.svc/en-gb"
API_USER_AGENT = "eboks/35 CFNetwork/672.1.15 Darwin/14.0.0"

# Configuration keys
CONF_CPR = "cpr"
CONF_PASSWORD = "password"
CONF_DEVICE_ID = "device_id"
CONF_ACTIVATION_CODE = "activation_code"

# Update interval
DEFAULT_SCAN_INTERVAL = timedelta(minutes=30)

# Platforms
PLATFORMS = ["sensor", "binary_sensor"]

# Attributes
ATTR_SENDER = "sender"
ATTR_SUBJECT = "subject"
ATTR_RECEIVED = "received"
ATTR_FOLDER = "folder"
ATTR_MESSAGE_ID = "message_id"
ATTR_UNREAD = "unread"
ATTR_MESSAGES = "messages"

# Services
SERVICE_DOWNLOAD_MESSAGE = "download_message"
SERVICE_REFRESH = "refresh"
