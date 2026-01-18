"""Constants for the e-Boks integration."""
from datetime import timedelta
from typing import Final

DOMAIN: Final = "eboks"

# API Configuration
API_BASE_URL: Final = "https://rest.e-boks.dk/mobile/1/xml.svc/en-gb"
API_USER_AGENT: Final = "eboks/35 CFNetwork/672.1.15 Darwin/14.0.0"

# Configuration keys
CONF_CPR: Final = "cpr"
CONF_PASSWORD: Final = "password"
CONF_DEVICE_ID: Final = "device_id"
CONF_ACTIVATION_CODE: Final = "activation_code"
CONF_AUTH_TYPE: Final = "auth_type"
CONF_PRIVATE_KEY: Final = "private_key"

# Authentication types
AUTH_TYPE_ACTIVATION_CODE: Final = "activation_code"
AUTH_TYPE_MITID: Final = "mitid"

# Options keys
CONF_SCAN_INTERVAL: Final = "scan_interval"
CONF_MESSAGE_COUNT: Final = "message_count"
CONF_NOTIFY_SENDERS: Final = "notify_senders"

# Default values
DEFAULT_SCAN_INTERVAL: Final = 30  # minutes
DEFAULT_MESSAGE_COUNT: Final = 5
DEFAULT_NOTIFY_SENDERS: Final[list[str]] = [
    "Skattestyrelsen",
    "Kommune",
    "Sundhed",
    "NemKonto",
    "Udbetaling Danmark",
]

# Min/Max values
MIN_SCAN_INTERVAL: Final = 5
MAX_SCAN_INTERVAL: Final = 1440  # 24 hours
MIN_MESSAGE_COUNT: Final = 1
MAX_MESSAGE_COUNT: Final = 20

# Platforms
PLATFORMS: Final = ["sensor", "binary_sensor", "button"]

# Attributes
ATTR_SENDER: Final = "sender"
ATTR_SUBJECT: Final = "subject"
ATTR_RECEIVED: Final = "received"
ATTR_FOLDER: Final = "folder"
ATTR_MESSAGE_ID: Final = "message_id"
ATTR_UNREAD: Final = "unread"
ATTR_MESSAGES: Final = "messages"
ATTR_LAST_UPDATED: Final = "last_updated"
ATTR_CONNECTION_STATUS: Final = "connection_status"

# Services
SERVICE_DOWNLOAD_MESSAGE: Final = "download_message"
SERVICE_MARK_AS_READ: Final = "mark_as_read"
SERVICE_REFRESH: Final = "refresh"

# Events
EVENT_NEW_MESSAGE: Final = f"{DOMAIN}_new_message"
EVENT_UNREAD_CHANGED: Final = f"{DOMAIN}_unread_changed"
EVENT_MESSAGE_DOWNLOADED: Final = f"{DOMAIN}_message_downloaded"
