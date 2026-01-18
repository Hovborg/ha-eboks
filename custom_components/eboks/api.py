"""e-Boks API client."""
from __future__ import annotations

import base64
import hashlib
import logging
import re
import uuid
from datetime import datetime
from typing import Any
from xml.etree import ElementTree as ET

import aiohttp

from .const import API_BASE_URL, API_USER_AGENT

_LOGGER = logging.getLogger(__name__)

# XML Namespace
NS = {"eb": "urn:eboks:mobile:1.0.0"}

# Auth types
AUTH_TYPE_ACTIVATION_CODE = "activation_code"
AUTH_TYPE_RSA = "rsa"


class EboksApiError(Exception):
    """Exception for e-Boks API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        """Initialize the exception."""
        super().__init__(message)
        self.status_code = status_code


class EboksAuthError(EboksApiError):
    """Exception for authentication errors."""


class EboksApi:
    """e-Boks API client.

    Supports two authentication methods:
    1. Activation code + PIN (limited to mailbox 0 / Virksomheder)
    2. RSA key (after MitID registration, full access including Digital Post)
    """

    def __init__(
        self,
        cpr: str,
        password: str,
        device_id: str | None = None,
        activation_code: str | None = None,
        private_key_pem: str | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        """Initialize the API client.

        Args:
            cpr: CPR number (with or without dash)
            password: e-Boks mobile password / PIN code
            device_id: Device ID (generated if not provided)
            activation_code: Activation code (for simple auth)
            private_key_pem: RSA private key in PEM format (for MitID auth)
            session: Optional aiohttp session to reuse
        """
        self._cpr = cpr.replace("-", "")
        self._password = password
        self._device_id = device_id or str(uuid.uuid4()).upper()
        self._activation_code = activation_code
        self._private_key_pem = private_key_pem
        self._session = session
        self._session_id: str | None = None
        self._nonce: str | None = None
        self._user_id: str | None = None
        self._owns_session = session is None

        # Determine auth type
        if private_key_pem:
            self._auth_type = AUTH_TYPE_RSA
        elif activation_code:
            self._auth_type = AUTH_TYPE_ACTIVATION_CODE
        else:
            raise EboksAuthError("Either activation_code or private_key_pem must be provided")

    @property
    def device_id(self) -> str:
        """Return the device ID."""
        return self._device_id

    @property
    def activation_code(self) -> str | None:
        """Return the activation code."""
        return self._activation_code

    @property
    def auth_type(self) -> str:
        """Return the authentication type."""
        return self._auth_type

    def _compute_challenge(self, datetime_str: str) -> str:
        """Compute the authentication challenge."""
        if self._auth_type == AUTH_TYPE_RSA:
            return self._compute_challenge_rsa(datetime_str)
        else:
            return self._compute_challenge_activation_code(datetime_str)

    def _compute_challenge_activation_code(self, datetime_str: str) -> str:
        """Compute the authentication challenge hash for activation code auth."""
        # Format: SHA256(SHA256("{activationCode}:{deviceId}:P:{userId}:DK:{password}:{datetime}"))
        raw = f"{self._activation_code}:{self._device_id}:P:{self._cpr}:DK:{self._password}:{datetime_str}"
        first_hash = hashlib.sha256(raw.encode()).hexdigest()
        second_hash = hashlib.sha256(first_hash.encode()).hexdigest()
        return second_hash

    def _compute_challenge_rsa(self, datetime_str: str) -> str:
        """Compute the authentication challenge using RSA signing."""
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError:
            raise EboksAuthError("cryptography library required for RSA authentication")

        # Challenge format: EBOKS:deviceid:type:cpr:country:password:datetime
        challenge_str = f"EBOKS:{self._device_id}:P:{self._cpr}:DK:{self._password}:{datetime_str}"

        # Load private key and sign
        private_key = serialization.load_pem_private_key(
            self._private_key_pem.encode('utf-8'),
            password=None,
        )

        signature = private_key.sign(
            challenge_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return base64.b64encode(signature).decode('utf-8')

    def _compute_response(self, challenge: str) -> str:
        """Compute session response hash."""
        if self._auth_type == AUTH_TYPE_RSA:
            return self._compute_response_rsa(challenge)
        else:
            return self._compute_response_activation_code(challenge)

    def _compute_response_activation_code(self, challenge: str) -> str:
        """Compute session response hash for activation code auth."""
        raw = f"{self._activation_code}:{self._device_id}:{challenge}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _compute_response_rsa(self, challenge: str) -> str:
        """Compute session response using RSA signing."""
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError:
            raise EboksAuthError("cryptography library required for RSA authentication")

        # For RSA auth, response is signature of: deviceId:challenge
        response_str = f"{self._device_id}:{challenge}"

        private_key = serialization.load_pem_private_key(
            self._private_key_pem.encode('utf-8'),
            password=None,
        )

        signature = private_key.sign(
            response_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return base64.b64encode(signature).decode('utf-8')

    def _get_headers(self, auth_header: str | None = None) -> dict[str, str]:
        """Get common headers for API requests."""
        headers = {
            "Content-Type": "application/xml",
            "Accept": "*/*",
            "User-Agent": API_USER_AGENT,
        }
        if auth_header:
            headers["X-EBOKS-AUTHENTICATE"] = auth_header
        return headers

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure we have an aiohttp session."""
        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._owns_session = True
        return self._session

    async def close(self) -> None:
        """Close the session if we own it."""
        if self._owns_session and self._session:
            await self._session.close()
            self._session = None

    async def authenticate(self) -> bool:
        """Authenticate with e-Boks API."""
        if not self._activation_code:
            raise EboksAuthError("Activation code is required for authentication")

        session = await self._ensure_session()

        # Build datetime string
        dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

        # Compute challenge
        challenge = self._compute_challenge(dt)

        # Build auth header for logon
        auth_header = f'logon deviceid="{self._device_id}",datetime="{dt}",challenge="{challenge}"'

        # Build session XML
        session_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<Logon xmlns="urn:eboks:mobile:1.0.0">
    <App version="1.4.1" os="iOS" osVersion="9.0" device="iPhone" />
    <User identity="{self._cpr}" identityType="P" nationality="DK" pincode="{self._password}" />
</Logon>"""

        try:
            async with session.put(
                f"{API_BASE_URL}/session",
                headers=self._get_headers(auth_header),
                data=session_xml,
            ) as response:
                if response.status == 200:
                    # Parse session credentials from X-EBOKS-AUTHENTICATE header
                    auth_response = response.headers.get("X-EBOKS-AUTHENTICATE", "")
                    _LOGGER.debug("Auth response header: %s", auth_response)

                    # Parse header: sessionid="...",nonce="..."
                    for part in auth_response.split(","):
                        part = part.strip()
                        match = re.match(r'(sessionid|nonce)="([^"]*)"', part)
                        if match:
                            key, value = match.groups()
                            if key == "sessionid":
                                self._session_id = value
                            elif key == "nonce":
                                self._nonce = value

                    # Parse user info from XML body
                    text = await response.text()
                    _LOGGER.warning("SESSION XML: %s", text[:2000])
                    root = ET.fromstring(text)

                    # Try with namespace first, then without
                    user_elem = root.find(".//eb:User", NS)
                    if user_elem is None:
                        user_elem = root.find(".//User")
                    if user_elem is None:
                        user_elem = root.find("User")

                    if user_elem is not None:
                        self._user_id = user_elem.get("userId")
                        _LOGGER.info("User ID: %s, All user attributes: %s", self._user_id, user_elem.attrib)

                    # Log all mailbox elements
                    for mailbox in root.findall(".//eb:Mailbox", NS):
                        _LOGGER.info("Found Mailbox: %s", mailbox.attrib)
                    for mailbox in root.findall(".//Mailbox"):
                        _LOGGER.info("Found Mailbox (no ns): %s", mailbox.attrib)

                    # Session response parsed successfully

                    if self._session_id and self._nonce and self._user_id:
                        _LOGGER.debug("Successfully authenticated with e-Boks (session=%s)", self._session_id[:8])
                        return True
                    else:
                        _LOGGER.error("Missing session data: session_id=%s, nonce=%s, user_id=%s",
                                     self._session_id, self._nonce, self._user_id)
                        raise EboksApiError("Failed to parse session data")
                elif response.status == 401:
                    raise EboksAuthError("Invalid credentials", response.status)
                else:
                    text = await response.text()
                    raise EboksApiError(f"Authentication failed: {text}", response.status)
        except aiohttp.ClientError as err:
            raise EboksApiError(f"Connection error: {err}") from err

    def _get_session_header(self) -> str:
        """Get the session authentication header."""
        if not self._session_id or not self._nonce:
            raise EboksAuthError("Not authenticated")

        response = self._compute_response(self._nonce)
        return f'deviceid="{self._device_id}",nonce="{self._nonce}",sessionid="{self._session_id}",response="{response}"'

    def _update_nonce_from_response(self, response: aiohttp.ClientResponse) -> bool:
        """Update nonce from response header for next request.

        Returns True if nonce was updated, False otherwise.
        """
        auth_header = response.headers.get("X-EBOKS-AUTHENTICATE", "")
        for part in auth_header.split(","):
            part = part.strip()
            match = re.match(r'nonce="([^"]*)"', part)
            if match:
                self._nonce = match.group(1)
                _LOGGER.debug("Updated nonce: %s...", self._nonce[:8] if self._nonce else "None")
                return True
        _LOGGER.debug("No nonce in response (status=%s)", response.status)
        return False

    async def get_shares(self) -> list[dict[str, Any]]:
        """Get list of available shares (mailboxes) for the user."""
        if not self._user_id:
            await self.authenticate()

        session = await self._ensure_session()
        auth_header = self._get_session_header()

        try:
            _LOGGER.debug("Fetching shares list")
            async with session.get(
                f"{API_BASE_URL}/{self._user_id}/0/shares?listType=active",
                headers=self._get_headers(auth_header),
            ) as response:
                self._update_nonce_from_response(response)

                if response.status == 200:
                    text = await response.text()
                    _LOGGER.warning("SHARES XML: %s", text[:1000])
                    return self._parse_shares(text)
                elif response.status == 401:
                    await self.authenticate()
                    return await self.get_shares()
                else:
                    error_body = await response.text()
                    _LOGGER.warning("Failed to get shares: status %d, body: %s", response.status, error_body[:500])
                    return []
        except aiohttp.ClientError as err:
            _LOGGER.warning("Connection error getting shares: %s", err)
            return []

    def _parse_shares(self, xml_text: str) -> list[dict[str, Any]]:
        """Parse shares XML response."""
        shares = []
        try:
            root = ET.fromstring(xml_text)
            # Try with namespace
            for share in root.findall(".//eb:ShareInfo", NS):
                shares.append({
                    "id": share.get("id"),
                    "name": share.get("name"),
                    "type": share.get("type"),
                })
            # Try without namespace
            if not shares:
                for share in root.findall(".//ShareInfo"):
                    shares.append({
                        "id": share.get("id"),
                        "name": share.get("name"),
                        "type": share.get("type"),
                    })
            _LOGGER.warning("Parsed %d shares: %s", len(shares), shares)
        except ET.ParseError as err:
            _LOGGER.error("Failed to parse shares XML: %s", err)
        return shares

    async def get_folders(self, share_id: str = "0") -> list[dict[str, Any]]:
        """Get list of mail folders from a specific share (mailbox)."""
        if not self._user_id:
            await self.authenticate()

        session = await self._ensure_session()
        auth_header = self._get_session_header()

        try:
            _LOGGER.debug("Fetching folders from share %s", share_id)
            async with session.get(
                f"{API_BASE_URL}/{self._user_id}/{share_id}/mail/folders",
                headers=self._get_headers(auth_header),
            ) as response:
                # Always try to update nonce from response
                self._update_nonce_from_response(response)

                if response.status == 200:
                    text = await response.text()
                    _LOGGER.debug("Raw folders XML from share %s: %s", share_id, text[:500])
                    folders = self._parse_folders(text, share_id)
                    _LOGGER.debug("Got %d folders from share %s", len(folders), share_id)
                    return folders
                elif response.status == 401:
                    # Session expired, re-authenticate
                    _LOGGER.debug("Session expired, re-authenticating")
                    await self.authenticate()
                    return await self.get_folders(share_id)
                elif response.status == 404:
                    # Share doesn't exist for this user, return empty
                    _LOGGER.warning("Share %s returned 404 - not found for user", share_id)
                    return []
                else:
                    error_body = await response.text()
                    _LOGGER.warning("Failed to get folders from share %s: status %d, body: %s", share_id, response.status, error_body[:500])
                    raise EboksApiError(f"Failed to get folders from share {share_id}", response.status)
        except aiohttp.ClientError as err:
            raise EboksApiError(f"Connection error: {err}") from err

    async def get_all_folders(self) -> list[dict[str, Any]]:
        """Get folders from all available shares (mailboxes).

        First fetches the list of available shares, then gets folders from each.
        """
        all_folders = []

        # First, get available shares
        shares = await self.get_shares()
        _LOGGER.warning("Available shares: %s", shares)

        # Always include share 0 (default mailbox)
        share_ids = ["0"]
        for share in shares:
            share_id = share.get("id")
            if share_id and share_id not in share_ids:
                share_ids.append(share_id)

        _LOGGER.warning("Will fetch folders from share IDs: %s", share_ids)

        # Fetch folders from each share
        for share_id in share_ids:
            try:
                folders = await self.get_folders(share_id)
                if folders:
                    # Find share name
                    share_name = next((s.get("name") for s in shares if s.get("id") == share_id), f"Share {share_id}")
                    if share_id == "0":
                        share_name = "Virksomheder"
                    for f in folders:
                        f["mailbox_name"] = share_name
                        f["share_id"] = share_id
                    all_folders.extend(folders)
                    _LOGGER.warning("Got %d folders from share %s (%s)", len(folders), share_id, share_name)
            except EboksApiError as err:
                _LOGGER.warning("Failed to get folders from share %s: %s", share_id, err)

        _LOGGER.warning("Total folders found: %d", len(all_folders))
        return all_folders

    def _parse_folders(self, xml_text: str, share_id: str = "0") -> list[dict[str, Any]]:
        """Parse folders XML response."""
        folders = []
        try:
            root = ET.fromstring(xml_text)
            for folder in root.findall(".//eb:FolderInfo", NS):
                folders.append({
                    "id": folder.get("id"),
                    "name": folder.get("name"),
                    "unread": int(folder.get("unread", 0)),
                    "share_id": share_id,
                    "mailbox_id": share_id,  # Keep for backwards compatibility
                })
        except ET.ParseError as err:
            _LOGGER.error("Failed to parse folders XML: %s", err)
        return folders

    async def get_messages(
        self, folder_id: str = "0", share_id: str = "0", skip: int = 0, take: int = 100,
        mailbox_id: int | str | None = None  # Deprecated, for backwards compatibility
    ) -> list[dict[str, Any]]:
        """Get messages from a folder."""
        # Handle backwards compatibility
        if mailbox_id is not None:
            share_id = str(mailbox_id)

        if not self._user_id:
            await self.authenticate()

        session = await self._ensure_session()
        auth_header = self._get_session_header()

        try:
            _LOGGER.debug("Fetching messages from folder %s (share %s)", folder_id, share_id)
            async with session.get(
                f"{API_BASE_URL}/{self._user_id}/{share_id}/mail/folder/{folder_id}?skip={skip}&take={take}",
                headers=self._get_headers(auth_header),
            ) as response:
                # Always try to update nonce from response
                self._update_nonce_from_response(response)

                if response.status == 200:
                    text = await response.text()
                    messages = self._parse_messages(text)
                    _LOGGER.debug("Got %d messages from folder %s", len(messages), folder_id)
                    return messages
                elif response.status == 401:
                    _LOGGER.debug("Session expired while getting messages, re-authenticating")
                    await self.authenticate()
                    return await self.get_messages(folder_id, share_id, skip, take)
                elif response.status == 404:
                    # Folder doesn't exist, return empty
                    _LOGGER.debug("Folder %s not found", folder_id)
                    return []
                else:
                    _LOGGER.warning("Failed to get messages from folder %s: status %d", folder_id, response.status)
                    raise EboksApiError(f"Failed to get messages from folder {folder_id}", response.status)
        except aiohttp.ClientError as err:
            raise EboksApiError(f"Connection error: {err}") from err

    def _parse_messages(self, xml_text: str) -> list[dict[str, Any]]:
        """Parse messages XML response."""
        messages = []
        try:
            root = ET.fromstring(xml_text)
            for msg in root.findall(".//eb:MessageInfo", NS):
                # Sender is a child element with text content
                sender_elem = msg.find("eb:Sender", NS)
                sender = sender_elem.text if sender_elem is not None and sender_elem.text else ""

                messages.append({
                    "id": msg.get("id"),
                    "subject": msg.get("name", ""),
                    "sender": sender,
                    "received": msg.get("receivedDateTime"),
                    "unread": msg.get("unread", "false").lower() == "true",
                    "format": msg.get("format"),
                    "folder_id": msg.get("folderId"),
                    "attachments_count": int(msg.get("attachmentsCount", 0)),
                    "size": int(msg.get("size", 0)),
                })
        except ET.ParseError as err:
            _LOGGER.error("Failed to parse messages XML: %s", err)
        return messages

    async def get_message_content(
        self, folder_id: str, message_id: str, share_id: str = "0",
        mailbox_id: int | str | None = None  # Deprecated, for backwards compatibility
    ) -> bytes | None:
        """Download message content."""
        # Handle backwards compatibility
        if mailbox_id is not None:
            share_id = str(mailbox_id)

        if not self._user_id:
            await self.authenticate()

        session = await self._ensure_session()
        auth_header = self._get_session_header()

        try:
            async with session.get(
                f"{API_BASE_URL}/{self._user_id}/{share_id}/mail/folder/{folder_id}/message/{message_id}/content",
                headers=self._get_headers(auth_header),
            ) as response:
                # Always try to update nonce from response
                self._update_nonce_from_response(response)

                if response.status == 200:
                    return await response.read()
                elif response.status == 401:
                    await self.authenticate()
                    return await self.get_message_content(folder_id, message_id, share_id)
                else:
                    raise EboksApiError(f"Failed to get message content", response.status)
        except aiohttp.ClientError as err:
            raise EboksApiError(f"Connection error: {err}") from err

    async def get_all_messages(self) -> list[dict[str, Any]]:
        """Get all messages from all folders in all mailboxes."""
        all_messages = []
        folders = await self.get_all_folders()

        for folder in folders:
            try:
                messages = await self.get_messages(
                    folder["id"],
                    mailbox_id=folder.get("mailbox_id", 0)
                )
                for msg in messages:
                    msg["folder_name"] = folder["name"]
                    msg["mailbox_id"] = folder.get("mailbox_id", 0)
                all_messages.extend(messages)
            except EboksApiError as err:
                _LOGGER.warning("Failed to get messages from folder %s: %s", folder.get("id"), err)
            except Exception as err:
                _LOGGER.error("Unexpected error getting messages from folder %s: %s", folder.get("id"), err)

        # Sort by received date, newest first
        all_messages.sort(key=lambda x: x.get("received", ""), reverse=True)
        return all_messages

    async def get_unread_count(self) -> int:
        """Get total unread message count from all mailboxes."""
        folders = await self.get_all_folders()
        return sum(folder.get("unread", 0) for folder in folders)
