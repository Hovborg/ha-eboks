"""e-Boks Mobile JSON API client for MitID authentication.

This module provides access to the Mobile JSON API which is used when
authenticating via MitID. This gives access to Digital Post (Post fra
det offentlige) which is not available via the XML API.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import aiohttp

from .const import MOBILE_API_BASE_URL, MOBILE_API_VERSION
from .mitid_auth import MitIDAuthenticator, MitIDCredentials

_LOGGER = logging.getLogger(__name__)


class EboksMobileApiError(Exception):
    """Exception for e-Boks Mobile API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        """Initialize the exception."""
        super().__init__(message)
        self.status_code = status_code


class EboksMobileAuthError(EboksMobileApiError):
    """Exception for authentication errors."""


class EboksMobileApi:
    """e-Boks Mobile JSON API client.

    This client uses the Mobile JSON API (mobile-api-dk.e-boks.com) which
    requires MitID authentication. It provides access to Digital Post
    (Post fra det offentlige) and the personal e-Boks mailbox.
    """

    def __init__(
        self,
        access_token: str,
        refresh_token: str | None = None,
        inbox_folder_id: str | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        """Initialize the API client.

        Args:
            access_token: e-Boks access token from MitID authentication
            refresh_token: Refresh token for automatic token renewal
            inbox_folder_id: Inbox folder ID (from userToken JWT)
            session: Optional aiohttp session to reuse
        """
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._inbox_folder_id = inbox_folder_id
        self._session = session
        self._owns_session = session is None

    @property
    def access_token(self) -> str:
        """Return the current access token."""
        return self._access_token

    @property
    def refresh_token(self) -> str | None:
        """Return the refresh token."""
        return self._refresh_token

    def _get_headers(self) -> dict[str, str]:
        """Get common headers for API requests."""
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

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

    async def refresh_access_token(self) -> bool:
        """Refresh the access token using the refresh token.

        Returns:
            True if token was refreshed successfully
        """
        if not self._refresh_token:
            _LOGGER.warning("No refresh token available")
            return False

        try:
            auth = MitIDAuthenticator()
            result = await auth.refresh_eboks_token(self._refresh_token)
            self._access_token = result["access_token"]
            if "refresh_token" in result:
                self._refresh_token = result["refresh_token"]
            _LOGGER.debug("Access token refreshed successfully")
            return True
        except Exception as e:
            _LOGGER.error("Failed to refresh access token: %s", e)
            return False

    async def get_profile(self) -> dict[str, Any]:
        """Get user profile information.

        Note: The /1/profile endpoint often returns 404, so we fall back to
        extracting user info from the access token JWT.

        Returns:
            User profile with id, name, etc.
        """
        session = await self._ensure_session()

        async with session.get(
            f"{MOBILE_API_BASE_URL}/1/profile",
            headers=self._get_headers(),
        ) as response:
            if response.status == 401:
                if await self.refresh_access_token():
                    return await self.get_profile()
                raise EboksMobileAuthError("Authentication failed", response.status)
            if response.status == 200:
                return await response.json()
            _LOGGER.warning("Profile endpoint returned %d, using JWT fallback", response.status)

        # Fallback: extract user info from JWT access token
        try:
            import base64
            import json
            payload_b64 = self._access_token.split('.')[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            user_id = payload.get("sub", "")
            _LOGGER.info("Extracted user_id from JWT: %s", user_id)
            return {"id": user_id, "name": f"e-Boks User {user_id}"}
        except Exception as e:
            _LOGGER.warning("Could not extract user info from JWT: %s", e)
            return {"id": "unknown", "name": "e-Boks User"}

    async def get_folders(self) -> list[dict[str, Any]]:
        """Get list of mail folders.

        Returns:
            List of folder dicts with id, name, unreadCount, etc.
        """
        session = await self._ensure_session()

        async with session.get(
            f"{MOBILE_API_BASE_URL}/{MOBILE_API_VERSION}/mail/folders",
            headers=self._get_headers(),
        ) as response:
            if response.status == 401:
                if await self.refresh_access_token():
                    return await self.get_folders()
                raise EboksMobileAuthError("Authentication failed", response.status)
            if response.status != 200:
                error = await response.text()
                raise EboksMobileApiError(f"Folders request failed: {error}", response.status)

            data = await response.json()
            # API returns {"folders": [...]}
            return data.get("folders", [])

    async def get_messages(
        self,
        folder_id: str | None = None,
        skip: int = 0,
        take: int = 50,
    ) -> list[dict[str, Any]]:
        """Get messages from a folder.

        Args:
            folder_id: Folder ID (defaults to inbox)
            skip: Number of messages to skip
            take: Number of messages to retrieve

        Returns:
            List of message dicts
        """
        session = await self._ensure_session()

        # Use provided folder_id or fall back to inbox
        fid = folder_id or self._inbox_folder_id
        if not fid:
            # Get folders to find inbox
            folders = await self.get_folders()
            for folder in folders:
                if folder.get("name", "").lower() == "inbox":
                    fid = folder.get("id")
                    self._inbox_folder_id = fid
                    break
            if not fid and folders:
                fid = folders[0].get("id")
                self._inbox_folder_id = fid

        if not fid:
            _LOGGER.warning("No folder ID available")
            return []

        async with session.get(
            f"{MOBILE_API_BASE_URL}/{MOBILE_API_VERSION}/mail/folders/{fid}/messages",
            headers=self._get_headers(),
            params={"skip": skip, "take": take},
        ) as response:
            if response.status == 401:
                if await self.refresh_access_token():
                    return await self.get_messages(folder_id, skip, take)
                raise EboksMobileAuthError("Authentication failed", response.status)
            if response.status != 200:
                error = await response.text()
                raise EboksMobileApiError(f"Messages request failed: {error}", response.status)

            data = await response.json()
            # API returns {"messages": [...], "totalCount": N}
            messages = data.get("messages", [])
            _LOGGER.debug("Got %d messages from folder %s", len(messages), fid)
            return messages

    async def get_message(self, message_id: str) -> dict[str, Any]:
        """Get a specific message by ID.

        Args:
            message_id: Message ID

        Returns:
            Message details
        """
        session = await self._ensure_session()

        async with session.get(
            f"{MOBILE_API_BASE_URL}/{MOBILE_API_VERSION}/mail/messages/{message_id}",
            headers=self._get_headers(),
        ) as response:
            if response.status == 401:
                if await self.refresh_access_token():
                    return await self.get_message(message_id)
                raise EboksMobileAuthError("Authentication failed", response.status)
            if response.status != 200:
                error = await response.text()
                raise EboksMobileApiError(f"Message request failed: {error}", response.status)

            return await response.json()

    async def get_message_content(self, message_id: str) -> bytes:
        """Download message content (PDF or HTML).

        Args:
            message_id: Message ID

        Returns:
            Message content as bytes
        """
        session = await self._ensure_session()

        async with session.get(
            f"{MOBILE_API_BASE_URL}/{MOBILE_API_VERSION}/mail/messages/{message_id}/content",
            headers=self._get_headers(),
        ) as response:
            if response.status == 401:
                if await self.refresh_access_token():
                    return await self.get_message_content(message_id)
                raise EboksMobileAuthError("Authentication failed", response.status)
            if response.status != 200:
                error = await response.text()
                raise EboksMobileApiError(f"Content request failed: {error}", response.status)

            return await response.read()

    async def get_all_messages(self, max_messages: int = 100) -> list[dict[str, Any]]:
        """Get all messages from all folders.

        Args:
            max_messages: Maximum number of messages to retrieve per folder

        Returns:
            List of all messages with folder information
        """
        all_messages = []
        folders = await self.get_folders()

        for folder in folders:
            folder_id = folder.get("id")
            folder_name = folder.get("name", "Unknown")
            if not folder_id:
                continue

            try:
                messages = await self.get_messages(folder_id, take=max_messages)
                for msg in messages:
                    msg["folder_id"] = folder_id
                    msg["folder_name"] = folder_name
                all_messages.extend(messages)
            except EboksMobileApiError as e:
                _LOGGER.warning("Failed to get messages from folder %s: %s", folder_name, e)

        # Sort by received date, newest first
        all_messages.sort(
            key=lambda x: x.get("receivedDateTime", x.get("received", "")),
            reverse=True,
        )
        return all_messages

    async def get_unread_count(self) -> int:
        """Get total unread message count.

        Returns:
            Number of unread messages
        """
        folders = await self.get_folders()
        return sum(folder.get("unreadCount", 0) for folder in folders)

    def normalize_message(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Normalize a message to a consistent format.

        Converts Mobile API message format to match the XML API format
        used by the rest of the integration.

        Args:
            msg: Message from Mobile API

        Returns:
            Normalized message dict
        """
        return {
            "id": msg.get("id"),
            "subject": msg.get("subject", msg.get("name", "")),
            "sender": msg.get("sender", {}).get("name", "") if isinstance(msg.get("sender"), dict) else msg.get("sender", ""),
            "received": msg.get("receivedDateTime", msg.get("received", "")),
            "unread": not msg.get("read", True),
            "format": msg.get("format", msg.get("contentType", "")),
            "folder_id": msg.get("folder_id", msg.get("folderId", "")),
            "folder_name": msg.get("folder_name", ""),
            "attachments_count": len(msg.get("attachments", [])),
            "size": msg.get("size", 0),
        }
