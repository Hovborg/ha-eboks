"""DataUpdateCoordinator for e-Boks integration."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from homeassistant.components.persistent_notification import async_create
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import EboksApi, EboksApiError, EboksAuthError
from .const import DEFAULT_NOTIFY_SENDERS, DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)

# Event names
EVENT_NEW_MESSAGE = f"{DOMAIN}_new_message"
EVENT_UNREAD_CHANGED = f"{DOMAIN}_unread_changed"


class EboksCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Class to manage fetching e-Boks data."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: EboksApi,
        scan_interval: timedelta | None = None,
        notify_senders: list[str] | None = None,
    ) -> None:
        """Initialize the coordinator."""
        if scan_interval is None:
            scan_interval = timedelta(minutes=DEFAULT_SCAN_INTERVAL)

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=scan_interval,
        )
        self.api = api
        self.notify_senders = notify_senders or DEFAULT_NOTIFY_SENDERS
        self._previous_unread_count: int | None = None
        self._previous_message_ids: set[str] = set()
        self._last_updated: datetime | None = None
        self._connection_ok: bool = True

    def _should_notify(self, sender: str) -> bool:
        """Check if sender matches any notify sender pattern."""
        sender_lower = sender.lower() if sender else ""
        for pattern in self.notify_senders:
            if pattern.lower() in sender_lower:
                return True
        return False

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from e-Boks API."""
        try:
            _LOGGER.debug("Starting e-Boks data update")

            # Fetch data - API methods handle re-authentication on 401
            # Order matters: get_all_messages and get_unread_count both call get_all_folders internally
            messages = await self.api.get_all_messages()
            _LOGGER.debug("Got %d messages", len(messages))

            unread_count = await self.api.get_unread_count()
            _LOGGER.debug("Unread count: %d", unread_count)

            folders = await self.api.get_all_folders()
            _LOGGER.debug("Got %d folders", len(folders))

            # Debug notification to show mailbox info
            mailbox0_count = len([f for f in folders if f.get("mailbox_name") == "Virksomheder"])
            mailbox1_count = len([f for f in folders if f.get("mailbox_name") == "Det offentlige"])
            mailbox1_result = getattr(self.api, '_mailbox1_result', 'N/A')
            async_create(
                self.hass,
                f"Mailbox 0: {mailbox0_count} folders. Mailbox 1: {mailbox1_count} folders ({mailbox1_result}). Total: {len(folders)}",
                title="e-Boks Debug",
                notification_id="eboks_debug_mailboxes",
            )

            # Update timestamps and connection status
            self._last_updated = dt_util.now()
            self._connection_ok = True

            data = {
                "messages": messages,
                "unread_count": unread_count,
                "folders": folders,
                "latest_message": messages[0] if messages else None,
                "last_updated": self._last_updated.isoformat(),
                "connection_ok": self._connection_ok,
            }

            # Fire events for new messages
            current_message_ids = {m["id"] for m in messages}

            if self._previous_unread_count is not None:
                # Check for new messages
                new_message_ids = current_message_ids - self._previous_message_ids

                for msg in messages:
                    if msg["id"] in new_message_ids and msg.get("unread"):
                        sender = msg.get("sender", "")
                        subject = msg.get("subject", "")

                        # Fire event for each new unread message
                        self.hass.bus.async_fire(EVENT_NEW_MESSAGE, {
                            "message_id": msg["id"],
                            "sender": sender,
                            "subject": subject,
                            "received": msg.get("received"),
                            "folder": msg.get("folder_name"),
                            "folder_id": msg.get("folder_id"),
                        })
                        _LOGGER.info(
                            "New e-Boks message from %s: %s",
                            sender,
                            subject,
                        )

                        # Create persistent notification for important senders
                        if self._should_notify(sender):
                            async_create(
                                self.hass,
                                f"**Afsender:** {sender}\n\n**Emne:** {subject}",
                                title=f"📬 Ny e-Boks besked fra {sender}",
                                notification_id=f"eboks_new_message_{msg['id']}",
                            )
                            _LOGGER.info(
                                "Created persistent notification for important sender: %s",
                                sender,
                            )

                # Fire event if unread count changed
                if unread_count != self._previous_unread_count:
                    self.hass.bus.async_fire(EVENT_UNREAD_CHANGED, {
                        "previous_count": self._previous_unread_count,
                        "current_count": unread_count,
                        "difference": unread_count - self._previous_unread_count,
                    })

            # Update previous state
            self._previous_unread_count = unread_count
            self._previous_message_ids = current_message_ids

            return data

        except EboksAuthError as err:
            self._connection_ok = False
            raise ConfigEntryAuthFailed from err
        except EboksApiError as err:
            self._connection_ok = False
            raise UpdateFailed(f"Error communicating with e-Boks: {err}") from err

    @property
    def last_updated(self) -> datetime | None:
        """Return the last update timestamp."""
        return self._last_updated

    @property
    def connection_ok(self) -> bool:
        """Return True if the last update was successful."""
        return self._connection_ok
