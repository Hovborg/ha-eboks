"""DataUpdateCoordinator for e-Boks integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import EboksApi, EboksApiError, EboksAuthError
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN

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
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=DEFAULT_SCAN_INTERVAL,
        )
        self.api = api
        self._previous_unread_count: int | None = None
        self._previous_message_ids: set[str] = set()

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from e-Boks API."""
        try:
            messages = await self.api.get_all_messages()
            unread_count = await self.api.get_unread_count()
            folders = await self.api.get_folders()

            data = {
                "messages": messages,
                "unread_count": unread_count,
                "folders": folders,
                "latest_message": messages[0] if messages else None,
            }

            # Fire events for new messages
            current_message_ids = {m["id"] for m in messages}

            if self._previous_unread_count is not None:
                # Check for new messages
                new_message_ids = current_message_ids - self._previous_message_ids

                for msg in messages:
                    if msg["id"] in new_message_ids and msg.get("unread"):
                        # Fire event for each new unread message
                        self.hass.bus.async_fire(EVENT_NEW_MESSAGE, {
                            "message_id": msg["id"],
                            "sender": msg.get("sender"),
                            "subject": msg.get("subject"),
                            "received": msg.get("received"),
                            "folder": msg.get("folder_name"),
                            "folder_id": msg.get("folder_id"),
                        })
                        _LOGGER.info(
                            "New e-Boks message from %s: %s",
                            msg.get("sender"),
                            msg.get("subject"),
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
            raise ConfigEntryAuthFailed from err
        except EboksApiError as err:
            raise UpdateFailed(f"Error communicating with e-Boks: {err}") from err
