"""Button platform for e-Boks integration."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import EboksApi
from .const import CONF_CPR, DOMAIN
from .coordinator import EboksCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up e-Boks buttons."""
    coordinator: EboksCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    api: EboksApi = hass.data[DOMAIN][entry.entry_id]["api"]
    cpr: str = entry.data[CONF_CPR]

    async_add_entities([
        EboksMarkAllReadButton(coordinator, api, entry, cpr),
        EboksRefreshButton(coordinator, entry, cpr),
    ])


class EboksMarkAllReadButton(CoordinatorEntity[EboksCoordinator], ButtonEntity):
    """Button to mark all unread messages as read."""

    _attr_icon = "mdi:email-check"
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: EboksCoordinator,
        api: EboksApi,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._api = api
        self._entry = entry
        self._cpr = cpr
        self._attr_unique_id = f"{entry.entry_id}_mark_all_read"
        self._attr_name = "Markér alle læst"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"e-Boks ({self._cpr[:6]}...)",
            manufacturer="e-Boks",
            model="Digital Postkasse",
        )

    async def async_press(self) -> None:
        """Handle button press - mark all unread messages as read."""
        if not self.coordinator.data:
            return

        messages: list[dict[str, Any]] = self.coordinator.data.get("messages", [])
        unread_messages = [m for m in messages if m.get("unread")]

        if not unread_messages:
            _LOGGER.info("No unread messages to mark as read")
            return

        _LOGGER.info("Marking %d messages as read", len(unread_messages))

        # Limit to first 10 to avoid overloading the API
        messages_to_mark = unread_messages[:10]
        marked_count = 0

        for msg in messages_to_mark:
            try:
                folder_id: str | None = msg.get("folder_id")
                message_id: str | None = msg.get("id")

                if folder_id and message_id:
                    # Download content to mark as read
                    await self._api.get_message_content(folder_id, message_id)
                    marked_count += 1
                    _LOGGER.debug(
                        "Marked message %s as read (%d/%d)",
                        message_id,
                        marked_count,
                        len(messages_to_mark),
                    )

                # Wait between calls to avoid rate limiting
                await asyncio.sleep(1)

            except Exception as err:
                _LOGGER.error("Failed to mark message as read: %s", err)
                # Re-authenticate and continue
                try:
                    await self._api.authenticate()
                except Exception:
                    break

        _LOGGER.info("Marked %d messages as read", marked_count)

        # Wait a bit before refreshing
        await asyncio.sleep(2)

        # Refresh data
        await self.coordinator.async_request_refresh()


class EboksRefreshButton(CoordinatorEntity[EboksCoordinator], ButtonEntity):
    """Button to refresh e-Boks data."""

    _attr_icon = "mdi:refresh"
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: EboksCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._entry = entry
        self._cpr = cpr
        self._attr_unique_id = f"{entry.entry_id}_refresh"
        self._attr_name = "Opdater"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"e-Boks ({self._cpr[:6]}...)",
            manufacturer="e-Boks",
            model="Digital Postkasse",
        )

    async def async_press(self) -> None:
        """Handle button press - refresh data."""
        _LOGGER.info("Refreshing e-Boks data")
        await self.coordinator.async_request_refresh()
