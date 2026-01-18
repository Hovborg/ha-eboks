"""Button platform for e-Boks integration."""
from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_CPR, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up e-Boks buttons."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    api = hass.data[DOMAIN][entry.entry_id]["api"]
    cpr = entry.data[CONF_CPR]

    async_add_entities([
        EboksMarkAllReadButton(coordinator, api, entry, cpr),
        EboksRefreshButton(coordinator, entry, cpr),
    ])


class EboksMarkAllReadButton(CoordinatorEntity, ButtonEntity):
    """Button to mark all unread messages as read."""

    _attr_icon = "mdi:email-check"
    _attr_has_entity_name = True

    def __init__(self, coordinator, api, entry: ConfigEntry, cpr: str) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._api = api
        self._entry = entry
        self._cpr = cpr
        self._attr_unique_id = f"{entry.entry_id}_mark_all_read"
        self._attr_name = "Markér alle læst"

    @property
    def device_info(self):
        """Return device info."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": f"e-Boks ({self._cpr[:6]}...)",
            "manufacturer": "e-Boks",
            "model": "Digital Postkasse",
        }

    async def async_press(self) -> None:
        """Handle button press - mark all unread messages as read."""
        if not self.coordinator.data:
            return

        messages = self.coordinator.data.get("messages", [])
        unread_messages = [m for m in messages if m.get("unread")]

        _LOGGER.info("Marking %d messages as read", len(unread_messages))

        for msg in unread_messages:
            try:
                # Download content to mark as read
                await self._api.get_message_content(
                    msg.get("folder_id"),
                    msg.get("id"),
                )
                _LOGGER.debug("Marked message %s as read", msg.get("id"))
            except Exception as err:
                _LOGGER.error("Failed to mark message as read: %s", err)

        # Refresh data
        await self.coordinator.async_request_refresh()


class EboksRefreshButton(CoordinatorEntity, ButtonEntity):
    """Button to refresh e-Boks data."""

    _attr_icon = "mdi:refresh"
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry: ConfigEntry, cpr: str) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._entry = entry
        self._cpr = cpr
        self._attr_unique_id = f"{entry.entry_id}_refresh"
        self._attr_name = "Opdater"

    @property
    def device_info(self):
        """Return device info."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": f"e-Boks ({self._cpr[:6]}...)",
            "manufacturer": "e-Boks",
            "model": "Digital Postkasse",
        }

    async def async_press(self) -> None:
        """Handle button press - refresh data."""
        _LOGGER.info("Refreshing e-Boks data")
        await self.coordinator.async_request_refresh()
