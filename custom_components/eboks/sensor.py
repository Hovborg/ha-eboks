"""Sensor platform for e-Boks integration."""
from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import (
    ATTR_FOLDER,
    ATTR_MESSAGE_ID,
    ATTR_MESSAGES,
    ATTR_RECEIVED,
    ATTR_SENDER,
    ATTR_SUBJECT,
    ATTR_UNREAD,
    CONF_CPR,
    DOMAIN,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up e-Boks sensors."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    cpr = entry.data[CONF_CPR]

    entities = [
        EboksMessageCountSensor(coordinator, entry, cpr),
        EboksLatestMessageSensor(coordinator, entry, cpr),
    ]

    async_add_entities(entities)


class EboksBaseSensor(CoordinatorEntity, SensorEntity):
    """Base class for e-Boks sensors."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._cpr = cpr
        self._attr_has_entity_name = True

    @property
    def device_info(self):
        """Return device info."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": f"e-Boks ({self._cpr[:6]}...)",
            "manufacturer": "e-Boks",
            "model": "Digital Postkasse",
        }


class EboksMessageCountSensor(EboksBaseSensor):
    """Sensor for e-Boks message count."""

    _attr_icon = "mdi:email-multiple"
    _attr_native_unit_of_measurement = "beskeder"

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, cpr)
        self._attr_unique_id = f"{entry.entry_id}_message_count"
        self._attr_name = "Ulæste beskeder"

    @property
    def native_value(self):
        """Return the number of unread messages."""
        if self.coordinator.data:
            return self.coordinator.data.get("unread_count", 0)
        return 0

    @property
    def extra_state_attributes(self):
        """Return additional attributes."""
        if not self.coordinator.data:
            return {}

        folders = self.coordinator.data.get("folders", [])
        return {
            "folders": [
                {"name": f["name"], "unread": f["unread"]}
                for f in folders
            ],
            "total_messages": len(self.coordinator.data.get("messages", [])),
        }


class EboksLatestMessageSensor(EboksBaseSensor):
    """Sensor for latest e-Boks message."""

    _attr_icon = "mdi:email"

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, cpr)
        self._attr_unique_id = f"{entry.entry_id}_latest_message"
        self._attr_name = "Seneste besked"

    @property
    def native_value(self):
        """Return the subject of the latest message."""
        if self.coordinator.data:
            latest = self.coordinator.data.get("latest_message")
            if latest:
                return latest.get("subject", "Ingen emne")
        return "Ingen beskeder"

    @property
    def extra_state_attributes(self):
        """Return additional attributes."""
        if not self.coordinator.data:
            return {}

        latest = self.coordinator.data.get("latest_message")
        if not latest:
            return {}

        # Also include last 5 messages
        messages = self.coordinator.data.get("messages", [])[:5]

        return {
            ATTR_SENDER: latest.get("sender"),
            ATTR_SUBJECT: latest.get("subject"),
            ATTR_RECEIVED: latest.get("received"),
            ATTR_FOLDER: latest.get("folder_name"),
            ATTR_MESSAGE_ID: latest.get("id"),
            ATTR_UNREAD: latest.get("unread"),
            ATTR_MESSAGES: [
                {
                    "sender": m.get("sender"),
                    "subject": m.get("subject"),
                    "received": m.get("received"),
                    "unread": m.get("unread"),
                }
                for m in messages
            ],
        }
