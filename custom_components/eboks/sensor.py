"""Sensor platform for e-Boks integration."""
from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ATTR_FOLDER,
    ATTR_MESSAGE_ID,
    ATTR_MESSAGES,
    ATTR_RECEIVED,
    ATTR_SENDER,
    ATTR_SUBJECT,
    ATTR_UNREAD,
    CONF_CPR,
    CONF_MESSAGE_COUNT,
    DEFAULT_MESSAGE_COUNT,
    DOMAIN,
)
from .coordinator import EboksCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up e-Boks sensors."""
    coordinator: EboksCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    cpr: str = entry.data[CONF_CPR]

    # Get message count from options
    message_count = entry.options.get(CONF_MESSAGE_COUNT, DEFAULT_MESSAGE_COUNT)

    entities: list[SensorEntity] = [
        EboksMessageCountSensor(coordinator, entry, cpr),
        EboksLatestMessageSensor(coordinator, entry, cpr),
        EboksLastUpdatedSensor(coordinator, entry, cpr),
    ]

    # Add individual message sensors based on options
    for i in range(1, message_count + 1):
        entities.append(EboksMessageSensor(coordinator, entry, cpr, i))

    # Add folder sensors
    if coordinator.data and coordinator.data.get("folders"):
        for folder in coordinator.data["folders"]:
            entities.append(EboksFolderSensor(coordinator, entry, cpr, folder))

    async_add_entities(entities)


class EboksBaseSensor(CoordinatorEntity[EboksCoordinator], SensorEntity):
    """Base class for e-Boks sensors."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: EboksCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._cpr = cpr

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"e-Boks ({self._cpr[:6]}...)",
            manufacturer="e-Boks",
            model="Digital Postkasse",
        )


class EboksMessageCountSensor(EboksBaseSensor):
    """Sensor for e-Boks message count."""

    _attr_icon = "mdi:email-multiple"
    _attr_native_unit_of_measurement = "beskeder"

    def __init__(
        self,
        coordinator: EboksCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, cpr)
        self._attr_unique_id = f"{entry.entry_id}_message_count"
        self._attr_name = "Ulæste beskeder"

    @property
    def native_value(self) -> int:
        """Return the number of unread messages."""
        if self.coordinator.data:
            return int(self.coordinator.data.get("unread_count", 0))
        return 0

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        if not self.coordinator.data:
            return {}

        folders: list[dict[str, Any]] = self.coordinator.data.get("folders", [])
        messages: list[dict[str, Any]] = self.coordinator.data.get("messages", [])

        return {
            "folders": [
                {"name": f["name"], "unread": f["unread"]}
                for f in folders
            ],
            "total_messages": len(messages),
        }


class EboksLatestMessageSensor(EboksBaseSensor):
    """Sensor for latest e-Boks message."""

    _attr_icon = "mdi:email"

    def __init__(
        self,
        coordinator: EboksCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, cpr)
        self._attr_unique_id = f"{entry.entry_id}_latest_message"
        self._attr_name = "Seneste besked"

    @property
    def native_value(self) -> str:
        """Return the subject of the latest message."""
        if self.coordinator.data:
            latest: dict[str, Any] | None = self.coordinator.data.get("latest_message")
            if latest:
                return str(latest.get("subject", "Ingen emne"))
        return "Ingen beskeder"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        if not self.coordinator.data:
            return {}

        latest: dict[str, Any] | None = self.coordinator.data.get("latest_message")
        if not latest:
            return {}

        # Include last 20 messages with full details for services
        messages: list[dict[str, Any]] = self.coordinator.data.get("messages", [])[:20]

        return {
            ATTR_SENDER: latest.get("sender"),
            ATTR_SUBJECT: latest.get("subject"),
            ATTR_RECEIVED: latest.get("received"),
            ATTR_FOLDER: latest.get("folder_name"),
            ATTR_MESSAGE_ID: latest.get("id"),
            ATTR_UNREAD: latest.get("unread"),
            "folder_id": latest.get("folder_id"),
            ATTR_MESSAGES: [
                {
                    "message_id": m.get("id"),
                    "folder_id": m.get("folder_id"),
                    "sender": m.get("sender"),
                    "subject": m.get("subject"),
                    "received": m.get("received"),
                    "folder": m.get("folder_name"),
                    "unread": m.get("unread"),
                }
                for m in messages
            ],
        }


class EboksMessageSensor(EboksBaseSensor):
    """Sensor for individual e-Boks message (1-5)."""

    _attr_icon = "mdi:email-outline"

    def __init__(
        self,
        coordinator: EboksCoordinator,
        entry: ConfigEntry,
        cpr: str,
        position: int,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, cpr)
        self._position = position
        self._attr_unique_id = f"{entry.entry_id}_message_{position}"
        self._attr_name = f"Besked {position}"

    def _get_message(self) -> dict[str, Any] | None:
        """Get the message at this position from inbox only."""
        if not self.coordinator.data:
            return None
        messages: list[dict[str, Any]] = self.coordinator.data.get("messages", [])
        # Filter to only inbox messages (folder name contains inbox/indbakke)
        inbox_messages = [
            m for m in messages
            if self._is_inbox_folder(m.get("folder_name", ""))
        ]
        if len(inbox_messages) >= self._position:
            return inbox_messages[self._position - 1]
        return None

    @staticmethod
    def _is_inbox_folder(folder_name: str) -> bool:
        """Check if folder is the inbox folder."""
        name_lower = folder_name.lower() if folder_name else ""
        return "inbox" in name_lower or "indbakke" in name_lower

    @property
    def native_value(self) -> str:
        """Return the subject of this message."""
        msg = self._get_message()
        if msg:
            return str(msg.get("subject", "Ingen emne"))
        return "Ingen besked"

    @property
    def icon(self) -> str:
        """Return icon based on read status."""
        msg = self._get_message()
        if msg and msg.get("unread"):
            return "mdi:email-mark-as-unread"
        return "mdi:email-open-outline"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        msg = self._get_message()
        if not msg:
            return {"position": self._position}

        return {
            "position": self._position,
            "message_id": msg.get("id"),
            "folder_id": msg.get("folder_id"),
            "sender": msg.get("sender"),
            "subject": msg.get("subject"),
            "received": msg.get("received"),
            "folder": msg.get("folder_name"),
            "unread": msg.get("unread"),
            "format": msg.get("format"),
            "attachments": msg.get("attachments_count", 0),
            "size_bytes": msg.get("size", 0),
        }


class EboksLastUpdatedSensor(EboksBaseSensor):
    """Sensor showing when e-Boks was last updated."""

    _attr_icon = "mdi:clock-check-outline"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(
        self,
        coordinator: EboksCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, cpr)
        self._attr_unique_id = f"{entry.entry_id}_last_updated"
        self._attr_name = "Sidst opdateret"

    @property
    def native_value(self) -> str | None:
        """Return the last update timestamp."""
        if self.coordinator.last_updated:
            return self.coordinator.last_updated.isoformat()
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        if not self.coordinator.data:
            return {}

        return {
            "connection_ok": self.coordinator.connection_ok,
            "update_interval_minutes": self.coordinator.update_interval.total_seconds() / 60
            if self.coordinator.update_interval
            else None,
        }


class EboksFolderSensor(EboksBaseSensor):
    """Sensor for an e-Boks folder."""

    _attr_icon = "mdi:folder-outline"
    _attr_native_unit_of_measurement = "beskeder"

    def __init__(
        self,
        coordinator: EboksCoordinator,
        entry: ConfigEntry,
        cpr: str,
        folder: dict[str, Any],
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, cpr)
        self._folder_id = folder.get("id", "")
        self._folder_name = folder.get("name", "Ukendt")
        self._attr_unique_id = f"{entry.entry_id}_folder_{self._folder_id}"
        self._attr_name = f"Mappe: {self._folder_name}"

    def _get_folder(self) -> dict[str, Any] | None:
        """Get the folder data."""
        if not self.coordinator.data:
            return None
        folders: list[dict[str, Any]] = self.coordinator.data.get("folders", [])
        for folder in folders:
            if folder.get("id") == self._folder_id:
                return folder
        return None

    @property
    def native_value(self) -> int:
        """Return the number of unread messages in this folder."""
        folder = self._get_folder()
        if folder:
            return int(folder.get("unread", 0))
        return 0

    @property
    def icon(self) -> str:
        """Return icon based on folder name."""
        name_lower = self._folder_name.lower()
        if "indbakke" in name_lower or "inbox" in name_lower:
            return "mdi:inbox"
        if "arkiv" in name_lower or "archive" in name_lower:
            return "mdi:archive"
        if "papirkurv" in name_lower or "trash" in name_lower:
            return "mdi:trash-can"
        if "sendt" in name_lower or "sent" in name_lower:
            return "mdi:send"
        return "mdi:folder-outline"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        folder = self._get_folder()
        if not folder:
            return {"folder_id": self._folder_id}

        # Count messages in this folder
        messages: list[dict[str, Any]] = self.coordinator.data.get("messages", []) if self.coordinator.data else []
        folder_messages = [m for m in messages if m.get("folder_id") == self._folder_id]

        return {
            "folder_id": self._folder_id,
            "folder_name": self._folder_name,
            "total_count": folder.get("total", len(folder_messages)),
            "unread_count": folder.get("unread", 0),
        }
