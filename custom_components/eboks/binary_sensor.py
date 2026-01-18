"""Binary sensor platform for e-Boks integration."""
from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import ATTR_RECEIVED, ATTR_SENDER, ATTR_SUBJECT, CONF_CPR, DOMAIN
from .coordinator import EboksCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up e-Boks binary sensors."""
    coordinator: EboksCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    cpr: str = entry.data[CONF_CPR]

    async_add_entities([
        EboksUnreadSensor(coordinator, entry, cpr),
        EboksConnectionSensor(coordinator, entry, cpr),
    ])


class EboksUnreadSensor(CoordinatorEntity[EboksCoordinator], BinarySensorEntity):
    """Binary sensor indicating unread messages."""

    _attr_icon = "mdi:email-alert"
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: EboksCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._cpr = cpr
        self._attr_unique_id = f"{entry.entry_id}_unread"
        self._attr_name = "Ulæst post"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"e-Boks ({self._cpr[:6]}...)",
            manufacturer="e-Boks",
            model="Digital Postkasse",
        )

    @property
    def is_on(self) -> bool:
        """Return True if there are unread messages."""
        if self.coordinator.data:
            return int(self.coordinator.data.get("unread_count", 0)) > 0
        return False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        if not self.coordinator.data:
            return {}

        latest: dict[str, Any] | None = self.coordinator.data.get("latest_message")
        unread_count: int = self.coordinator.data.get("unread_count", 0)

        attrs: dict[str, Any] = {"unread_count": unread_count}

        if latest and latest.get("unread"):
            attrs[ATTR_SENDER] = latest.get("sender")
            attrs[ATTR_SUBJECT] = latest.get("subject")
            attrs[ATTR_RECEIVED] = latest.get("received")

        return attrs


class EboksConnectionSensor(CoordinatorEntity[EboksCoordinator], BinarySensorEntity):
    """Binary sensor indicating e-Boks connection status."""

    _attr_icon = "mdi:connection"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: EboksCoordinator,
        entry: ConfigEntry,
        cpr: str,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._cpr = cpr
        self._attr_unique_id = f"{entry.entry_id}_connection"
        self._attr_name = "Forbindelse"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=f"e-Boks ({self._cpr[:6]}...)",
            manufacturer="e-Boks",
            model="Digital Postkasse",
        )

    @property
    def is_on(self) -> bool:
        """Return True if connection is OK."""
        return self.coordinator.connection_ok

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        attrs: dict[str, Any] = {
            "connection_ok": self.coordinator.connection_ok,
        }

        if self.coordinator.last_updated:
            attrs["last_updated"] = self.coordinator.last_updated.isoformat()

        if self.coordinator.update_interval:
            attrs["update_interval_minutes"] = (
                self.coordinator.update_interval.total_seconds() / 60
            )

        return attrs
