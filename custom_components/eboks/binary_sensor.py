"""Binary sensor platform for e-Boks integration."""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import ATTR_RECEIVED, ATTR_SENDER, ATTR_SUBJECT, CONF_CPR, DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up e-Boks binary sensors."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    cpr = entry.data[CONF_CPR]

    async_add_entities([EboksUnreadSensor(coordinator, entry, cpr)])


class EboksUnreadSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor indicating unread messages."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_icon = "mdi:email-alert"
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
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
    def device_info(self):
        """Return device info."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": f"e-Boks ({self._cpr[:6]}...)",
            "manufacturer": "e-Boks",
            "model": "Digital Postkasse",
        }

    @property
    def is_on(self) -> bool:
        """Return True if there are unread messages."""
        if self.coordinator.data:
            return self.coordinator.data.get("unread_count", 0) > 0
        return False

    @property
    def extra_state_attributes(self):
        """Return additional attributes."""
        if not self.coordinator.data:
            return {}

        latest = self.coordinator.data.get("latest_message")
        unread_count = self.coordinator.data.get("unread_count", 0)

        attrs = {"unread_count": unread_count}

        if latest and latest.get("unread"):
            attrs[ATTR_SENDER] = latest.get("sender")
            attrs[ATTR_SUBJECT] = latest.get("subject")
            attrs[ATTR_RECEIVED] = latest.get("received")

        return attrs
