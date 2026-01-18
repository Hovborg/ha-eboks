"""The e-Boks integration."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import EboksApi, EboksApiError, EboksAuthError
from .const import (
    CONF_ACTIVATION_CODE,
    CONF_CPR,
    CONF_DEVICE_ID,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .services import async_setup_services, async_unload_services

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]

# Event names
EVENT_NEW_MESSAGE = f"{DOMAIN}_new_message"
EVENT_UNREAD_CHANGED = f"{DOMAIN}_unread_changed"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up e-Boks from a config entry."""
    session = async_get_clientsession(hass)

    api = EboksApi(
        cpr=entry.data[CONF_CPR],
        password=entry.data[CONF_PASSWORD],
        device_id=entry.data.get(CONF_DEVICE_ID),
        activation_code=entry.data[CONF_ACTIVATION_CODE],
        session=session,
    )

    # Track previous state for event firing
    previous_data: dict[str, Any] = {
        "unread_count": None,
        "message_ids": set(),
    }

    async def async_update_data() -> dict[str, Any]:
        """Fetch data from e-Boks."""
        try:
            messages = await api.get_all_messages()
            unread_count = await api.get_unread_count()
            folders = await api.get_folders()

            data = {
                "messages": messages,
                "unread_count": unread_count,
                "folders": folders,
                "latest_message": messages[0] if messages else None,
            }

            # Fire events for new messages
            current_message_ids = {m["id"] for m in messages}

            if previous_data["unread_count"] is not None:
                # Check for new messages
                new_message_ids = current_message_ids - previous_data["message_ids"]

                for msg in messages:
                    if msg["id"] in new_message_ids and msg.get("unread"):
                        # Fire event for each new unread message
                        hass.bus.async_fire(EVENT_NEW_MESSAGE, {
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
                if unread_count != previous_data["unread_count"]:
                    hass.bus.async_fire(EVENT_UNREAD_CHANGED, {
                        "previous_count": previous_data["unread_count"],
                        "current_count": unread_count,
                        "difference": unread_count - previous_data["unread_count"],
                    })

            # Update previous state
            previous_data["unread_count"] = unread_count
            previous_data["message_ids"] = current_message_ids

            return data
        except EboksAuthError as err:
            raise ConfigEntryAuthFailed from err
        except EboksApiError as err:
            raise UpdateFailed(f"Error communicating with e-Boks: {err}") from err

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=DOMAIN,
        update_method=async_update_data,
        update_interval=DEFAULT_SCAN_INTERVAL,
    )

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "coordinator": coordinator,
        "api": api,
    }

    # Set up services (only once)
    if len(hass.data[DOMAIN]) == 1:
        await async_setup_services(hass)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data = hass.data[DOMAIN].pop(entry.entry_id)
        await data["api"].close()

        # Unload services if no more entries
        if not hass.data[DOMAIN]:
            await async_unload_services(hass)

    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
