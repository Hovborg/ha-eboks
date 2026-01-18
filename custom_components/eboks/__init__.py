"""The e-Boks integration."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import EboksApi
from .const import (
    CONF_ACTIVATION_CODE,
    CONF_CPR,
    CONF_DEVICE_ID,
    CONF_MESSAGE_COUNT,
    CONF_NOTIFY_SENDERS,
    CONF_SCAN_INTERVAL,
    DEFAULT_MESSAGE_COUNT,
    DEFAULT_NOTIFY_SENDERS,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .coordinator import EboksCoordinator, EVENT_NEW_MESSAGE, EVENT_UNREAD_CHANGED
from .services import async_setup_services, async_unload_services

__all__ = ["EVENT_NEW_MESSAGE", "EVENT_UNREAD_CHANGED"]

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.BUTTON]


def get_options(entry: ConfigEntry) -> dict[str, Any]:
    """Get options from config entry with defaults."""
    notify_senders = entry.options.get(CONF_NOTIFY_SENDERS, "")
    if isinstance(notify_senders, str):
        # Parse comma-separated string to list
        notify_senders = [s.strip() for s in notify_senders.split(",") if s.strip()]
    if not notify_senders:
        notify_senders = DEFAULT_NOTIFY_SENDERS

    return {
        CONF_SCAN_INTERVAL: entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        CONF_MESSAGE_COUNT: entry.options.get(CONF_MESSAGE_COUNT, DEFAULT_MESSAGE_COUNT),
        CONF_NOTIFY_SENDERS: notify_senders,
    }


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

    # Get options
    options = get_options(entry)
    scan_interval = timedelta(minutes=options[CONF_SCAN_INTERVAL])
    notify_senders = options[CONF_NOTIFY_SENDERS]

    coordinator = EboksCoordinator(
        hass,
        api,
        scan_interval=scan_interval,
        notify_senders=notify_senders,
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

    # Add options update listener
    entry.async_on_unload(entry.add_update_listener(async_options_updated))

    return True


async def async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)


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
