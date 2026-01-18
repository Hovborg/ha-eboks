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

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]


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

    async def async_update_data() -> dict[str, Any]:
        """Fetch data from e-Boks."""
        try:
            messages = await api.get_all_messages()
            unread_count = await api.get_unread_count()
            folders = await api.get_folders()

            return {
                "messages": messages,
                "unread_count": unread_count,
                "folders": folders,
                "latest_message": messages[0] if messages else None,
            }
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

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data = hass.data[DOMAIN].pop(entry.entry_id)
        await data["api"].close()

    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
