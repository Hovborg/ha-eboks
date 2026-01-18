"""Diagnostics support for e-Boks integration."""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant

from .const import CONF_ACTIVATION_CODE, CONF_CPR, CONF_DEVICE_ID, DOMAIN

# Keys to redact from diagnostics
TO_REDACT = {
    CONF_CPR,
    CONF_PASSWORD,
    CONF_ACTIVATION_CODE,
    CONF_DEVICE_ID,
    "cpr",
    "password",
    "activation_code",
    "device_id",
    "sender",  # May contain personal info
    "subject",  # May contain sensitive info
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    # Get coordinator data
    coordinator_data = coordinator.data or {}

    # Redact sensitive message data
    messages = []
    for msg in coordinator_data.get("messages", [])[:10]:  # Limit to 10 messages
        messages.append({
            "id": msg.get("id"),
            "sender": "**REDACTED**",
            "subject": "**REDACTED**",
            "received": msg.get("received"),
            "unread": msg.get("unread"),
            "format": msg.get("format"),
            "folder_id": msg.get("folder_id"),
            "folder_name": msg.get("folder_name"),
            "attachments_count": msg.get("attachments_count"),
            "size": msg.get("size"),
        })

    # Get folder info (safe to include)
    folders = coordinator_data.get("folders", [])

    return {
        "entry": {
            "entry_id": entry.entry_id,
            "version": entry.version,
            "domain": entry.domain,
            "title": async_redact_data({"title": entry.title}, {"title"})["title"],
            "data": async_redact_data(dict(entry.data), TO_REDACT),
        },
        "coordinator": {
            "last_update_success": coordinator.last_update_success,
            "update_interval": str(coordinator.update_interval),
        },
        "data": {
            "unread_count": coordinator_data.get("unread_count"),
            "total_messages": len(coordinator_data.get("messages", [])),
            "folders": folders,
            "messages_sample": messages,
            "has_latest_message": coordinator_data.get("latest_message") is not None,
        },
    }
