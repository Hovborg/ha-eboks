"""Services for e-Boks integration."""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import TYPE_CHECKING, Any, TypedDict

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.helpers import config_validation as cv

from .const import DOMAIN

if TYPE_CHECKING:
    from .api import EboksApi
    from .coordinator import EboksCoordinator

_LOGGER = logging.getLogger(__name__)

# Service names
SERVICE_DOWNLOAD_MESSAGE = "download_message"
SERVICE_MARK_AS_READ = "mark_as_read"
SERVICE_REFRESH = "refresh"

# Service schemas
SERVICE_DOWNLOAD_SCHEMA = vol.Schema({
    vol.Required("message_id"): cv.string,
    vol.Required("folder_id"): cv.string,
    vol.Optional("filename"): cv.string,
})

SERVICE_MARK_READ_SCHEMA = vol.Schema({
    vol.Required("message_id"): cv.string,
    vol.Required("folder_id"): cv.string,
})


class DownloadResult(TypedDict, total=False):
    """Type for download service result."""

    success: bool
    url: str
    path: str
    error: str


class MarkReadResult(TypedDict, total=False):
    """Type for mark as read service result."""

    success: bool
    error: str


def _get_api_and_coordinator(
    hass: HomeAssistant,
) -> tuple[EboksApi | None, EboksCoordinator | None]:
    """Get the first available API and coordinator."""
    for entry_id, data in hass.data.get(DOMAIN, {}).items():
        api: EboksApi | None = data.get("api")
        coordinator: EboksCoordinator | None = data.get("coordinator")
        if api:
            return api, coordinator
    return None, None


async def async_setup_services(hass: HomeAssistant) -> None:
    """Set up e-Boks services."""

    async def handle_download_message(call: ServiceCall) -> ServiceResponse:
        """Handle download message service call."""
        message_id: str = call.data["message_id"]
        folder_id: str = call.data["folder_id"]
        filename: str | None = call.data.get("filename")

        api, _ = _get_api_and_coordinator(hass)
        if not api:
            return DownloadResult(success=False, error="No e-Boks API available")

        try:
            content = await api.get_message_content(folder_id, message_id)
            if not content:
                return DownloadResult(success=False, error="No content returned")

            # Create www/eboks directory if it doesn't exist
            www_path: str = hass.config.path("www", "eboks")
            os.makedirs(www_path, exist_ok=True)

            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"eboks_{message_id[:20]}_{timestamp}.pdf"

            # Ensure .pdf extension
            if not filename.lower().endswith(".pdf"):
                filename += ".pdf"

            # Save file
            file_path = os.path.join(www_path, filename)
            with open(file_path, "wb") as f:
                f.write(content)

            # Return URL for browser access
            url = f"/local/eboks/{filename}"
            _LOGGER.info("Downloaded e-Boks message to %s", file_path)

            # Fire event with download info
            hass.bus.async_fire(f"{DOMAIN}_message_downloaded", {
                "message_id": message_id,
                "folder_id": folder_id,
                "filename": filename,
                "url": url,
                "path": file_path,
            })

            return DownloadResult(success=True, url=url, path=file_path)

        except Exception as err:
            _LOGGER.error("Failed to download message: %s", err)
            return DownloadResult(success=False, error=str(err))

    async def handle_mark_as_read(call: ServiceCall) -> ServiceResponse:
        """Handle mark as read service call.

        Note: In e-Boks, downloading/viewing the content typically marks it as read.
        This service downloads the content to mark it as read.
        """
        message_id: str = call.data["message_id"]
        folder_id: str = call.data["folder_id"]

        api, coordinator = _get_api_and_coordinator(hass)
        if not api:
            return MarkReadResult(success=False, error="No e-Boks API available")

        try:
            # Download content to mark as read (e-Boks marks as read on view)
            content = await api.get_message_content(folder_id, message_id)
            if not content:
                return MarkReadResult(success=False, error="Failed to access message")

            _LOGGER.info("Marked message %s as read", message_id)

            # Refresh data to update unread counts
            if coordinator:
                await coordinator.async_request_refresh()

            # Fire event
            hass.bus.async_fire(f"{DOMAIN}_message_read", {
                "message_id": message_id,
                "folder_id": folder_id,
            })

            return MarkReadResult(success=True)

        except Exception as err:
            _LOGGER.error("Failed to mark message as read: %s", err)
            return MarkReadResult(success=False, error=str(err))

    async def handle_refresh(call: ServiceCall) -> None:
        """Handle refresh service call."""
        _, coordinator = _get_api_and_coordinator(hass)
        if coordinator:
            await coordinator.async_request_refresh()
            _LOGGER.info("Refreshed e-Boks data")

    # Register services
    hass.services.async_register(
        DOMAIN,
        SERVICE_DOWNLOAD_MESSAGE,
        handle_download_message,
        schema=SERVICE_DOWNLOAD_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_MARK_AS_READ,
        handle_mark_as_read,
        schema=SERVICE_MARK_READ_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_REFRESH,
        handle_refresh,
    )


async def async_unload_services(hass: HomeAssistant) -> None:
    """Unload e-Boks services."""
    hass.services.async_remove(DOMAIN, SERVICE_DOWNLOAD_MESSAGE)
    hass.services.async_remove(DOMAIN, SERVICE_MARK_AS_READ)
    hass.services.async_remove(DOMAIN, SERVICE_REFRESH)
