"""Fixtures for e-Boks integration tests."""
from __future__ import annotations

from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from custom_components.eboks.const import DOMAIN


@pytest.fixture
def mock_config_entry_data() -> dict[str, Any]:
    """Return mock config entry data."""
    return {
        "cpr": "0101901234",
        "password": "1234",
        "activation_code": "Abc12345",
        "device_id": "TEST-DEVICE-ID-1234",
    }


@pytest.fixture
def mock_folders() -> list[dict[str, Any]]:
    """Return mock folders data."""
    return [
        {"id": "0", "name": "Indbakke", "unread": 2},
        {"id": "1", "name": "Arkiv", "unread": 0},
        {"id": "2", "name": "Skat", "unread": 1},
    ]


@pytest.fixture
def mock_messages() -> list[dict[str, Any]]:
    """Return mock messages data."""
    return [
        {
            "id": "msg-001",
            "subject": "Din årsopgørelse 2025",
            "sender": "Skattestyrelsen",
            "received": "2026-01-15T10:30:00",
            "unread": True,
            "format": "pdf",
            "folder_id": "0",
            "folder_name": "Indbakke",
            "attachments_count": 1,
            "size": 125000,
        },
        {
            "id": "msg-002",
            "subject": "Brev fra kommunen",
            "sender": "København Kommune",
            "received": "2026-01-14T14:20:00",
            "unread": True,
            "format": "pdf",
            "folder_id": "0",
            "folder_name": "Indbakke",
            "attachments_count": 0,
            "size": 45000,
        },
        {
            "id": "msg-003",
            "subject": "Kontoudtog januar",
            "sender": "Danske Bank",
            "received": "2026-01-10T09:00:00",
            "unread": False,
            "format": "pdf",
            "folder_id": "0",
            "folder_name": "Indbakke",
            "attachments_count": 2,
            "size": 250000,
        },
    ]


@pytest.fixture
def mock_api(mock_folders: list, mock_messages: list) -> Generator[MagicMock, None, None]:
    """Return a mocked e-Boks API."""
    with patch(
        "custom_components.eboks.api.EboksApi", autospec=True
    ) as mock_api_class:
        api_instance = mock_api_class.return_value
        api_instance.authenticate = AsyncMock(return_value=True)
        api_instance.get_folders = AsyncMock(return_value=mock_folders)
        api_instance.get_messages = AsyncMock(return_value=mock_messages)
        api_instance.get_all_messages = AsyncMock(return_value=mock_messages)
        api_instance.get_unread_count = AsyncMock(return_value=3)
        api_instance.get_message_content = AsyncMock(return_value=b"%PDF-1.4 test content")
        api_instance.close = AsyncMock()
        api_instance.device_id = "TEST-DEVICE-ID-1234"
        api_instance.activation_code = "Abc12345"
        yield api_instance


@pytest.fixture
def mock_api_auth_error() -> Generator[MagicMock, None, None]:
    """Return a mocked e-Boks API that fails authentication."""
    with patch(
        "custom_components.eboks.api.EboksApi", autospec=True
    ) as mock_api_class:
        from custom_components.eboks.api import EboksAuthError
        api_instance = mock_api_class.return_value
        api_instance.authenticate = AsyncMock(side_effect=EboksAuthError("Invalid credentials"))
        api_instance.device_id = "TEST-DEVICE-ID-1234"
        yield api_instance


@pytest.fixture
def mock_api_connection_error() -> Generator[MagicMock, None, None]:
    """Return a mocked e-Boks API that fails to connect."""
    with patch(
        "custom_components.eboks.api.EboksApi", autospec=True
    ) as mock_api_class:
        from custom_components.eboks.api import EboksApiError
        api_instance = mock_api_class.return_value
        api_instance.authenticate = AsyncMock(side_effect=EboksApiError("Connection error"))
        api_instance.device_id = "TEST-DEVICE-ID-1234"
        yield api_instance


@pytest.fixture
def mock_coordinator_data(mock_messages: list, mock_folders: list) -> dict[str, Any]:
    """Return mock coordinator data."""
    return {
        "messages": mock_messages,
        "unread_count": 3,
        "folders": mock_folders,
        "latest_message": mock_messages[0] if mock_messages else None,
    }
