"""Tests for e-Boks diagnostics."""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from homeassistant.core import HomeAssistant

from custom_components.eboks.const import DOMAIN
from custom_components.eboks.diagnostics import async_get_config_entry_diagnostics


@pytest.fixture
def mock_entry() -> MagicMock:
    """Create a mock config entry."""
    entry = MagicMock()
    entry.entry_id = "test_entry_id"
    entry.version = 1
    entry.domain = DOMAIN
    entry.title = "e-Boks (010190...)"
    entry.data = {
        "cpr": "0101901234",
        "password": "secret_password",
        "activation_code": "Abc12345",
        "device_id": "TEST-DEVICE-ID",
    }
    return entry


async def test_diagnostics_redacts_sensitive_data(
    hass: HomeAssistant,
    mock_entry: MagicMock,
    mock_coordinator_data: dict[str, Any],
) -> None:
    """Test that diagnostics redacts sensitive data."""
    # Setup mock coordinator
    coordinator = MagicMock()
    coordinator.data = mock_coordinator_data
    coordinator.last_update_success = True
    coordinator.update_interval = "0:30:00"

    hass.data[DOMAIN] = {
        "test_entry_id": {
            "coordinator": coordinator,
            "api": MagicMock(),
        }
    }

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_entry)

    # Check that config entry data is redacted
    assert diagnostics["entry"]["data"]["cpr"] == "**REDACTED**"
    assert diagnostics["entry"]["data"]["password"] == "**REDACTED**"
    assert diagnostics["entry"]["data"]["activation_code"] == "**REDACTED**"
    assert diagnostics["entry"]["data"]["device_id"] == "**REDACTED**"

    # Check that messages have redacted sender/subject
    for msg in diagnostics["data"]["messages_sample"]:
        assert msg["sender"] == "**REDACTED**"
        assert msg["subject"] == "**REDACTED**"

    # Check that non-sensitive data is included
    assert diagnostics["data"]["unread_count"] == 3
    assert diagnostics["coordinator"]["last_update_success"] is True


async def test_diagnostics_with_no_data(
    hass: HomeAssistant,
    mock_entry: MagicMock,
) -> None:
    """Test diagnostics when coordinator has no data."""
    coordinator = MagicMock()
    coordinator.data = None
    coordinator.last_update_success = False
    coordinator.update_interval = "0:30:00"

    hass.data[DOMAIN] = {
        "test_entry_id": {
            "coordinator": coordinator,
            "api": MagicMock(),
        }
    }

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_entry)

    assert diagnostics["data"]["unread_count"] is None
    assert diagnostics["data"]["total_messages"] == 0
    assert diagnostics["data"]["messages_sample"] == []
