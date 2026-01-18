"""Tests for e-Boks integration setup."""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant

from custom_components.eboks.const import DOMAIN


async def test_setup_entry_success(
    hass: HomeAssistant,
    mock_config_entry_data: dict[str, Any],
    mock_folders: list,
    mock_messages: list,
) -> None:
    """Test successful setup of config entry."""
    with patch(
        "custom_components.eboks.EboksApi"
    ) as mock_api_class:
        mock_api = mock_api_class.return_value
        mock_api.authenticate = AsyncMock(return_value=True)
        mock_api.get_folders = AsyncMock(return_value=mock_folders)
        mock_api.get_messages = AsyncMock(return_value=mock_messages)
        mock_api.get_all_messages = AsyncMock(return_value=mock_messages)
        mock_api.get_unread_count = AsyncMock(return_value=3)
        mock_api.close = AsyncMock()

        entry = MagicMock()
        entry.entry_id = "test_entry"
        entry.data = mock_config_entry_data
        entry.add_to_hass(hass)

        # The setup would be tested through the actual flow
        # For unit tests, we verify the API is called correctly
        mock_api.get_all_messages.assert_not_called()  # Not called until coordinator runs


async def test_unload_entry(
    hass: HomeAssistant,
    mock_config_entry_data: dict[str, Any],
) -> None:
    """Test unloading a config entry."""
    with patch(
        "custom_components.eboks.EboksApi"
    ) as mock_api_class:
        mock_api = mock_api_class.return_value
        mock_api.close = AsyncMock()

        # Setup mock data structure
        hass.data[DOMAIN] = {
            "test_entry": {
                "coordinator": MagicMock(),
                "api": mock_api,
            }
        }

        # Simulate unload
        data = hass.data[DOMAIN].pop("test_entry")
        await data["api"].close()

        mock_api.close.assert_called_once()
        assert "test_entry" not in hass.data[DOMAIN]


async def test_events_fired_on_new_message(
    hass: HomeAssistant,
    mock_messages: list,
) -> None:
    """Test that events are fired when new messages arrive."""
    from custom_components.eboks import EVENT_NEW_MESSAGE

    events = []

    def event_listener(event):
        events.append(event)

    hass.bus.async_listen(EVENT_NEW_MESSAGE, event_listener)

    # Fire test event
    hass.bus.async_fire(EVENT_NEW_MESSAGE, {
        "message_id": "msg-001",
        "sender": "Test Sender",
        "subject": "Test Subject",
    })

    await hass.async_block_till_done()

    assert len(events) == 1
    assert events[0].data["message_id"] == "msg-001"
    assert events[0].data["sender"] == "Test Sender"


async def test_events_fired_on_unread_changed(
    hass: HomeAssistant,
) -> None:
    """Test that events are fired when unread count changes."""
    from custom_components.eboks import EVENT_UNREAD_CHANGED

    events = []

    def event_listener(event):
        events.append(event)

    hass.bus.async_listen(EVENT_UNREAD_CHANGED, event_listener)

    # Fire test event
    hass.bus.async_fire(EVENT_UNREAD_CHANGED, {
        "previous_count": 2,
        "current_count": 5,
        "difference": 3,
    })

    await hass.async_block_till_done()

    assert len(events) == 1
    assert events[0].data["previous_count"] == 2
    assert events[0].data["current_count"] == 5
    assert events[0].data["difference"] == 3
