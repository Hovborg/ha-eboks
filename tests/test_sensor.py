"""Tests for e-Boks sensors."""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from custom_components.eboks.sensor import (
    EboksLatestMessageSensor,
    EboksMessageCountSensor,
    EboksMessageSensor,
)
from custom_components.eboks.const import DOMAIN


@pytest.fixture
def mock_entry() -> MagicMock:
    """Create a mock config entry."""
    entry = MagicMock()
    entry.entry_id = "test_entry_id"
    entry.data = {
        "cpr": "0101901234",
        "password": "1234",
        "activation_code": "Abc12345",
        "device_id": "TEST-DEVICE-ID",
    }
    return entry


@pytest.fixture
def mock_coordinator(
    hass: HomeAssistant,
    mock_coordinator_data: dict[str, Any],
) -> MagicMock:
    """Create a mock coordinator."""
    coordinator = MagicMock(spec=DataUpdateCoordinator)
    coordinator.data = mock_coordinator_data
    coordinator.hass = hass
    return coordinator


class TestEboksMessageCountSensor:
    """Tests for message count sensor."""

    def test_native_value_with_data(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test native value with coordinator data."""
        sensor = EboksMessageCountSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
        )

        assert sensor.native_value == 3  # From mock_coordinator_data

    def test_native_value_without_data(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test native value without coordinator data."""
        mock_coordinator.data = None
        sensor = EboksMessageCountSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
        )

        assert sensor.native_value == 0

    def test_extra_state_attributes(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test extra state attributes."""
        sensor = EboksMessageCountSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
        )

        attrs = sensor.extra_state_attributes

        assert "folders" in attrs
        assert "total_messages" in attrs
        assert attrs["total_messages"] == 3  # 3 mock messages

    def test_unique_id(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test unique ID."""
        sensor = EboksMessageCountSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
        )

        assert sensor.unique_id == "test_entry_id_message_count"

    def test_device_info(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test device info."""
        sensor = EboksMessageCountSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
        )

        device_info = sensor.device_info

        assert device_info["identifiers"] == {(DOMAIN, "test_entry_id")}
        assert "e-Boks" in device_info["name"]
        assert device_info["manufacturer"] == "e-Boks"


class TestEboksLatestMessageSensor:
    """Tests for latest message sensor."""

    def test_native_value_with_messages(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test native value with messages."""
        sensor = EboksLatestMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
        )

        assert sensor.native_value == "Din årsopgørelse 2025"

    def test_native_value_without_messages(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test native value without messages."""
        mock_coordinator.data = {"messages": [], "latest_message": None}
        sensor = EboksLatestMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
        )

        assert sensor.native_value == "Ingen beskeder"

    def test_extra_state_attributes(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test extra state attributes."""
        sensor = EboksLatestMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
        )

        attrs = sensor.extra_state_attributes

        assert attrs["sender"] == "Skattestyrelsen"
        assert attrs["subject"] == "Din årsopgørelse 2025"
        assert "messages" in attrs


class TestEboksMessageSensor:
    """Tests for individual message sensors."""

    def test_native_value_position_1(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test native value for position 1."""
        sensor = EboksMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
            position=1,
        )

        assert sensor.native_value == "Din årsopgørelse 2025"

    def test_native_value_position_2(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test native value for position 2."""
        sensor = EboksMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
            position=2,
        )

        assert sensor.native_value == "Brev fra kommunen"

    def test_native_value_no_message_at_position(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test native value when no message at position."""
        sensor = EboksMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
            position=10,  # Position beyond available messages
        )

        assert sensor.native_value == "Ingen besked"

    def test_icon_unread(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test icon for unread message."""
        sensor = EboksMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
            position=1,  # First message is unread
        )

        assert sensor.icon == "mdi:email-mark-as-unread"

    def test_icon_read(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test icon for read message."""
        sensor = EboksMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
            position=3,  # Third message is read
        )

        assert sensor.icon == "mdi:email-open-outline"

    def test_extra_state_attributes(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test extra state attributes."""
        sensor = EboksMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
            position=1,
        )

        attrs = sensor.extra_state_attributes

        assert attrs["position"] == 1
        assert attrs["message_id"] == "msg-001"
        assert attrs["sender"] == "Skattestyrelsen"
        assert attrs["attachments"] == 1
        assert attrs["size_bytes"] == 125000

    def test_unique_id(
        self,
        mock_coordinator: MagicMock,
        mock_entry: MagicMock,
    ) -> None:
        """Test unique ID includes position."""
        sensor = EboksMessageSensor(
            coordinator=mock_coordinator,
            entry=mock_entry,
            cpr="0101901234",
            position=3,
        )

        assert sensor.unique_id == "test_entry_id_message_3"
