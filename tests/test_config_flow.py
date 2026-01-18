"""Tests for e-Boks config flow."""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from custom_components.eboks.const import DOMAIN


async def test_form_user(hass: HomeAssistant, mock_api: AsyncMock) -> None:
    """Test we get the user form."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {}


async def test_form_user_success(
    hass: HomeAssistant,
    mock_config_entry_data: dict[str, Any],
) -> None:
    """Test successful user form submission."""
    with patch(
        "custom_components.eboks.config_flow.EboksApi"
    ) as mock_api_class:
        mock_api = mock_api_class.return_value
        mock_api.authenticate = AsyncMock(return_value=True)
        mock_api.get_folders = AsyncMock(return_value=[])
        mock_api.device_id = "TEST-DEVICE-ID"

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "cpr": mock_config_entry_data["cpr"],
                "password": mock_config_entry_data["password"],
                "activation_code": mock_config_entry_data["activation_code"],
            },
        )

        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert result["title"] == f"e-Boks ({mock_config_entry_data['cpr'][:6]}...)"
        assert result["data"]["cpr"] == mock_config_entry_data["cpr"]
        assert result["data"]["password"] == mock_config_entry_data["password"]
        assert result["data"]["activation_code"] == mock_config_entry_data["activation_code"]
        assert result["data"]["device_id"] == "TEST-DEVICE-ID"


async def test_form_invalid_auth(
    hass: HomeAssistant,
    mock_config_entry_data: dict[str, Any],
) -> None:
    """Test form with invalid authentication."""
    with patch(
        "custom_components.eboks.config_flow.EboksApi"
    ) as mock_api_class:
        from custom_components.eboks.api import EboksAuthError
        mock_api = mock_api_class.return_value
        mock_api.authenticate = AsyncMock(side_effect=EboksAuthError("Invalid credentials"))
        mock_api.device_id = "TEST-DEVICE-ID"

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "cpr": mock_config_entry_data["cpr"],
                "password": "wrong_password",
                "activation_code": mock_config_entry_data["activation_code"],
            },
        )

        assert result["type"] == FlowResultType.FORM
        assert result["errors"] == {"base": "invalid_auth"}


async def test_form_cannot_connect(
    hass: HomeAssistant,
    mock_config_entry_data: dict[str, Any],
) -> None:
    """Test form when connection fails."""
    with patch(
        "custom_components.eboks.config_flow.EboksApi"
    ) as mock_api_class:
        from custom_components.eboks.api import EboksApiError
        mock_api = mock_api_class.return_value
        mock_api.authenticate = AsyncMock(side_effect=EboksApiError("Connection error"))
        mock_api.device_id = "TEST-DEVICE-ID"

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "cpr": mock_config_entry_data["cpr"],
                "password": mock_config_entry_data["password"],
                "activation_code": mock_config_entry_data["activation_code"],
            },
        )

        assert result["type"] == FlowResultType.FORM
        assert result["errors"] == {"base": "cannot_connect"}


async def test_form_unknown_error(
    hass: HomeAssistant,
    mock_config_entry_data: dict[str, Any],
) -> None:
    """Test form when unknown error occurs."""
    with patch(
        "custom_components.eboks.config_flow.EboksApi"
    ) as mock_api_class:
        mock_api = mock_api_class.return_value
        mock_api.authenticate = AsyncMock(side_effect=Exception("Unknown error"))
        mock_api.device_id = "TEST-DEVICE-ID"

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "cpr": mock_config_entry_data["cpr"],
                "password": mock_config_entry_data["password"],
                "activation_code": mock_config_entry_data["activation_code"],
            },
        )

        assert result["type"] == FlowResultType.FORM
        assert result["errors"] == {"base": "unknown"}


async def test_form_already_configured(
    hass: HomeAssistant,
    mock_config_entry_data: dict[str, Any],
) -> None:
    """Test that we abort if already configured."""
    # Create a mock config entry first
    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="e-Boks (010190...)",
        data=mock_config_entry_data,
        source=config_entries.SOURCE_USER,
        unique_id=mock_config_entry_data["cpr"],
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.eboks.config_flow.EboksApi"
    ) as mock_api_class:
        mock_api = mock_api_class.return_value
        mock_api.authenticate = AsyncMock(return_value=True)
        mock_api.get_folders = AsyncMock(return_value=[])
        mock_api.device_id = "TEST-DEVICE-ID"

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "cpr": mock_config_entry_data["cpr"],
                "password": mock_config_entry_data["password"],
                "activation_code": mock_config_entry_data["activation_code"],
            },
        )

        assert result["type"] == FlowResultType.ABORT
        assert result["reason"] == "already_configured"
