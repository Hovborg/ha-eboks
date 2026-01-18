"""Config flow for e-Boks integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import EboksApi, EboksApiError, EboksAuthError
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
    MAX_MESSAGE_COUNT,
    MAX_SCAN_INTERVAL,
    MIN_MESSAGE_COUNT,
    MIN_SCAN_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CPR): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_ACTIVATION_CODE): str,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect."""
    session = async_get_clientsession(hass)

    api = EboksApi(
        cpr=data[CONF_CPR],
        password=data[CONF_PASSWORD],
        activation_code=data[CONF_ACTIVATION_CODE],
        session=session,
    )

    try:
        await api.authenticate()
        # Test that we can get folders
        await api.get_folders()
    except EboksAuthError as err:
        raise InvalidAuth from err
    except EboksApiError as err:
        raise CannotConnect from err

    # Return info to store in config entry
    return {
        "title": f"e-Boks ({data[CONF_CPR][:6]}...)",
        "device_id": api.device_id,
    }


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for e-Boks."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                # Store device_id in the data
                user_input[CONF_DEVICE_ID] = info["device_id"]

                # Check if already configured
                await self.async_set_unique_id(user_input[CONF_CPR])
                self._abort_if_unique_id_configured()

                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
            description_placeholders={
                "activation_info": "Find activation code in e-Boks app under Menu → Mobiladgang"
            },
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Handle reauthorization."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reauthorization confirmation."""
        errors: dict[str, str] = {}

        if user_input is not None:
            entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
            if entry:
                data = {**entry.data, **user_input}
                try:
                    await validate_input(self.hass, data)
                except CannotConnect:
                    errors["base"] = "cannot_connect"
                except InvalidAuth:
                    errors["base"] = "invalid_auth"
                except Exception:  # pylint: disable=broad-except
                    _LOGGER.exception("Unexpected exception")
                    errors["base"] = "unknown"
                else:
                    self.hass.config_entries.async_update_entry(entry, data=data)
                    await self.hass.config_entries.async_reload(entry.entry_id)
                    return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(CONF_ACTIVATION_CODE): str,
                }
            ),
            errors=errors,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reconfiguration."""
        errors: dict[str, str] = {}
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])

        if user_input is not None and entry:
            data = {**entry.data, **user_input}
            try:
                info = await validate_input(self.hass, data)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                data[CONF_DEVICE_ID] = info["device_id"]
                self.hass.config_entries.async_update_entry(entry, data=data)
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reconfigure_successful")

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_CPR, default=entry.data.get(CONF_CPR) if entry else ""): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(CONF_ACTIVATION_CODE): str,
                }
            ),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for e-Boks."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        # Get current options or defaults
        current_scan_interval = self.config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )
        current_message_count = self.config_entry.options.get(
            CONF_MESSAGE_COUNT, DEFAULT_MESSAGE_COUNT
        )
        current_notify_senders = self.config_entry.options.get(
            CONF_NOTIFY_SENDERS, DEFAULT_NOTIFY_SENDERS
        )

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SCAN_INTERVAL,
                        default=current_scan_interval,
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL),
                    ),
                    vol.Required(
                        CONF_MESSAGE_COUNT,
                        default=current_message_count,
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(min=MIN_MESSAGE_COUNT, max=MAX_MESSAGE_COUNT),
                    ),
                    vol.Optional(
                        CONF_NOTIFY_SENDERS,
                        default=",".join(current_notify_senders) if current_notify_senders else "",
                    ): str,
                }
            ),
            description_placeholders={
                "min_scan": str(MIN_SCAN_INTERVAL),
                "max_scan": str(MAX_SCAN_INTERVAL),
                "min_msg": str(MIN_MESSAGE_COUNT),
                "max_msg": str(MAX_MESSAGE_COUNT),
            },
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
