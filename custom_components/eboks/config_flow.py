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
    AUTH_TYPE_ACTIVATION_CODE,
    AUTH_TYPE_MITID,
    CONF_ACTIVATION_CODE,
    CONF_AUTH_TYPE,
    CONF_CPR,
    CONF_DEVICE_ID,
    CONF_MESSAGE_COUNT,
    CONF_NOTIFY_SENDERS,
    CONF_PRIVATE_KEY,
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

# Schema for activation code authentication
STEP_ACTIVATION_CODE_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CPR): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_ACTIVATION_CODE): str,
    }
)

# Schema for MitID authentication - step 1: credentials
STEP_MITID_CREDENTIALS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CPR): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

# Schema for MitID authentication - step 2: authorization code
STEP_MITID_AUTH_CODE_SCHEMA = vol.Schema(
    {
        vol.Required("authorization_code"): str,
    }
)


async def validate_activation_code_input(
    hass: HomeAssistant, data: dict[str, Any]
) -> dict[str, Any]:
    """Validate activation code authentication."""
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

    return {
        "title": f"e-Boks ({data[CONF_CPR][:6]}...)",
        "device_id": api.device_id,
    }


async def validate_mitid_input(
    hass: HomeAssistant, data: dict[str, Any]
) -> dict[str, Any]:
    """Validate MitID RSA authentication."""
    session = async_get_clientsession(hass)

    api = EboksApi(
        cpr=data[CONF_CPR],
        password=data[CONF_PASSWORD],
        device_id=data.get(CONF_DEVICE_ID),
        private_key_pem=data[CONF_PRIVATE_KEY],
        session=session,
    )

    try:
        await api.authenticate()
        # Test that we can get folders
        folders = await api.get_folders()
        _LOGGER.info("MitID auth successful, got %d folders", len(folders))
    except EboksAuthError as err:
        raise InvalidAuth from err
    except EboksApiError as err:
        raise CannotConnect from err

    return {
        "title": f"e-Boks MitID ({data[CONF_CPR][:6]}...)",
        "device_id": api.device_id,
    }


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for e-Boks."""

    VERSION = 2  # Bumped for MitID support

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._data: dict[str, Any] = {}
        self._mitid_authenticator = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step - choose authentication method."""
        if user_input is not None:
            auth_type = user_input.get("auth_type", AUTH_TYPE_ACTIVATION_CODE)
            if auth_type == AUTH_TYPE_MITID:
                return await self.async_step_mitid_credentials()
            else:
                return await self.async_step_activation_code()

        return self.async_show_menu(
            step_id="user",
            menu_options={
                "activation_code": "Aktiverings­kode (kun Virksomheder)",
                "mitid_credentials": "MitID (fuld adgang inkl. Digital Post)",
            },
            description_placeholders={
                "activation_info": "Vælg autentificeringsmetode",
            },
        )

    async def async_step_activation_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle activation code authentication."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await validate_activation_code_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                # Store data
                user_input[CONF_DEVICE_ID] = info["device_id"]
                user_input[CONF_AUTH_TYPE] = AUTH_TYPE_ACTIVATION_CODE

                # Check if already configured
                await self.async_set_unique_id(user_input[CONF_CPR])
                self._abort_if_unique_id_configured()

                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="activation_code",
            data_schema=STEP_ACTIVATION_CODE_SCHEMA,
            errors=errors,
            description_placeholders={
                "activation_info": "Find aktiverings­kode i e-Boks app: Menu → Mobiladgang"
            },
        )

    async def async_step_mitid_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle MitID credentials input."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._data = user_input

            # Create MitID authenticator and get auth URL
            try:
                from .mitid_auth import MitIDAuthenticator

                self._mitid_authenticator = MitIDAuthenticator(
                    cpr=user_input[CONF_CPR],
                    password=user_input[CONF_PASSWORD],
                )

                # Store device_id for later
                self._data[CONF_DEVICE_ID] = self._mitid_authenticator.device_id

                return await self.async_step_mitid_authorize()

            except Exception as err:
                _LOGGER.exception("Failed to initialize MitID authenticator: %s", err)
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="mitid_credentials",
            data_schema=STEP_MITID_CREDENTIALS_SCHEMA,
            errors=errors,
            description_placeholders={
                "info": "Indtast dit CPR-nummer og din e-Boks mobil­adgangskode"
            },
        )

    async def async_step_mitid_authorize(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle MitID authorization step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            authorization_code = user_input.get("authorization_code", "").strip()

            # Extract code from URL if user pasted the full redirect URL
            # URL format: dk.e-boks.app://oauth?code=XXXXX&state=XXXXX
            if "code=" in authorization_code:
                import urllib.parse
                try:
                    # Handle both URL formats
                    if "://" in authorization_code:
                        parsed = urllib.parse.urlparse(authorization_code)
                        params = urllib.parse.parse_qs(parsed.query)
                    else:
                        # Just query string
                        params = urllib.parse.parse_qs(authorization_code)
                    if "code" in params:
                        authorization_code = params["code"][0]
                        _LOGGER.info("Extracted authorization code from URL")
                except Exception as e:
                    _LOGGER.warning("Failed to parse URL, using as-is: %s", e)

            try:
                # Complete the MitID authentication
                credentials = await self._mitid_authenticator.complete_authentication(
                    authorization_code
                )

                # Store credentials
                self._data[CONF_PRIVATE_KEY] = credentials.private_key_pem
                self._data[CONF_DEVICE_ID] = credentials.device_id
                self._data[CONF_AUTH_TYPE] = AUTH_TYPE_MITID

                # Validate that we can connect
                info = await validate_mitid_input(self.hass, self._data)

                # Check if already configured
                await self.async_set_unique_id(self._data[CONF_CPR])
                self._abort_if_unique_id_configured()

                return self.async_create_entry(title=info["title"], data=self._data)

            except Exception as err:
                _LOGGER.exception("MitID authentication failed: %s", err)
                errors["base"] = "mitid_auth_failed"

        # Get the authorization URL
        auth_url = self._mitid_authenticator.get_authorization_url()

        return self.async_show_form(
            step_id="mitid_authorize",
            data_schema=STEP_MITID_AUTH_CODE_SCHEMA,
            errors=errors,
            description_placeholders={
                "auth_url": auth_url,
                "instructions": (
                    "1. Åbn linket nedenfor i en browser\n"
                    "2. Log ind med MitID\n"
                    "3. Kopier autoriserings­koden fra URL'en efter redirect\n"
                    "4. Indsæt koden nedenfor"
                ),
            },
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Handle reauthorization."""
        self._data = dict(entry_data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reauthorization confirmation."""
        errors: dict[str, str] = {}

        if user_input is not None:
            entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
            if entry:
                auth_type = entry.data.get(CONF_AUTH_TYPE, AUTH_TYPE_ACTIVATION_CODE)

                if auth_type == AUTH_TYPE_ACTIVATION_CODE:
                    data = {**entry.data, **user_input}
                    try:
                        await validate_activation_code_input(self.hass, data)
                    except CannotConnect:
                        errors["base"] = "cannot_connect"
                    except InvalidAuth:
                        errors["base"] = "invalid_auth"
                    except Exception:
                        _LOGGER.exception("Unexpected exception")
                        errors["base"] = "unknown"
                    else:
                        self.hass.config_entries.async_update_entry(entry, data=data)
                        await self.hass.config_entries.async_reload(entry.entry_id)
                        return self.async_abort(reason="reauth_successful")
                else:
                    # MitID reauth - need to redo the flow
                    return await self.async_step_mitid_credentials()

        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        auth_type = entry.data.get(CONF_AUTH_TYPE, AUTH_TYPE_ACTIVATION_CODE) if entry else AUTH_TYPE_ACTIVATION_CODE

        if auth_type == AUTH_TYPE_ACTIVATION_CODE:
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
        else:
            return await self.async_step_mitid_credentials()

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reconfiguration."""
        errors: dict[str, str] = {}
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])

        if user_input is not None and entry:
            data = {**entry.data, **user_input}
            try:
                auth_type = data.get(CONF_AUTH_TYPE, AUTH_TYPE_ACTIVATION_CODE)
                if auth_type == AUTH_TYPE_ACTIVATION_CODE:
                    info = await validate_activation_code_input(self.hass, data)
                else:
                    info = await validate_mitid_input(self.hass, data)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                data[CONF_DEVICE_ID] = info["device_id"]
                self.hass.config_entries.async_update_entry(entry, data=data)
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reconfigure_successful")

        auth_type = entry.data.get(CONF_AUTH_TYPE, AUTH_TYPE_ACTIVATION_CODE) if entry else AUTH_TYPE_ACTIVATION_CODE

        if auth_type == AUTH_TYPE_ACTIVATION_CODE:
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
        else:
            # For MitID, redirect to new credentials flow
            return await self.async_step_mitid_credentials()

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
            # Parse notify_senders from comma-separated string
            notify_senders_str = user_input.get(CONF_NOTIFY_SENDERS, "")
            if notify_senders_str:
                user_input[CONF_NOTIFY_SENDERS] = [
                    s.strip() for s in notify_senders_str.split(",") if s.strip()
                ]
            else:
                user_input[CONF_NOTIFY_SENDERS] = []

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

        # Show auth type info
        auth_type = self.config_entry.data.get(CONF_AUTH_TYPE, AUTH_TYPE_ACTIVATION_CODE)
        auth_type_display = "MitID (fuld adgang)" if auth_type == AUTH_TYPE_MITID else "Aktiverings­kode"

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
                "auth_type": auth_type_display,
            },
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""


class MitIDAuthFailed(HomeAssistantError):
    """Error to indicate MitID authentication failed."""
