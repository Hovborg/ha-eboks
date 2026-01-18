"""Tests for e-Boks API client."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
from aioresponses import aioresponses

from custom_components.eboks.api import EboksApi, EboksApiError, EboksAuthError
from custom_components.eboks.const import API_BASE_URL


# Sample XML responses
AUTH_RESPONSE_XML = """<?xml version="1.0" encoding="utf-8"?>
<Session xmlns="urn:eboks:mobile:1.0.0">
    <User userId="12345678" name="Test User" />
</Session>"""

FOLDERS_RESPONSE_XML = """<?xml version="1.0" encoding="utf-8"?>
<FolderInfoList xmlns="urn:eboks:mobile:1.0.0">
    <FolderInfo id="0" name="Indbakke" unread="2" />
    <FolderInfo id="1" name="Arkiv" unread="0" />
</FolderInfoList>"""

MESSAGES_RESPONSE_XML = """<?xml version="1.0" encoding="utf-8"?>
<MessageInfoList xmlns="urn:eboks:mobile:1.0.0">
    <MessageInfo id="msg-001" name="Test besked" folderId="0"
                 receivedDateTime="2026-01-15T10:30:00" unread="true"
                 format="pdf" attachmentsCount="1" size="125000">
        <Sender>Skattestyrelsen</Sender>
    </MessageInfo>
    <MessageInfo id="msg-002" name="Anden besked" folderId="0"
                 receivedDateTime="2026-01-14T14:20:00" unread="false"
                 format="pdf" attachmentsCount="0" size="45000">
        <Sender>Kommune</Sender>
    </MessageInfo>
</MessageInfoList>"""


@pytest.fixture
def api() -> EboksApi:
    """Create an API instance for testing."""
    return EboksApi(
        cpr="0101901234",
        password="1234",
        activation_code="Abc12345",
    )


class TestEboksApiAuthentication:
    """Tests for e-Boks API authentication."""

    async def test_authenticate_success(self, api: EboksApi) -> None:
        """Test successful authentication."""
        with aioresponses() as mocked:
            mocked.put(
                f"{API_BASE_URL}/session",
                status=200,
                body=AUTH_RESPONSE_XML,
                headers={
                    "X-EBOKS-AUTHENTICATE": 'sessionid="sess123",nonce="nonce456"'
                },
            )

            result = await api.authenticate()

            assert result is True
            assert api._session_id == "sess123"
            assert api._nonce == "nonce456"
            assert api._user_id == "12345678"

        await api.close()

    async def test_authenticate_invalid_credentials(self, api: EboksApi) -> None:
        """Test authentication with invalid credentials."""
        with aioresponses() as mocked:
            mocked.put(
                f"{API_BASE_URL}/session",
                status=401,
                body="Unauthorized",
            )

            with pytest.raises(EboksAuthError) as exc_info:
                await api.authenticate()

            assert exc_info.value.status_code == 401

        await api.close()

    async def test_authenticate_connection_error(self, api: EboksApi) -> None:
        """Test authentication when connection fails."""
        with aioresponses() as mocked:
            mocked.put(
                f"{API_BASE_URL}/session",
                exception=aiohttp.ClientError("Connection failed"),
            )

            with pytest.raises(EboksApiError) as exc_info:
                await api.authenticate()

            assert "Connection error" in str(exc_info.value)

        await api.close()

    async def test_authenticate_missing_activation_code(self) -> None:
        """Test authentication without activation code."""
        api = EboksApi(
            cpr="0101901234",
            password="1234",
            activation_code=None,
        )

        with pytest.raises(EboksAuthError) as exc_info:
            await api.authenticate()

        assert "Activation code is required" in str(exc_info.value)

        await api.close()


class TestEboksApiFolders:
    """Tests for e-Boks API folder operations."""

    async def test_get_folders_success(self, api: EboksApi) -> None:
        """Test getting folders successfully."""
        with aioresponses() as mocked:
            # Mock authentication
            mocked.put(
                f"{API_BASE_URL}/session",
                status=200,
                body=AUTH_RESPONSE_XML,
                headers={
                    "X-EBOKS-AUTHENTICATE": 'sessionid="sess123",nonce="nonce456"'
                },
            )
            # Mock get folders
            mocked.get(
                f"{API_BASE_URL}/12345678/0/mail/folders",
                status=200,
                body=FOLDERS_RESPONSE_XML,
                headers={
                    "X-EBOKS-AUTHENTICATE": 'nonce="nonce789"'
                },
            )

            folders = await api.get_folders()

            assert len(folders) == 2
            assert folders[0]["id"] == "0"
            assert folders[0]["name"] == "Indbakke"
            assert folders[0]["unread"] == 2
            assert folders[1]["id"] == "1"
            assert folders[1]["name"] == "Arkiv"
            assert folders[1]["unread"] == 0

        await api.close()

    async def test_get_folders_updates_nonce(self, api: EboksApi) -> None:
        """Test that getting folders updates the nonce."""
        with aioresponses() as mocked:
            mocked.put(
                f"{API_BASE_URL}/session",
                status=200,
                body=AUTH_RESPONSE_XML,
                headers={
                    "X-EBOKS-AUTHENTICATE": 'sessionid="sess123",nonce="nonce456"'
                },
            )
            mocked.get(
                f"{API_BASE_URL}/12345678/0/mail/folders",
                status=200,
                body=FOLDERS_RESPONSE_XML,
                headers={
                    "X-EBOKS-AUTHENTICATE": 'nonce="updated_nonce"'
                },
            )

            await api.get_folders()

            assert api._nonce == "updated_nonce"

        await api.close()


class TestEboksApiMessages:
    """Tests for e-Boks API message operations."""

    async def test_get_messages_success(self, api: EboksApi) -> None:
        """Test getting messages successfully."""
        with aioresponses() as mocked:
            mocked.put(
                f"{API_BASE_URL}/session",
                status=200,
                body=AUTH_RESPONSE_XML,
                headers={
                    "X-EBOKS-AUTHENTICATE": 'sessionid="sess123",nonce="nonce456"'
                },
            )
            mocked.get(
                f"{API_BASE_URL}/12345678/0/mail/folder/0?skip=0&take=100",
                status=200,
                body=MESSAGES_RESPONSE_XML,
                headers={
                    "X-EBOKS-AUTHENTICATE": 'nonce="nonce789"'
                },
            )

            messages = await api.get_messages("0")

            assert len(messages) == 2
            assert messages[0]["id"] == "msg-001"
            assert messages[0]["subject"] == "Test besked"
            assert messages[0]["sender"] == "Skattestyrelsen"
            assert messages[0]["unread"] is True
            assert messages[0]["attachments_count"] == 1
            assert messages[0]["size"] == 125000

        await api.close()

    async def test_get_unread_count(self, api: EboksApi) -> None:
        """Test getting unread count."""
        with aioresponses() as mocked:
            mocked.put(
                f"{API_BASE_URL}/session",
                status=200,
                body=AUTH_RESPONSE_XML,
                headers={
                    "X-EBOKS-AUTHENTICATE": 'sessionid="sess123",nonce="nonce456"'
                },
            )
            mocked.get(
                f"{API_BASE_URL}/12345678/0/mail/folders",
                status=200,
                body=FOLDERS_RESPONSE_XML,
                headers={
                    "X-EBOKS-AUTHENTICATE": 'nonce="nonce789"'
                },
            )

            unread = await api.get_unread_count()

            assert unread == 2  # 2 from Indbakke + 0 from Arkiv

        await api.close()


class TestEboksApiChallengeComputation:
    """Tests for e-Boks API challenge computation."""

    def test_compute_challenge(self, api: EboksApi) -> None:
        """Test challenge hash computation."""
        # The challenge should be a double SHA256 hash
        datetime_str = "2026-01-18 12:00:00Z"
        challenge = api._compute_challenge(datetime_str)

        # Should be a 64 character hex string (SHA256)
        assert len(challenge) == 64
        assert all(c in "0123456789abcdef" for c in challenge)

    def test_compute_response(self, api: EboksApi) -> None:
        """Test response hash computation."""
        api._nonce = "test_nonce"
        response = api._compute_response("test_challenge")

        # Should be a 64 character hex string (SHA256)
        assert len(response) == 64
        assert all(c in "0123456789abcdef" for c in response)


class TestEboksApiDeviceId:
    """Tests for e-Boks API device ID handling."""

    def test_device_id_generated_if_not_provided(self) -> None:
        """Test that device ID is generated if not provided."""
        api = EboksApi(
            cpr="0101901234",
            password="1234",
            activation_code="Abc12345",
        )

        assert api.device_id is not None
        assert len(api.device_id) == 36  # UUID format

    def test_device_id_preserved_if_provided(self) -> None:
        """Test that device ID is preserved if provided."""
        api = EboksApi(
            cpr="0101901234",
            password="1234",
            device_id="MY-CUSTOM-DEVICE-ID",
            activation_code="Abc12345",
        )

        assert api.device_id == "MY-CUSTOM-DEVICE-ID"

    def test_cpr_strips_dashes(self) -> None:
        """Test that CPR number strips dashes."""
        api = EboksApi(
            cpr="010190-1234",
            password="1234",
            activation_code="Abc12345",
        )

        assert api._cpr == "0101901234"
