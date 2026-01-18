"""MitID OAuth2 authentication for e-Boks.

This module handles the complete MitID authentication flow for accessing
Digital Post (Post fra det offentlige) via e-Boks.

The flow is:
1. User visits authorization URL and completes MitID login
2. Browser redirects to custom URI with authorization code
3. Code is exchanged at digitalpost.dk for access token
4. Token is exchanged at digitalpostproxy.e-boks.dk for usertoken
5. Usertoken is exchanged at oauth-dk.e-boks.com for e-Boks access token
6. e-Boks access token is used to access the Mobile JSON API
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_LOGGER = logging.getLogger(__name__)

# OAuth2 endpoints (verified working 2026-01-19)
DIGITALPOST_AUTH_URL = "https://gateway.digitalpost.dk/auth/oauth/authorize"
DIGITALPOST_TOKEN_URL = "https://digitalpost.dk/auth/oauth/token"
EBOKS_PROXY_URL = "https://digitalpostproxy.e-boks.dk/loginservice/v2/connect"
EBOKS_OAUTH_URL = "https://oauth-dk.e-boks.com/1/connect/token"
EBOKS_MOBILE_API = "https://mobile-api-dk.e-boks.com"

# OAuth2 client credentials for digitalpost.dk (step 1)
# These are the official e-Boks mobile app credentials
OAUTH_CLIENT_ID = "e-boks-mobile"
OAUTH_CLIENT_SECRET = "y0vKRKoVvqO%N3HBDK0T5bbzqo_eZsI0"
OAUTH_REDIRECT_URI = "eboksdk://ngdpoidc/callback"
OAUTH_SCOPE = "openid"

# Pre-computed Basic auth header for digitalpost.dk token endpoint
# Base64 of "e-boks-mobile:y0vKRKoVvqO%N3HBDK0T5bbzqo_eZsI0"
DIGITALPOST_BASIC_AUTH = "ZS1ib2tzLW1vYmlsZTp5MHZLUktvVnZxTyVOM0hCREswVDViYnpxb19lWnNJMA=="

# OAuth2 client credentials for oauth-dk.e-boks.com (step 3)
EBOKS_CLIENT_ID = "MobileApp-Short-Custom-id"
EBOKS_CLIENT_SECRET = "QmaENW6MeYwwjzF5"


@dataclass
class MitIDCredentials:
    """Credentials obtained from MitID authentication."""

    user_id: str
    name: str
    device_id: str
    access_token: str
    refresh_token: str | None = None
    private_key_pem: str = ""  # Not used for MitID, kept for backwards compatibility


def generate_rsa_keypair() -> tuple[str, str]:
    """Generate a new RSA keypair for device authentication.

    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')

    return private_pem, public_pem


def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge.

    Returns:
        Tuple of (code_verifier, code_challenge)
    """
    # Generate random 32-byte verifier
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    # Create SHA256 challenge
    challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge


def sign_challenge_rsa(private_key_pem: str, challenge: str) -> str:
    """Sign a challenge string with RSA private key.

    Args:
        private_key_pem: PEM-encoded private key
        challenge: Challenge string to sign

    Returns:
        Base64-encoded signature
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
    )

    signature = private_key.sign(
        challenge.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode('utf-8')


class MitIDAuthenticator:
    """Handle MitID OAuth2 authentication flow for e-Boks.

    Usage:
        1. Create authenticator instance
        2. Call get_authorization_url() to get the MitID login URL
        3. User opens URL in browser, completes MitID login
        4. Browser tries to redirect to eboksdk://... (fails)
        5. User copies the 'code' parameter from the URL
        6. Call complete_authentication(code) to exchange for tokens

    Example:
        auth = MitIDAuthenticator()
        url = auth.get_authorization_url()
        print(f"Open this URL: {url}")
        code = input("Enter the code from the callback URL: ")
        credentials = await auth.complete_authentication(code)
    """

    def __init__(self) -> None:
        """Initialize the authenticator."""
        self._device_id = str(uuid.uuid4()).upper()
        self._private_key_pem: str | None = None
        self._public_key_pem: str | None = None
        self._session: aiohttp.ClientSession | None = None

        # PKCE values
        self._state = secrets.token_urlsafe(32)
        self._nonce = secrets.token_urlsafe(16)
        self._code_verifier, self._code_challenge = generate_pkce_pair()

    @property
    def device_id(self) -> str:
        """Return the device ID."""
        return self._device_id

    @property
    def private_key_pem(self) -> str | None:
        """Return the private key PEM."""
        return self._private_key_pem

    def get_authorization_url(self) -> str:
        """Get the MitID authorization URL for user to visit.

        The user should open this URL in their browser, complete the MitID login,
        and then copy the authorization code from the callback URL.

        The callback URL will look like:
        eboksdk://ngdpoidc/callback?code=XXXXX&state=...&session_state=...

        The user needs to copy the 'code' parameter value.

        Returns:
            URL to redirect user to for MitID login
        """
        import urllib.parse

        params = {
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "response_type": "code",
            "scope": OAUTH_SCOPE,
            "state": self._state,
            "nonce": self._nonce,
            "code_challenge": self._code_challenge,
            "code_challenge_method": "S256",
            "idp": "nemloginEboksRealm",  # Required for MitID/NemLog-in
        }

        query = urllib.parse.urlencode(params)
        return f"{DIGITALPOST_AUTH_URL}?{query}"

    @property
    def code_verifier(self) -> str:
        """Return the code verifier for PKCE."""
        return self._code_verifier

    @property
    def state(self) -> str:
        """Return the state parameter for validation."""
        return self._state

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure we have an aiohttp session."""
        if self._session is None:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def exchange_code_for_tokens(self, authorization_code: str) -> dict[str, Any]:
        """Exchange OAuth authorization code for DigitalPost tokens (Step 1).

        Args:
            authorization_code: Code received from MitID callback

        Returns:
            Token response dict with access_token, refresh_token, etc.
        """
        session = await self._ensure_session()

        headers = {
            "Authorization": f"Basic {DIGITALPOST_BASIC_AUTH}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "code_verifier": self._code_verifier,
        }

        _LOGGER.debug("Exchanging authorization code at digitalpost.dk...")

        async with session.post(
            DIGITALPOST_TOKEN_URL,
            headers=headers,
            data=data,
        ) as response:
            if response.status != 200:
                error = await response.text()
                _LOGGER.error("Token exchange failed (status %d): %s", response.status, error)
                raise Exception(f"Token exchange failed: {error}")

            result = await response.json()
            _LOGGER.debug("Got DigitalPost access token (expires_in: %s)", result.get("expires_in"))
            return result

    async def get_user_token(self, bearer_token: str) -> dict[str, Any]:
        """Get e-Boks user token from DigitalPost proxy (Step 2).

        Args:
            bearer_token: Access token from DigitalPost OAuth

        Returns:
            User token response with userToken field
        """
        session = await self._ensure_session()

        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }

        _LOGGER.debug("Getting user token from digitalpostproxy.e-boks.dk...")

        async with session.get(
            f"{EBOKS_PROXY_URL}/usertoken",
            headers=headers,
        ) as response:
            if response.status != 200:
                error = await response.text()
                _LOGGER.error("User token request failed (status %d): %s", response.status, error)
                raise Exception(f"User token request failed: {error}")

            result = await response.json()
            _LOGGER.debug("Got e-Boks user token")
            return result

    async def get_eboks_access_token(self, user_token: str) -> dict[str, Any]:
        """Get e-Boks access token (Step 3).

        Exchanges the userToken from step 2 for an e-Boks access token
        that can be used with the Mobile JSON API.

        Args:
            user_token: User token from digitalpostproxy (JWT)

        Returns:
            e-Boks token response with access_token and refresh_token
        """
        session = await self._ensure_session()

        # Build Basic auth header from e-Boks client credentials
        eboks_credentials = base64.b64encode(
            f"{EBOKS_CLIENT_ID}:{EBOKS_CLIENT_SECRET}".encode()
        ).decode()

        headers = {
            "Authorization": f"Basic {eboks_credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": user_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "mobileapi offline_access",
        }

        _LOGGER.debug("Getting e-Boks access token from oauth-dk.e-boks.com...")

        async with session.post(
            EBOKS_OAUTH_URL,
            headers=headers,
            data=data,
        ) as response:
            if response.status != 200:
                error = await response.text()
                _LOGGER.error("e-Boks token request failed (status %d): %s", response.status, error)
                raise Exception(f"e-Boks token request failed: {error}")

            result = await response.json()
            _LOGGER.debug("Got e-Boks access token (expires_in: %s)", result.get("expires_in"))
            return result

    async def register_device(self, access_token: str) -> dict[str, Any]:
        """Register device with e-Boks using RSA public key.

        Args:
            access_token: e-Boks access token

        Returns:
            Device registration response
        """
        # Generate RSA keypair
        self._private_key_pem, self._public_key_pem = generate_rsa_keypair()

        session = await self._ensure_session()

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        # Extract public key without PEM headers for registration
        public_key_base64 = self._public_key_pem.replace(
            "-----BEGIN PUBLIC KEY-----", ""
        ).replace(
            "-----END PUBLIC KEY-----", ""
        ).replace("\n", "")

        data = {
            "deviceId": self._device_id,
            "deviceName": "Home Assistant e-Boks",
            "deviceOS": "Linux",
            "publicKey": public_key_base64,
        }

        async with session.put(
            f"{EBOKS_MOBILE_API}/1/device",
            headers=headers,
            json=data,
        ) as response:
            if response.status not in (200, 201):
                error = await response.text()
                _LOGGER.error("Device registration failed: %s", error)
                raise Exception(f"Device registration failed: {error}")

            return await response.json()

    async def get_user_profile(self, access_token: str) -> dict[str, Any]:
        """Get user profile from e-Boks.

        Args:
            access_token: e-Boks access token

        Returns:
            User profile
        """
        session = await self._ensure_session()

        headers = {
            "Authorization": f"Bearer {access_token}",
        }

        async with session.get(
            f"{EBOKS_MOBILE_API}/1/profile",
            headers=headers,
        ) as response:
            if response.status != 200:
                error = await response.text()
                _LOGGER.error("Profile request failed: %s", error)
                raise Exception(f"Profile request failed: {error}")

            return await response.json()

    async def refresh_eboks_token(self, refresh_token: str) -> dict[str, Any]:
        """Refresh e-Boks access token.

        Args:
            refresh_token: Refresh token from previous authentication

        Returns:
            New token response with access_token and refresh_token
        """
        session = await self._ensure_session()

        eboks_credentials = base64.b64encode(
            f"{EBOKS_CLIENT_ID}:{EBOKS_CLIENT_SECRET}".encode()
        ).decode()

        headers = {
            "Authorization": f"Basic {eboks_credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": "mobileapi offline_access",
        }

        _LOGGER.debug("Refreshing e-Boks access token...")

        async with session.post(
            EBOKS_OAUTH_URL,
            headers=headers,
            data=data,
        ) as response:
            if response.status != 200:
                error = await response.text()
                _LOGGER.error("Token refresh failed (status %d): %s", response.status, error)
                raise Exception(f"Token refresh failed: {error}")

            result = await response.json()
            _LOGGER.debug("Refreshed e-Boks access token (expires_in: %s)", result.get("expires_in"))
            return result

    async def complete_authentication(
        self, authorization_code: str
    ) -> MitIDCredentials:
        """Complete the full MitID authentication flow.

        This performs the 3-step token exchange:
        1. Exchange authorization code at digitalpost.dk
        2. Get userToken from digitalpostproxy.e-boks.dk
        3. Get e-Boks access token from oauth-dk.e-boks.com

        Args:
            authorization_code: Code received from MitID callback

        Returns:
            MitIDCredentials with all necessary authentication data
        """
        try:
            # Step 1: Exchange code for DigitalPost tokens
            _LOGGER.info("Step 1/4: Exchanging authorization code...")
            token_response = await self.exchange_code_for_tokens(authorization_code)
            bearer_token = token_response.get("access_token")

            if not bearer_token:
                raise Exception("No access_token in DigitalPost response")

            # Step 2: Get user token from e-Boks proxy
            _LOGGER.info("Step 2/4: Getting user token from e-Boks proxy...")
            user_token_response = await self.get_user_token(bearer_token)
            user_token = user_token_response.get("userToken")

            if not user_token:
                raise Exception("No userToken in proxy response")

            # Step 3: Get e-Boks access token
            _LOGGER.info("Step 3/4: Getting e-Boks access token...")
            eboks_token_response = await self.get_eboks_access_token(user_token)
            access_token = eboks_token_response.get("access_token")
            refresh_token = eboks_token_response.get("refresh_token")

            if not access_token:
                raise Exception("No access_token in e-Boks response")

            # Step 4: Get user profile
            _LOGGER.info("Step 4/4: Getting user profile...")
            profile = await self.get_user_profile(access_token)

            _LOGGER.info("MitID authentication completed successfully for: %s", profile.get("name", "Unknown"))

            return MitIDCredentials(
                user_id=str(profile.get("id", "")),
                name=profile.get("name", ""),
                private_key_pem="",  # Not used for MitID auth
                device_id=self._device_id,
                access_token=access_token,
                refresh_token=refresh_token,
            )

        except Exception as e:
            _LOGGER.error("MitID authentication failed: %s", e)
            raise
        finally:
            await self.close()
