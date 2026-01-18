"""MitID OAuth2 authentication for e-Boks."""
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

# OAuth2 endpoints
DIGITALPOST_AUTH_URL = "https://gateway.digitalpost.dk/auth/oauth/authorize"
DIGITALPOST_TOKEN_URL = "https://digitalpost.dk/auth/oauth/token"
EBOKS_PROXY_URL = "https://digitalpostproxy.e-boks.dk/loginservice"
EBOKS_OAUTH_URL = "https://oauth-dk.e-boks.com/1/connect/token"
EBOKS_MOBILE_API = "https://mobile-api-dk.e-boks.com"

# OAuth2 client credentials (from Net-Eboks)
OAUTH_CLIENT_ID = "e-boks-app"
OAUTH_CLIENT_SECRET = "digitalpost"  # Base64 encoded in actual request
OAUTH_REDIRECT_URI = "dk.e-boks.app://oauth"
OAUTH_SCOPE = "openid"


@dataclass
class MitIDCredentials:
    """Credentials obtained from MitID authentication."""

    user_id: str
    name: str
    private_key_pem: str
    device_id: str
    access_token: str | None = None


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
    """Handle MitID OAuth2 authentication flow for e-Boks."""

    def __init__(self, cpr: str, password: str) -> None:
        """Initialize the authenticator.

        Args:
            cpr: CPR number (without dash)
            password: e-Boks mobile password
        """
        self._cpr = cpr.replace("-", "")
        self._password = password
        self._device_id = str(uuid.uuid4()).upper()
        self._private_key_pem: str | None = None
        self._public_key_pem: str | None = None
        self._session: aiohttp.ClientSession | None = None

        # PKCE values
        self._state = secrets.token_urlsafe(16)
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

        Returns:
            URL to redirect user to for MitID login
        """
        params = {
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "response_type": "code",
            "scope": OAUTH_SCOPE,
            "state": self._state,
            "nonce": self._nonce,
            "code_challenge": self._code_challenge,
            "code_challenge_method": "S256",
            "login_hint": f"cpr:{self._cpr}",
        }

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{DIGITALPOST_AUTH_URL}?{query}"

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
        """Exchange OAuth authorization code for tokens.

        Args:
            authorization_code: Code received from MitID callback

        Returns:
            Token response dict
        """
        session = await self._ensure_session()

        # Base64 encode client credentials
        credentials = base64.b64encode(
            f"{OAUTH_CLIENT_ID}:{OAUTH_CLIENT_SECRET}".encode()
        ).decode()

        headers = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "code_verifier": self._code_verifier,
        }

        async with session.post(
            DIGITALPOST_TOKEN_URL,
            headers=headers,
            data=data,
        ) as response:
            if response.status != 200:
                error = await response.text()
                _LOGGER.error("Token exchange failed: %s", error)
                raise Exception(f"Token exchange failed: {error}")

            return await response.json()

    async def get_user_token(self, bearer_token: str) -> dict[str, Any]:
        """Get user token from e-Boks proxy.

        Args:
            bearer_token: Bearer token from OAuth

        Returns:
            User token response
        """
        session = await self._ensure_session()

        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }

        async with session.get(
            f"{EBOKS_PROXY_URL}/token",
            headers=headers,
        ) as response:
            if response.status != 200:
                error = await response.text()
                _LOGGER.error("User token request failed: %s", error)
                raise Exception(f"User token request failed: {error}")

            return await response.json()

    async def verify_password(self, user_token: str) -> bool:
        """Verify e-Boks password.

        Args:
            user_token: User token from proxy

        Returns:
            True if password is valid
        """
        session = await self._ensure_session()

        headers = {
            "Authorization": f"Bearer {user_token}",
            "Content-Type": "application/json",
        }

        data = {
            "password": self._password,
        }

        async with session.post(
            f"{EBOKS_PROXY_URL}/verify",
            headers=headers,
            json=data,
        ) as response:
            return response.status == 200

    async def get_eboks_access_token(self, user_token: str) -> dict[str, Any]:
        """Get e-Boks access token.

        Args:
            user_token: User token from proxy

        Returns:
            e-Boks token response
        """
        session = await self._ensure_session()

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": user_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }

        async with session.post(
            EBOKS_OAUTH_URL,
            headers=headers,
            data=data,
        ) as response:
            if response.status != 200:
                error = await response.text()
                _LOGGER.error("e-Boks token request failed: %s", error)
                raise Exception(f"e-Boks token request failed: {error}")

            return await response.json()

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

    async def complete_authentication(
        self, authorization_code: str
    ) -> MitIDCredentials:
        """Complete the full MitID authentication flow.

        Args:
            authorization_code: Code received from MitID callback

        Returns:
            MitIDCredentials with all necessary authentication data
        """
        try:
            # Step 1: Exchange code for tokens
            _LOGGER.info("Exchanging authorization code for tokens...")
            token_response = await self.exchange_code_for_tokens(authorization_code)
            bearer_token = token_response.get("access_token")

            # Step 2: Get user token from e-Boks proxy
            _LOGGER.info("Getting user token...")
            user_token_response = await self.get_user_token(bearer_token)
            user_token = user_token_response.get("token")

            # Step 3: Verify password
            _LOGGER.info("Verifying password...")
            if not await self.verify_password(user_token):
                raise Exception("Password verification failed")

            # Step 4: Get e-Boks access token
            _LOGGER.info("Getting e-Boks access token...")
            eboks_token_response = await self.get_eboks_access_token(user_token)
            access_token = eboks_token_response.get("access_token")

            # Step 5: Get user profile
            _LOGGER.info("Getting user profile...")
            profile = await self.get_user_profile(access_token)

            # Step 6: Register device with RSA key
            _LOGGER.info("Registering device...")
            await self.register_device(access_token)

            return MitIDCredentials(
                user_id=profile.get("userId", ""),
                name=profile.get("name", ""),
                private_key_pem=self._private_key_pem,
                device_id=self._device_id,
                access_token=access_token,
            )

        finally:
            await self.close()
