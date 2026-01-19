#!/usr/bin/env python3
"""
e-Boks Token Generator for Home Assistant

This script helps you generate a refresh token for the e-Boks Home Assistant integration.
It handles the complete MitID OAuth flow with automatic code capture.

Usage:
    python3 get_eboks_token.py [--manual]

Options:
    --manual    Skip browser automation and enter code manually

Requirements:
    pip install aiohttp playwright
    playwright install chromium

The script will:
1. Open a browser window with the MitID login page
2. Wait for you to complete MitID authentication
3. Automatically capture the authorization code
4. Exchange it for an e-Boks refresh token
"""

import argparse
import asyncio
import base64
import hashlib
import re
import secrets
import sys
import urllib.parse
import uuid

try:
    import aiohttp
except ImportError:
    print("Error: aiohttp not installed. Run: pip install aiohttp")
    sys.exit(1)

# OAuth2 endpoints
DIGITALPOST_AUTH_URL = "https://gateway.digitalpost.dk/auth/oauth/authorize"
DIGITALPOST_TOKEN_URL = "https://digitalpost.dk/auth/oauth/token"
EBOKS_PROXY_URL = "https://digitalpostproxy.e-boks.dk/loginservice/v2/connect"
EBOKS_OAUTH_URL = "https://oauth-dk.e-boks.com/1/connect/token"

# OAuth2 credentials (official e-Boks mobile app)
OAUTH_CLIENT_ID = "e-boks-mobile"
OAUTH_CLIENT_SECRET = "y0vKRKoVvqO%N3HBDK0T5bbzqo_eZsI0"
OAUTH_REDIRECT_URI = "eboksdk://ngdpoidc/callback"
DIGITALPOST_BASIC_AUTH = "ZS1ib2tzLW1vYmlsZTp5MHZLUktvVnZxTyVOM0hCREswVDViYnpxb19lWnNJMA=="

EBOKS_CLIENT_ID = "MobileApp-Short-Custom-id"
EBOKS_CLIENT_SECRET = "QmaENW6MeYwwjzF5"


def generate_pkce():
    """Generate PKCE code verifier and challenge."""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
    challenge = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(challenge).decode().rstrip('=')
    return code_verifier, code_challenge


def build_auth_url(code_challenge: str, device_id: str, state: str, nonce: str) -> str:
    """Build the MitID authorization URL."""
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "idp": "nemloginEboksRealm",
        "deviceName": "HomeAssistant",
        "deviceId": device_id,
    }
    return f"{DIGITALPOST_AUTH_URL}?{urllib.parse.urlencode(params)}"


def extract_code_from_url(url: str) -> str | None:
    """Extract authorization code from callback URL."""
    if "code=" in url:
        # Parse the code parameter
        match = re.search(r'[?&]code=([^&]+)', url)
        if match:
            return match.group(1)
    return None


async def get_code_with_playwright(auth_url: str) -> str | None:
    """Open browser and automatically capture authorization code."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print()
        print("=" * 60)
        print("Playwright not installed!")
        print("=" * 60)
        print()
        print("To enable automatic code capture, install Playwright:")
        print()
        print("  pip install playwright")
        print("  playwright install chromium")
        print()
        print("Or use --manual flag to enter the code manually.")
        print()
        return None

    print()
    print("Opening browser for MitID login...")
    print("(Complete the login - the code will be captured automatically)")
    print()

    async with async_playwright() as p:
        # Launch browser (visible to user)
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()

        captured_code = None

        # Listen for navigation to catch the callback
        async def handle_request(request):
            nonlocal captured_code
            url = request.url
            if url.startswith("eboksdk://") and "code=" in url:
                captured_code = extract_code_from_url(url)
                print(f"  ✓ Captured authorization code!")

        page.on("request", handle_request)

        # Also monitor URL changes (backup method)
        async def check_url():
            nonlocal captured_code
            while captured_code is None:
                try:
                    current_url = page.url
                    if current_url.startswith("eboksdk://") or "code=" in current_url:
                        code = extract_code_from_url(current_url)
                        if code:
                            captured_code = code
                            print(f"  ✓ Captured authorization code from URL!")
                            break
                except Exception:
                    pass
                await asyncio.sleep(0.5)

        # Navigate to auth URL
        try:
            await page.goto(auth_url, wait_until="domcontentloaded")
        except Exception:
            # Expected - the eboksdk:// redirect will fail
            pass

        # Start URL monitoring
        url_check_task = asyncio.create_task(check_url())

        # Wait for code capture (timeout after 5 minutes)
        timeout = 300  # 5 minutes
        elapsed = 0
        while captured_code is None and elapsed < timeout:
            await asyncio.sleep(1)
            elapsed += 1

            # Check if browser was closed
            try:
                if page.is_closed():
                    break
            except Exception:
                break

            # Also check page URL directly
            try:
                current_url = page.url
                if "eboksdk://" in current_url or (
                    "code=" in current_url and "digitalpost" not in current_url
                ):
                    code = extract_code_from_url(current_url)
                    if code:
                        captured_code = code
                        print(f"  ✓ Captured authorization code!")
                        break
            except Exception:
                pass

        url_check_task.cancel()

        # Close browser
        await browser.close()

        if captured_code:
            return captured_code
        else:
            print("Timeout or browser closed without completing login.")
            return None


async def exchange_tokens(authorization_code: str, code_verifier: str) -> dict:
    """Exchange authorization code for e-Boks tokens."""
    async with aiohttp.ClientSession() as session:
        # Step 1: Exchange code at digitalpost.dk
        print("Step 1/3: Exchanging authorization code...")
        headers = {
            "Authorization": f"Basic {DIGITALPOST_BASIC_AUTH}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "code_verifier": code_verifier,
        }

        async with session.post(DIGITALPOST_TOKEN_URL, headers=headers, data=data) as resp:
            if resp.status != 200:
                error = await resp.text()
                raise Exception(f"Token exchange failed: {error}")
            dp_token = await resp.json()
            bearer_token = dp_token["access_token"]
            print("  ✓ Got DigitalPost token")

        # Step 2: Get userToken from proxy
        print("Step 2/3: Getting user token...")
        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }

        async with session.post(f"{EBOKS_PROXY_URL}/usertoken", headers=headers) as resp:
            if resp.status != 200:
                error = await resp.text()
                raise Exception(f"User token request failed: {error}")
            user_token = (await resp.json()).get("userToken")
            print("  ✓ Got user token")

        # Step 3: Get e-Boks access token
        print("Step 3/3: Getting e-Boks tokens...")
        eboks_creds = base64.b64encode(f"{EBOKS_CLIENT_ID}:{EBOKS_CLIENT_SECRET}".encode()).decode()
        headers = {
            "Authorization": f"Basic {eboks_creds}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "grant_type": "usertoken",
            "usertoken": user_token,
            "scope": "mobileapi offline_access",
        }

        async with session.post(EBOKS_OAUTH_URL, headers=headers, data=data) as resp:
            if resp.status != 200:
                error = await resp.text()
                raise Exception(f"e-Boks token request failed: {error}")
            result = await resp.json()
            print("  ✓ Got e-Boks tokens")
            return result


def manual_flow(auth_url: str) -> str | None:
    """Manual flow where user copies the code."""
    print()
    print("1. Open this URL in your browser:")
    print()
    print(auth_url)
    print()
    print("2. Log in with MitID")
    print()
    print("3. When the browser shows 'cannot open eboksdk://...'")
    print("   copy the ENTIRE URL from the address bar")
    print()

    user_input = input("4. Paste the URL or just the code here: ").strip()

    if not user_input:
        print("Error: No input provided")
        return None

    # Check if it's a full URL or just the code
    if "code=" in user_input:
        return extract_code_from_url(user_input)
    else:
        # Assume it's just the code
        return user_input


async def main():
    parser = argparse.ArgumentParser(description="Generate e-Boks refresh token for Home Assistant")
    parser.add_argument("--manual", action="store_true", help="Skip browser automation")
    args = parser.parse_args()

    print("=" * 60)
    print("e-Boks Token Generator for Home Assistant")
    print("=" * 60)

    # Generate PKCE
    code_verifier, code_challenge = generate_pkce()
    device_id = str(uuid.uuid4()).upper()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)

    # Build auth URL
    auth_url = build_auth_url(code_challenge, device_id, state, nonce)

    # Get authorization code
    authorization_code = None

    if args.manual:
        authorization_code = manual_flow(auth_url)
    else:
        # Try automatic first
        authorization_code = await get_code_with_playwright(auth_url)

        # Fall back to manual if automatic failed
        if not authorization_code:
            print()
            print("Falling back to manual mode...")
            authorization_code = manual_flow(auth_url)

    if not authorization_code:
        print("Error: Could not obtain authorization code")
        sys.exit(1)

    print()

    try:
        result = await exchange_tokens(authorization_code, code_verifier)

        refresh_token = result.get("refresh_token")
        if not refresh_token:
            print("Error: No refresh token in response")
            sys.exit(1)

        print()
        print("=" * 60)
        print("SUCCESS!")
        print("=" * 60)
        print()
        print("Copy this refresh token to Home Assistant:")
        print()
        print("-" * 60)
        print(refresh_token)
        print("-" * 60)
        print()
        print("In Home Assistant:")
        print("1. Go to Settings → Devices & Services")
        print("2. Click '+ Add Integration'")
        print("3. Search for 'e-Boks'")
        print("4. Select 'MitID' login method")
        print("5. Paste the refresh token above")
        print()

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
