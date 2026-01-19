"""HTTP views for MitID OAuth callback handling."""
from __future__ import annotations

import logging
import re
from typing import Any

from aiohttp import web

from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Store pending auth flows
PENDING_AUTH_FLOWS: dict[str, dict[str, Any]] = {}


def extract_code_from_url(url: str) -> str | None:
    """Extract authorization code from callback URL."""
    if "code=" in url:
        match = re.search(r'[?&]code=([^&]+)', url)
        if match:
            return match.group(1)
    return None


class EboksMitIDCallbackView(HomeAssistantView):
    """Handle MitID OAuth callback."""

    url = "/api/eboks/callback"
    name = "api:eboks:callback"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the view."""
        self.hass = hass

    async def get(self, request: web.Request) -> web.Response:
        """Handle GET request - show form to paste URL."""
        flow_id = request.query.get("flow_id", "")

        html = f"""<!DOCTYPE html>
<html lang="da">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>e-Boks MitID Login</title>
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            padding: 40px;
            max-width: 600px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }}
        .logo {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .logo h1 {{
            color: #1a1a2e;
            font-size: 28px;
            margin-bottom: 8px;
        }}
        .logo p {{
            color: #666;
            font-size: 14px;
        }}
        .steps {{
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .step {{
            display: flex;
            align-items: flex-start;
            margin-bottom: 16px;
        }}
        .step:last-child {{
            margin-bottom: 0;
        }}
        .step-number {{
            background: #4CAF50;
            color: white;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 14px;
            margin-right: 12px;
            flex-shrink: 0;
        }}
        .step-number.pending {{
            background: #ccc;
        }}
        .step-text {{
            color: #333;
            line-height: 1.5;
        }}
        .step-text strong {{
            color: #1a1a2e;
        }}
        .mitid-btn {{
            display: block;
            width: 100%;
            padding: 16px 24px;
            background: #0060e6;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            text-align: center;
            text-decoration: none;
            margin-bottom: 24px;
            transition: background 0.2s;
        }}
        .mitid-btn:hover {{
            background: #0050c0;
        }}
        .form-group {{
            margin-bottom: 16px;
        }}
        label {{
            display: block;
            color: #333;
            font-weight: 500;
            margin-bottom: 8px;
        }}
        textarea {{
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            font-family: monospace;
            resize: vertical;
            min-height: 100px;
            transition: border-color 0.2s;
        }}
        textarea:focus {{
            outline: none;
            border-color: #0060e6;
        }}
        .submit-btn {{
            width: 100%;
            padding: 14px 24px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .submit-btn:hover {{
            background: #43a047;
        }}
        .submit-btn:disabled {{
            background: #ccc;
            cursor: not-allowed;
        }}
        .error {{
            background: #ffebee;
            color: #c62828;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
            display: none;
        }}
        .success {{
            background: #e8f5e9;
            color: #2e7d32;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            display: none;
        }}
        .success h3 {{
            margin-bottom: 8px;
        }}
        .hint {{
            color: #666;
            font-size: 13px;
            margin-top: 8px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>e-Boks MitID Login</h1>
            <p>Home Assistant Integration</p>
        </div>

        <div class="steps">
            <div class="step">
                <div class="step-number">1</div>
                <div class="step-text">
                    Klik p\u00e5 <strong>"Log ind med MitID"</strong> knappen nedenfor
                </div>
            </div>
            <div class="step">
                <div class="step-number pending">2</div>
                <div class="step-text">
                    Gennemf\u00f8r MitID login i det nye vindue
                </div>
            </div>
            <div class="step">
                <div class="step-number pending">3</div>
                <div class="step-text">
                    N\u00e5r browseren viser en fejl (kan ikke \u00e5bne <code>eboksdk://</code>),
                    <strong>kopier hele URL'en</strong> fra adresselinjen
                </div>
            </div>
            <div class="step">
                <div class="step-number pending">4</div>
                <div class="step-text">
                    Inds\u00e6t URL'en i feltet nedenfor og klik <strong>"Fuldfor"</strong>
                </div>
            </div>
        </div>

        <a id="mitid-link" class="mitid-btn" href="#" target="_blank">
            Log ind med MitID
        </a>

        <div id="error" class="error"></div>
        <div id="success" class="success">
            <h3>Login gennemf\u00f8rt!</h3>
            <p>Du kan nu lukke dette vindue og g\u00e5 tilbage til Home Assistant.</p>
        </div>

        <form id="callback-form">
            <input type="hidden" name="flow_id" value="{flow_id}">
            <div class="form-group">
                <label for="callback_url">Inds\u00e6t callback URL her:</label>
                <textarea
                    id="callback_url"
                    name="callback_url"
                    placeholder="eboksdk://ngdpoidc/callback?code=...&state=..."
                    required
                ></textarea>
                <p class="hint">
                    Tip: URL'en starter med <code>eboksdk://</code> og indeholder <code>code=</code>
                </p>
            </div>
            <button type="submit" class="submit-btn">Fuldf\u00f8r login</button>
        </form>
    </div>

    <script>
        // Get auth URL from pending flows
        const flowId = '{flow_id}';

        // Fetch auth URL
        fetch('/api/eboks/auth_url?flow_id=' + flowId)
            .then(r => r.json())
            .then(data => {{
                if (data.auth_url) {{
                    document.getElementById('mitid-link').href = data.auth_url;
                }}
            }})
            .catch(e => console.error('Could not get auth URL:', e));

        // Handle form submission
        document.getElementById('callback-form').addEventListener('submit', async function(e) {{
            e.preventDefault();

            const errorEl = document.getElementById('error');
            const successEl = document.getElementById('success');
            const formEl = document.getElementById('callback-form');
            const submitBtn = formEl.querySelector('button[type="submit"]');

            errorEl.style.display = 'none';
            submitBtn.disabled = true;
            submitBtn.textContent = 'Behandler...';

            const callbackUrl = document.getElementById('callback_url').value.trim();

            try {{
                const response = await fetch('/api/eboks/callback', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{
                        flow_id: flowId,
                        callback_url: callbackUrl,
                    }}),
                }});

                const result = await response.json();

                if (result.success) {{
                    formEl.style.display = 'none';
                    successEl.style.display = 'block';
                    document.querySelector('.steps').style.display = 'none';
                    document.getElementById('mitid-link').style.display = 'none';
                }} else {{
                    errorEl.textContent = result.error || 'Der opstod en fejl';
                    errorEl.style.display = 'block';
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Fuldf\u00f8r login';
                }}
            }} catch (err) {{
                errorEl.textContent = 'Netv\u00e6rksfejl: ' + err.message;
                errorEl.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.textContent = 'Fuldf\u00f8r login';
            }}
        }});

        // Auto-detect paste
        document.getElementById('callback_url').addEventListener('paste', function(e) {{
            setTimeout(() => {{
                const value = this.value.trim();
                if (value.includes('code=') && value.includes('eboksdk://')) {{
                    document.getElementById('callback-form').dispatchEvent(new Event('submit'));
                }}
            }}, 100);
        }});
    </script>
</body>
</html>"""

        return web.Response(text=html, content_type="text/html")

    async def post(self, request: web.Request) -> web.Response:
        """Handle POST request - process callback URL."""
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON"})

        flow_id = data.get("flow_id", "")
        callback_url = data.get("callback_url", "")

        if not flow_id:
            return web.json_response({"success": False, "error": "Mangler flow_id"})

        if not callback_url:
            return web.json_response({"success": False, "error": "Mangler callback URL"})

        # Extract authorization code
        code = extract_code_from_url(callback_url)
        if not code:
            return web.json_response({
                "success": False,
                "error": "Kunne ikke finde authorization code i URL'en. Sørg for at kopiere hele URL'en."
            })

        # Store code for the flow
        if flow_id in PENDING_AUTH_FLOWS:
            PENDING_AUTH_FLOWS[flow_id]["code"] = code
            _LOGGER.info("Received authorization code for flow %s", flow_id)
            return web.json_response({"success": True})
        else:
            _LOGGER.warning("Unknown flow_id: %s", flow_id)
            return web.json_response({
                "success": False,
                "error": "Ukendt flow ID. Prøv at starte opsætningen igen."
            })


class EboksMitIDAuthUrlView(HomeAssistantView):
    """Provide auth URL for a flow."""

    url = "/api/eboks/auth_url"
    name = "api:eboks:auth_url"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Return auth URL for flow."""
        flow_id = request.query.get("flow_id", "")

        if flow_id in PENDING_AUTH_FLOWS:
            auth_url = PENDING_AUTH_FLOWS[flow_id].get("auth_url", "")
            return web.json_response({"auth_url": auth_url})

        return web.json_response({"auth_url": ""})


@callback
def async_register_views(hass: HomeAssistant) -> None:
    """Register HTTP views."""
    hass.http.register_view(EboksMitIDCallbackView(hass))
    hass.http.register_view(EboksMitIDAuthUrlView())
    _LOGGER.debug("Registered e-Boks MitID callback views")
