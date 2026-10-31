"""API-key authentication for the h4k API.

h4k has never had authentication: it binds to localhost and assumes a single
trusted operator. That is fine for a laptop but dangerous on a shared host or a
container published to a network.

``H4K_API_KEY`` turns on authentication: every request to the API (except
health and the docs) must carry ``X-API-Key: <key>`` or be rejected with 401.
When the variable is unset, authentication is **off** -- preserving the
existing behaviour for solo operators and the test suite.
"""

from __future__ import annotations

import hmac
import logging
import os

logger = logging.getLogger("h4k.auth")

ENV_VAR = "H4K_API_KEY"


def api_key() -> str | None:
    """The configured API key, or None when auth is disabled."""
    value = os.environ.get(ENV_VAR, "").strip()
    return value or None


def auth_enabled() -> bool:
    return api_key() is not None


def is_exempt(path: str) -> bool:
    """Paths that bypass authentication (health probes, docs, static assets)."""
    if not path:
        return False
    if path in ("/", "/docs", "/redoc", "/openapi.json", "/api", "/api/health"):
        return True
    if path.startswith("/static"):
        return True
    return path.startswith("/docs/") or path.startswith("/redoc/")


def check_key(supplied: str | None) -> bool:
    """Constant-time comparison of the supplied key against the configured one."""
    configured = api_key()
    if configured is None:
        return True  # auth disabled
    if not supplied:
        return False
    return hmac.compare_digest(supplied, configured)
