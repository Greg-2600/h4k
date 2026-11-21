# Authentication endpoints: config discovery, OIDC login/callback/logout,
# principal introspection, and admin API-key management.
#
# These routes are mounted at /api/auth. The config/login/callback/logout
# endpoints are public by design (you cannot present a credential before you
# have one); everything else follows the same role rules as the rest of the API.
import logging
import os
import urllib.parse
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from services import auth

logger = logging.getLogger("h4k.routers.auth")

router = APIRouter(prefix="/api/auth")

_OIDC = auth.OidcClient  # patched in tests
_OIDC_CLIENT: auth.OidcClient | None = None
_OIDC_KEY: tuple[str, str] | None = None


def _config() -> auth.AuthConfig:
    return auth.load_config(refresh=True)


def _oidc_client(config: auth.AuthConfig) -> auth.OidcClient | None:
    """One client per provider configuration.

    The client owns the short-lived state/nonce/PKCE map, so constructing a new
    instance for the callback would forget the login it just started.
    """
    global _OIDC_CLIENT, _OIDC_KEY
    if not config.oidc:
        return None
    key = (config.oidc.issuer, config.oidc.client_id)
    if _OIDC_CLIENT is None or key != _OIDC_KEY:
        _OIDC_CLIENT = _OIDC(config.oidc)
        _OIDC_KEY = key
    return _OIDC_CLIENT


def _principal(request: Request) -> auth.Principal:
    return getattr(request.state, "principal", None) or auth.principal_from_request(
        request, _config()
    )


def _redirect_uri(request: Request, override: str = "") -> str:
    if override:
        return override
    if os.environ.get("H4K_OIDC_REDIRECT_URI"):
        return os.environ["H4K_OIDC_REDIRECT_URI"]
    return str(request.base_url).rstrip("/") + "/api/auth/callback"


@router.get("/config")
def auth_config() -> dict[str, Any]:
    """Public auth capability discovery for the login screen."""
    config = _config()
    return {
        "enabled": config.enabled,
        "oidc": {
            "enabled": bool(config.oidc),
            "issuer": config.oidc.issuer if config.oidc else "",
            "client_id": config.oidc.client_id if config.oidc else "",
            "login_url": "/api/auth/login",
        },
        "roles": list(auth.ROLE_LEVELS),
        "session_cookie": auth.SESSION_COOKIE,
        "rate_limits": {
            "anonymous": config.limit_anonymous,
            "authenticated": config.limit_authenticated,
            "operator": config.limit_operator,
            "window_seconds": config.rate_window,
        },
    }


@router.get("/me")
def auth_me(request: Request) -> dict[str, Any]:
    principal = _principal(request)
    return {
        "subject": principal.subject,
        "role": principal.role,
        "method": principal.method,
        "claims": {
            k: v
            for k, v in principal.claims.items()
            if k in {"email", "name", "preferred_username", "exp", "iat"}
        },
    }


@router.get("/login")
def auth_login(request: Request) -> Response:
    """Start the OIDC authorization-code + PKCE flow."""
    config = _config()
    client = _oidc_client(config)
    if client is None:
        raise HTTPException(
            status_code=400,
            detail="OIDC is not configured (set H4K_OIDC_ISSUER and H4K_OIDC_CLIENT_ID)",
        )
    try:
        url = client.authorization_url(_redirect_uri(request))
    except auth.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return RedirectResponse(url, status_code=307)


@router.get("/callback")
def auth_callback(
    request: Request, code: str = "", state: str = "", error: str = ""
) -> Response:
    if error:
        raise HTTPException(status_code=401, detail=f"OIDC provider error: {error}")
    if not code or not state:
        raise HTTPException(status_code=400, detail="code and state are required")
    config = _config()
    client = _oidc_client(config)
    if client is None:
        raise HTTPException(status_code=400, detail="OIDC is not configured")
    try:
        result = client.exchange(code, state)
    except auth.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    claims = dict(result["claims"])
    claims["role"] = client.role_for(claims)
    token = auth.issue_session(claims, config.session_secret, config.session_ttl)
    target = os.environ.get("H4K_OIDC_POST_LOGIN", "/")
    if not target.startswith("/"):
        target = "/"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        max_age=config.session_ttl,
        httponly=True,
        samesite="lax",
        secure=os.environ.get("H4K_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"},
        path="/",
    )
    logger.info(
        "OIDC login: %s (%s)", claims.get("sub") or claims.get("email"), claims["role"]
    )
    return response


@router.post("/logout")
def auth_logout() -> Response:
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return response


@router.get("/keys")
def auth_keys(request: Request) -> dict[str, Any]:
    principal = _principal(request)
    if not principal.can("admin"):
        raise HTTPException(status_code=403, detail="admin role required")
    config = _config()
    return {
        "keys": auth.list_keys(config),
        "env_keys": sum(1 for k in config.keys.values() if k.source == "env"),
        "file": str(config.key_file),
    }


@router.post("/keys")
def auth_keys_create(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    principal = _principal(request)
    if not principal.can("admin"):
        raise HTTPException(status_code=403, detail="admin role required")
    try:
        result = auth.add_key(
            str(body.get("name") or ""), str(body.get("role") or "operator")
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # The plaintext key is returned exactly once. It is never logged.
    return {**result, "note": "store this key now — it cannot be shown again"}


@router.delete("/keys/{name}")
def auth_keys_delete(request: Request, name: str) -> dict[str, Any]:
    principal = _principal(request)
    if not principal.can("admin"):
        raise HTTPException(status_code=403, detail="admin role required")
    if not auth.delete_key(name):
        raise HTTPException(status_code=404, detail="api key not found")
    return {"status": "deleted", "name": name}


@router.get("/verify")
def auth_verify(request: Request) -> dict[str, Any]:
    """Validate the presented credential without performing an action."""
    principal = _principal(request)
    if principal.method == "anonymous":
        raise HTTPException(status_code=401, detail="no credential presented")
    return {"valid": True, "subject": principal.subject, "role": principal.role}


@router.get("/login-url")
def auth_login_url(request: Request) -> dict[str, Any]:
    """Build (but do not follow) the provider URL — useful for docs/tests."""
    config = _config()
    client = _oidc_client(config)
    if client is None:
        raise HTTPException(status_code=400, detail="OIDC is not configured")
    return {
        "url": client.authorization_url(_redirect_uri(request)),
        "redirect_uri": _redirect_uri(request),
    }


def parse_bearer(header: str) -> str:
    """Small helper kept public for middleware tests."""
    value = header.strip()
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return urllib.parse.unquote(value)
