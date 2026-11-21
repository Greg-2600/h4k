# Authentication, authorization and rate limiting for h4k.
#
# h4k started life as a single-operator console bound to localhost, where the
# network was the authentication. That stops being true the moment it is put on
# a shared lab VLAN or behind a reverse proxy. This module adds three things
# without turning the project into an identity provider:
#
#   1. API keys with roles (viewer < operator < admin), from env or a 0600 JSON
#      file so keys survive a restart and can be rotated from the UI/API.
#   2. Optional OIDC authorization-code + PKCE login against any compliant
#      provider. Disabled unless H4K_OIDC_ISSUER/CLIENT_ID are configured, so
#      the offline classroom deployment needs no network.
#   3. A role-aware sliding-window rate limiter with real 429 headers.
#
# Defaults are deliberately backwards compatible: with H4K_AUTH_ENABLED unset
# the middleware is a no-op and every existing test/route behaves as before.
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.auth")

ROLE_LEVELS = {"viewer": 1, "operator": 2, "admin": 3}
DEFAULT_ROLE = "operator"
SESSION_COOKIE = "h4k_session"
KEY_FILE_NAME = "api_keys.json"

# One process-wide fallback signing secret. Generating it inside load_config()
# would give the middleware and each route a different secret, so a session
# minted by the OIDC callback would never verify on the next request.
_EPHEMERAL_SESSION_SECRET = secrets.token_urlsafe(32)

# Endpoints that must stay reachable without a credential: the login flow
# itself, health probes, the UI shell/static assets, and the API docs. Every
# /api route not listed here is protected when auth is enabled.
PUBLIC_PATHS = {
    "/",
    "/api",
    "/api/health",
    "/api/auth/config",
    "/api/auth/login",
    "/api/auth/callback",
    "/api/auth/logout",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/readme",
}
PUBLIC_PREFIXES = ("/static/",)

# Routes that need admin even for GET (key management and host-level sandbox
# administration). Aggressive routes additionally need "operator".
ADMIN_PREFIXES = ("/api/auth/keys", "/api/security", "/api/sandbox/run")
OPERATOR_PREFIXES = (
    "/api/scan",
    "/api/attack",
    "/api/passattack",
    "/api/deepattack",
    "/api/autopilot",
    "/api/fuzz",
    "/api/vulnleads",
    "/api/ad",
    "/api/lab",
    "/api/telemetry/events",
    "/api/automation",
    "/api/net/mitm",
    "/api/net/sniff",
    "/api/net/wifi",
    "/api/net/tls",
    "/api/engagement",
    "/api/source",
    "/api/zap",
    "/api/john",
    "/api/aircrack",
    "/api/tshark",
    "/api/nmap",
    "/api/container_escape",
    "/api/lateral",
    "/api/db_interrogate",
    "/api/nuclei",
    "/api/sqlmap",
    "/api/ollama",
    "/api/session",
)


class AuthError(Exception):
    """Authentication/authorization failure with an HTTP status code."""

    def __init__(self, status_code: int, detail: str, *, challenge: str = "") -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.challenge = challenge


def _now() -> float:
    return time.time()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def hash_key(key: str) -> str:
    """API keys are stored as SHA-256 hashes; the plaintext is shown once."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_key(prefix: str = "h4k") -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def mask_key(key: str) -> str:
    if len(key) <= 10:
        return "***"
    return f"{key[:6]}…{key[-4:]}"


@dataclass(frozen=True)
class ApiKey:
    name: str
    role: str
    key_hash: str
    created_at: str = ""
    source: str = "env"

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
            "source": self.source,
            "fingerprint": self.key_hash[:12],
        }


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str = "viewer"
    method: str = "anonymous"
    claims: dict[str, Any] = field(default_factory=dict)

    @property
    def level(self) -> int:
        return ROLE_LEVELS.get(self.role, 0)

    def can(self, role: str) -> bool:
        return self.level >= ROLE_LEVELS.get(role, 99)


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int
    window: float

    def headers(self) -> dict[str, str]:
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(self.reset_seconds),
        }


class RateLimiter:
    """Sliding-window limiter keyed by principal/IP and budget class."""

    def __init__(self, window: float = 60.0) -> None:
        self.window = max(1.0, float(window))
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int) -> RateDecision:
        now = _now()
        cutoff = now - self.window
        with self._lock:
            hits = [t for t in self._hits[key] if t > cutoff]
            allowed = len(hits) < limit
            if allowed:
                hits.append(now)
            self._hits[key] = hits
            oldest = hits[0] if hits else now
            reset = int(max(1.0, self.window - (now - oldest)))
        return RateDecision(
            allowed=allowed,
            limit=limit,
            remaining=max(0, limit - len(hits)),
            reset_seconds=reset,
            window=self.window,
        )

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


@dataclass
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str = ""
    scopes: str = "openid profile email"
    redirect_uri: str = ""
    role_claim: str = "roles"
    admin_role: str = "h4k-admin"
    operator_role: str = "h4k-operator"
    verify_tls: bool = True

    @property
    def enabled(self) -> bool:
        return bool(self.issuer and self.client_id)


@dataclass
class AuthConfig:
    enabled: bool
    keys: dict[str, ApiKey]
    oidc: OidcConfig | None
    session_secret: str
    session_ttl: int
    key_file: Path
    limit_anonymous: int
    limit_authenticated: int
    limit_operator: int
    rate_window: float

    def key_by_plaintext(self, key: str) -> ApiKey | None:
        if not key:
            return None
        digest = hash_key(key)
        # constant-time compare so a timing side-channel cannot enumerate keys
        for candidate in self.keys.values():
            if hmac.compare_digest(candidate.key_hash, digest):
                return candidate
        return None

    def limit_for(self, principal: Principal) -> int:
        if principal.method in ("apikey", "oidc"):
            if principal.role == "admin":
                return self.limit_operator
            if principal.role == "operator":
                return self.limit_operator
            return self.limit_authenticated
        return self.limit_anonymous


def _runtime_dir() -> Path:
    container = Path("/opt/h4k/data")
    if container.is_dir():
        return container
    return Path(__file__).resolve().parent.parent / "data"


def key_file_path() -> Path:
    override = os.environ.get("H4K_API_KEYS_FILE", "")
    return Path(override) if override else _runtime_dir() / KEY_FILE_NAME


def _read_key_file(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("api key file unreadable: %s", path)
        return []
    if isinstance(data, dict):
        data = data.get("keys", [])
    if not isinstance(data, list):
        return []
    return [row for row in data if isinstance(row, dict) and row.get("key_hash")]


def _write_key_file(path: Path, keys: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"keys": keys}, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _parse_env_keys(raw: str) -> list[dict[str, Any]]:
    """Parse ``name:role:key`` triples (comma separated).

    A bare key is accepted too and gets the default operator role. The key is
    the last field so a base64 key containing ':' still works when the caller
    supplies an explicit name and role.
    """
    rows: list[dict[str, Any]] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":", 2)
        if len(parts) == 1:
            name, role, key = "env-key", DEFAULT_ROLE, parts[0]
        elif len(parts) == 2:
            name, role, key = parts[0], DEFAULT_ROLE, parts[1]
        else:
            name, role, key = parts
        role = role if role in ROLE_LEVELS else DEFAULT_ROLE
        if not key:
            continue
        rows.append(
            {
                "name": name,
                "role": role,
                "key_hash": hash_key(key),
                "created_at": "",
                "source": "env",
            }
        )
    return rows


def _load_keys(path: Path) -> dict[str, ApiKey]:
    rows: list[dict[str, Any]] = []
    rows.extend(_parse_env_keys(os.environ.get("H4K_API_KEYS", "")))
    rows.extend(_read_key_file(path))
    keys: dict[str, ApiKey] = {}
    for row in rows:
        key = ApiKey(
            name=str(row.get("name") or "key"),
            role=str(row.get("role") or DEFAULT_ROLE),
            key_hash=str(row["key_hash"]),
            created_at=str(row.get("created_at") or ""),
            source=str(row.get("source") or "file"),
        )
        # last one wins, so a file key can rotate an env key with the same name
        keys[key.name] = key
    return keys


def load_config(*, refresh: bool = False) -> AuthConfig:
    enabled = os.environ.get("H4K_AUTH_ENABLED", "0").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    path = key_file_path()
    oidc = None
    issuer = os.environ.get("H4K_OIDC_ISSUER", "").strip()
    client_id = os.environ.get("H4K_OIDC_CLIENT_ID", "").strip()
    if issuer and client_id:
        oidc = OidcConfig(
            issuer=issuer.rstrip("/"),
            client_id=client_id,
            client_secret=os.environ.get("H4K_OIDC_CLIENT_SECRET", ""),
            scopes=os.environ.get("H4K_OIDC_SCOPES", "openid profile email"),
            redirect_uri=os.environ.get("H4K_OIDC_REDIRECT_URI", ""),
            role_claim=os.environ.get("H4K_OIDC_ROLE_CLAIM", "roles"),
            admin_role=os.environ.get("H4K_OIDC_ADMIN_ROLE", "h4k-admin"),
            operator_role=os.environ.get("H4K_OIDC_OPERATOR_ROLE", "h4k-operator"),
            verify_tls=os.environ.get("H4K_OIDC_VERIFY_TLS", "1")
            not in {"0", "false", "no"},
        )
    secret = os.environ.get("H4K_SESSION_SECRET", "")
    if not secret:
        # Ephemeral secret: sessions do not survive a restart, which is safer
        # than a hard-coded default when the operator forgot to set one.
        secret = _EPHEMERAL_SESSION_SECRET
    legacy_key = os.environ.get("H4K_API_KEY", "").strip()
    return AuthConfig(
        enabled=enabled or bool(oidc) or bool(legacy_key),
        keys=_load_keys(path),
        oidc=oidc,
        session_secret=secret,
        session_ttl=int(os.environ.get("H4K_SESSION_TTL", "28800")),
        key_file=path,
        limit_anonymous=int(os.environ.get("H4K_RATE_LIMIT_ANON", "120")),
        limit_authenticated=int(os.environ.get("H4K_RATE_LIMIT_AUTHED", "600")),
        limit_operator=int(os.environ.get("H4K_RATE_LIMIT_OPERATOR", "1200")),
        rate_window=float(os.environ.get("H4K_RATE_LIMIT_WINDOW", "60")),
    )


def is_public_path(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)


def required_role(method: str, path: str) -> str:
    for prefix in ADMIN_PREFIXES:
        if path.startswith(prefix):
            return "admin"
    if method.upper() in ("GET", "HEAD", "OPTIONS"):
        return "viewer"
    for prefix in OPERATOR_PREFIXES:
        if path.startswith(prefix):
            return "operator"
    return "operator"


# ---------------------------------------------------------------------------
# OIDC
# ---------------------------------------------------------------------------
class OidcClient:
    """Minimal, dependency-light OIDC authorization-code client with PKCE.

    Discovery and token exchange use urllib; ID tokens are verified locally
    (RS256/RS384/RS512/ES256/HS256) so a forged token cannot become a session.
    A pending-login map keeps state/nonce/verifier server-side and expires it
    after five minutes.
    """

    PENDING_TTL = 300.0

    def __init__(self, config: OidcConfig) -> None:
        self.config = config
        self._discovery: dict[str, Any] | None = None
        self._discovery_at = 0.0
        self._pending: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    # -- HTTP ---------------------------------------------------------------
    def _fetch_json(self, url: str, *, data: bytes | None = None) -> dict[str, Any]:
        req = urllib.request.Request(
            url, data=data, headers={"Accept": "application/json"}
        )
        if data is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        context = None
        if not self.config.verify_tls:
            import ssl

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(  # nosec B310 - configured OIDC issuer only
            req, timeout=10, context=context
        ) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def discover(self) -> dict[str, Any]:
        if self._discovery and _now() - self._discovery_at < 3600:
            return self._discovery
        url = f"{self.config.issuer}/.well-known/openid-configuration"
        doc = self._fetch_json(url)
        for field_name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not doc.get(field_name):
                raise AuthError(502, f"OIDC discovery missing {field_name}")
        self._discovery = doc
        self._discovery_at = _now()
        return doc

    # -- login flow ---------------------------------------------------------
    def authorization_url(self, redirect_uri: str = "") -> str:
        doc = self.discover()
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        challenge = _b64url_encode(hashlib.sha256(verifier.encode()).digest())
        with self._lock:
            self._expire_pending()
            self._pending[state] = {
                "nonce": nonce,
                "verifier": verifier,
                "redirect_uri": redirect_uri or self.config.redirect_uri,
                "created": _now(),
            }
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri or self.config.redirect_uri,
            "scope": self.config.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{doc['authorization_endpoint']}?{urllib.parse.urlencode(params)}"

    def _expire_pending(self) -> None:
        cutoff = _now() - self.PENDING_TTL
        for state in [s for s, p in self._pending.items() if p["created"] < cutoff]:
            self._pending.pop(state, None)

    def exchange(self, code: str, state: str) -> dict[str, Any]:
        with self._lock:
            self._expire_pending()
            pending = self._pending.pop(state, None)
        if pending is None:
            raise AuthError(400, "unknown or expired OIDC state")
        doc = self.discover()
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": pending["redirect_uri"],
            "client_id": self.config.client_id,
            "code_verifier": pending["verifier"],
        }
        if self.config.client_secret:
            form["client_secret"] = self.config.client_secret
        tokens = self._fetch_json(
            doc["token_endpoint"], data=urllib.parse.urlencode(form).encode()
        )
        id_token = tokens.get("id_token")
        if not id_token:
            raise AuthError(502, "OIDC provider returned no id_token")
        claims = verify_jwt(id_token, doc, audience=self.config.client_id)
        if claims.get("nonce") and claims["nonce"] != pending["nonce"]:
            raise AuthError(401, "OIDC nonce mismatch")
        return {"tokens": tokens, "claims": claims}

    def role_for(self, claims: dict[str, Any]) -> str:
        raw = claims.get(self.config.role_claim, [])
        if isinstance(raw, str):
            raw = [raw]
        roles = {str(r) for r in raw} if isinstance(raw, list) else set()
        if self.config.admin_role in roles:
            return "admin"
        if self.config.operator_role in roles:
            return "operator"
        return "viewer"


def _jwk_public_key(jwk: dict[str, Any]) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if jwk.get("kty") == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if jwk.get("kty") == "EC":
        curve = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
        }.get(jwk.get("crv", ""))
        if curve is None:
            raise AuthError(401, "unsupported OIDC EC curve")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise AuthError(401, f"unsupported OIDC key type: {jwk.get('kty')}")


def verify_jwt(
    token: str, discovery: dict[str, Any], *, audience: str, leeway: int = 60
) -> dict[str, Any]:
    """Verify a compact JWT against an OIDC provider's published JWKS."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AuthError(401, "malformed JWT") from exc
    alg = str(header.get("alg", ""))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode(sig_b64)

    if alg == "HS256":
        raise AuthError(401, "HS256 ID tokens are not accepted")
    if alg not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}:
        raise AuthError(401, f"unsupported JWT algorithm: {alg}")

    jwks: dict[str, Any] = {"keys": []}
    jwks_uri = discovery.get("jwks_uri")
    if jwks_uri:
        req = urllib.request.Request(jwks_uri, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            jwks = json.loads(resp.read().decode("utf-8"))
    candidates = [
        k
        for k in jwks.get("keys", [])
        if not k.get("kid") or k.get("kid") == header.get("kid")
    ]
    if not candidates:
        raise AuthError(401, "no matching JWKS key")
    alg_hash = {
        "RS256": hashes.SHA256,
        "RS384": hashes.SHA384,
        "RS512": hashes.SHA512,
        "ES256": hashes.SHA256,
        "ES384": hashes.SHA384,
        "ES512": hashes.SHA512,
    }[alg]
    verified = False
    for jwk in candidates:
        try:
            key = _jwk_public_key(jwk)
            if isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(
                    signature, signing_input, ec.ECDSA(alg_hash())  # type: ignore[abstract]
                )
            else:
                key.verify(
                    signature,
                    signing_input,
                    padding.PKCS1v15(),
                    alg_hash(),  # type: ignore[abstract]
                )
            verified = True
            break
        except (InvalidSignature, ValueError, KeyError, TypeError):
            continue
    if not verified:
        raise AuthError(401, "JWT signature verification failed")

    now = int(_now())
    if int(claims.get("exp", 0)) + leeway < now:
        raise AuthError(401, "JWT expired")
    if int(claims.get("nbf", 0)) - leeway > now:
        raise AuthError(401, "JWT not yet valid")
    aud = claims.get("aud")
    aud_list = aud if isinstance(aud, list) else [aud]
    if audience not in aud_list:
        raise AuthError(401, "JWT audience mismatch")
    expected_issuer = discovery.get("issuer")
    if expected_issuer and claims.get("iss") != expected_issuer:
        raise AuthError(401, "JWT issuer mismatch")
    return claims


# ---------------------------------------------------------------------------
# Session tokens (signed, HttpOnly cookie)
# ---------------------------------------------------------------------------
def issue_session(
    claims: dict[str, Any], secret: str, ttl: int, *, now: float | None = None
) -> str:
    issued = int(now if now is not None else _now())
    payload = {
        "sub": str(claims.get("sub") or claims.get("email") or "user"),
        "role": str(claims.get("role") or "viewer"),
        "email": str(claims.get("email") or ""),
        "name": str(claims.get("name") or claims.get("preferred_username") or ""),
        "iat": issued,
        "exp": issued + int(ttl),
    }
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64url_encode(sig)}"


def verify_session(
    token: str, secret: str, *, now: float | None = None
) -> dict[str, Any]:
    try:
        body, sig = token.split(".")
        expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig)):
            raise AuthError(401, "bad session signature")
        payload = json.loads(_b64url_decode(body))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AuthError(401, "malformed session token") from exc
    if int(payload.get("exp", 0)) < int(now if now is not None else _now()):
        raise AuthError(401, "session expired")
    return payload


# ---------------------------------------------------------------------------
# Request principal
# ---------------------------------------------------------------------------
def principal_from_request(request: Any, config: AuthConfig) -> Principal:
    """Resolve the caller from an API key or session cookie.

    Raises AuthError(401) when auth is enabled and no valid credential is
    presented for a protected path. Public paths get a viewer principal.
    """
    path = str(getattr(request.url, "path", "/"))
    if not config.enabled and config.oidc is None:
        return Principal(subject="anonymous", role="admin", method="disabled")

    key = str(request.headers.get("x-api-key") or "").strip()
    legacy = os.environ.get("H4K_API_KEY", "").strip()
    if legacy:
        if key and hmac.compare_digest(key, legacy):
            return Principal(subject="operator", role="admin", method="apikey")
        if is_public_path(path):
            return Principal(subject="anonymous", role="viewer", method="anonymous")
        raise AuthError(
            401,
            "missing or invalid API key (X-API-Key header)",
            challenge="ApiKey",
        )
    auth_header = str(request.headers.get("authorization") or "")
    if not key and auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        # Session tokens are compact JWT-ish; API keys are also bearer-friendly.
        record = config.key_by_plaintext(token)
        if record is not None:
            return Principal(subject=record.name, role=record.role, method="apikey")
        key = ""
        cookie = _session_cookie(request)
        token = cookie or token
    else:
        token = key
        record = config.key_by_plaintext(key)
        if record is not None:
            return Principal(subject=record.name, role=record.role, method="apikey")
        token = _session_cookie(request)

    if token:
        claims = verify_session(token, config.session_secret)
        return Principal(
            subject=str(claims.get("sub") or "user"),
            role=str(claims.get("role") or "viewer"),
            method="oidc",
            claims=claims,
        )

    if is_public_path(path):
        return Principal(subject="anonymous", role="viewer", method="anonymous")
    raise AuthError(401, "authentication required", challenge="Bearer")


def _session_cookie(request: Any) -> str:
    cookies = getattr(request, "cookies", None)
    if cookies is not None:
        try:
            return str(cookies.get(SESSION_COOKIE) or "")
        except Exception:
            return ""
    raw = str(request.headers.get("cookie") or "")
    for part in raw.split(";"):
        name, _, value = part.strip().partition("=")
        if name == SESSION_COOKIE:
            return value
    return ""


def enforce(principal: Principal, method: str, path: str) -> None:
    need = required_role(method, path)
    if not principal.can(need):
        raise AuthError(403, f"{need} role required for {method.upper()} {path}")


# ---------------------------------------------------------------------------
# Key management (used by the auth router)
# ---------------------------------------------------------------------------
def add_key(name: str, role: str, *, path: Path | None = None) -> dict[str, Any]:
    if role not in ROLE_LEVELS:
        raise ValueError(f"unknown role: {role}")
    if not name.strip():
        raise ValueError("key name is required")
    target = path or key_file_path()
    plaintext = generate_key()
    rows = _read_key_file(target)
    rows = [r for r in rows if r.get("name") != name]
    rows.append(
        {
            "name": name.strip(),
            "role": role,
            "key_hash": hash_key(plaintext),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "file",
        }
    )
    _write_key_file(target, rows)
    return {"name": name, "role": role, "key": plaintext}


def delete_key(name: str, *, path: Path | None = None) -> bool:
    target = path or key_file_path()
    rows = _read_key_file(target)
    remaining = [r for r in rows if r.get("name") != name]
    if len(remaining) == len(rows):
        return False
    _write_key_file(target, remaining)
    return True


def list_keys(config: AuthConfig) -> list[dict[str, Any]]:
    return [k.public() for k in sorted(config.keys.values(), key=lambda k: k.name)]


# ---------------------------------------------------------------------------
# Back-compat surface for the env-gated middleware in main.py
# ---------------------------------------------------------------------------
# The legacy middleware only knows H4K_API_KEY; the richer config above
# remains the source of truth for roles/OIDC. Keeping these three helpers
# means an operator who sets only H4K_API_KEY gets the original behaviour.


def api_key() -> str | None:
    """The legacy H4K_API_KEY value, or None when it is unset."""
    value = os.environ.get("H4K_API_KEY", "").strip()
    return value or None


def is_exempt(path: str) -> bool:
    """Legacy public-path check used by the env-gated middleware."""
    if not path:
        return False
    if path in ("/", "/docs", "/redoc", "/openapi.json", "/api", "/api/health"):
        return True
    if path.startswith("/static"):
        return True
    return path.startswith("/docs/") or path.startswith("/redoc/")


def auth_enabled() -> bool:
    """True when the legacy single-key mode is configured."""
    return api_key() is not None


def check_key(supplied: str | None) -> bool:
    """Constant-time comparison for the legacy single-key mode."""
    configured = api_key()
    if configured is None:
        return True
    if not supplied:
        return False
    return hmac.compare_digest(supplied, configured)
