# Auth (#85): API keys, roles, OIDC (discovery/PKCE/JWT verification), signed
# sessions, and a role-aware rate limiter. Everything is offline: the OIDC
# provider and JWKS are faked at the urllib boundary.
import base64
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services import auth


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture()
def client(monkeypatch):
    """TestClient with a no-op lifespan and a fresh auth cache/limiter."""
    import app_state

    class _CveStub:
        cves: tuple = ()
        path = "stub.json"

        def refresh(self) -> bool:
            return False

    app_state.msf_client = None
    app_state.cve_db = _CveStub()  # type: ignore[assignment]
    app_state.active_engagement_id = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    monkeypatch.delenv("H4K_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("H4K_OIDC_CLIENT_ID", raising=False)
    main_module.reset_auth_cache()
    yield TestClient(main_module.app)
    main_module.reset_auth_cache()


# ---------------------------------------------------------------------------
# Config + keys
# ---------------------------------------------------------------------------
def test_env_key_parsing_roles(monkeypatch):
    monkeypatch.setenv(
        "H4K_API_KEYS",
        "alice:admin:aaa, bob:viewer:bbb, carol:operator:cc:dd, bare",
    )
    config = auth.load_config()
    assert config.keys["alice"].role == "admin"
    assert config.keys["bob"].role == "viewer"
    assert config.keys["carol"].key_hash == auth.hash_key("cc:dd")
    assert config.keys["env-key"].role == "operator"
    assert config.key_by_plaintext("aaa").name == "alice"
    assert config.key_by_plaintext("nope") is None


def test_key_file_roundtrip_and_delete(tmp_path):
    path = tmp_path / "keys.json"
    created = auth.add_key("ci", "operator", path=path)
    assert created["key"].startswith("h4k_")
    rows = auth._read_key_file(path)
    assert rows[0]["name"] == "ci"
    assert rows[0]["role"] == "operator"
    assert "key" not in rows[0]  # plaintext is never persisted
    assert auth.delete_key("ci", path=path) is True
    assert auth.delete_key("ci", path=path) is False


def test_add_key_rejects_bad_role_and_blank_name(tmp_path):
    with pytest.raises(ValueError):
        auth.add_key("x", "root", path=tmp_path / "k.json")
    with pytest.raises(ValueError):
        auth.add_key(" ", "viewer", path=tmp_path / "k.json")


def test_principal_key_lookup_is_constant_time_and_has_roles():
    config = auth.AuthConfig(
        enabled=True,
        keys={
            "a": auth.ApiKey("a", "admin", auth.hash_key("secret-a")),
        },
        oidc=None,
        session_secret="s",
        session_ttl=60,
        key_file=Path("/tmp/x"),
        limit_anonymous=1,
        limit_authenticated=2,
        limit_operator=3,
        rate_window=60,
    )
    p = auth.Principal("a", "admin", "apikey")
    assert p.level == 3
    assert p.can("operator") and p.can("admin")
    assert not auth.Principal("v", "viewer").can("operator")
    assert config.limit_for(p) == 3


def test_route_classes():
    assert auth.is_public_path("/api/health")
    assert auth.is_public_path("/static/app.js")
    assert not auth.is_public_path("/api/jobs")
    assert auth.required_role("GET", "/api/jobs") == "viewer"
    assert auth.required_role("POST", "/api/scan") == "operator"
    assert auth.required_role("GET", "/api/auth/keys") == "admin"
    assert auth.required_role("POST", "/api/auth/keys") == "admin"
    assert auth.required_role("POST", "/api/sandbox/run") == "admin"
    assert auth.required_role("POST", "/api/unknown") == "operator"


# ---------------------------------------------------------------------------
# Sessions + JWT
# ---------------------------------------------------------------------------
def test_session_roundtrip_tamper_and_expiry():
    token = auth.issue_session(
        {"sub": "alice", "role": "operator", "email": "a@example.test"},
        "secret",
        3600,
    )
    claims = auth.verify_session(token, "secret")
    assert claims["sub"] == "alice" and claims["role"] == "operator"
    with pytest.raises(auth.AuthError):
        auth.verify_session(token + "x", "secret")
    with pytest.raises(auth.AuthError):
        auth.verify_session(token, "other")
    expired = auth.issue_session({"sub": "a"}, "secret", 10, now=time.time() - 100)
    with pytest.raises(auth.AuthError):
        auth.verify_session(expired, "secret")


def _rsa_keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(public) -> dict:
    numbers = public.public_numbers()
    return {
        "kty": "RSA",
        "kid": "k1",
        "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


def _sign(private, claims: dict) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    header = _b64(json.dumps({"alg": "RS256", "kid": "k1"}).encode())
    payload = _b64(json.dumps(claims).encode())
    sig = private.sign(
        f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{header}.{payload}.{_b64(sig)}"


def test_jwt_verification_rs256(monkeypatch):
    private = _rsa_keypair()
    jwks = {"keys": [_jwk(private.public_key())]}
    token = _sign(
        private,
        {
            "sub": "u1",
            "aud": "h4k-client",
            "exp": int(time.time()) + 300,
            "iss": "https://idp.test",
        },
    )

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(jwks).encode()

    monkeypatch.setattr(auth.urllib.request, "urlopen", lambda *a, **k: _Resp())
    claims = auth.verify_jwt(
        token, {"jwks_uri": "https://idp.test/jwks"}, audience="h4k-client"
    )
    assert claims["sub"] == "u1"

    with pytest.raises(auth.AuthError):
        auth.verify_jwt(token, {"jwks_uri": "https://idp.test/jwks"}, audience="wrong")

    bad = token.rsplit(".", 1)[0] + "." + _b64(b"0" * 64)
    with pytest.raises(auth.AuthError):
        auth.verify_jwt(
            bad, {"jwks_uri": "https://idp.test/jwks"}, audience="h4k-client"
        )


def test_jwt_rejects_hs256_and_expired():
    header = _b64(json.dumps({"alg": "HS256"}).encode())
    payload = _b64(json.dumps({"aud": "x", "exp": int(time.time()) + 10}).encode())
    with pytest.raises(auth.AuthError):
        auth.verify_jwt(f"{header}.{payload}.sig", {}, audience="x")
    expired = (
        _b64(json.dumps({"alg": "RS256"}).encode())
        + "."
        + _b64(json.dumps({"aud": "x", "exp": 1}).encode())
        + ".sig"
    )
    with pytest.raises(auth.AuthError):
        auth.verify_jwt(expired, {}, audience="x")


# ---------------------------------------------------------------------------
# OIDC flow
# ---------------------------------------------------------------------------
def test_oidc_authorization_exchange_and_roles(monkeypatch):
    config = auth.OidcConfig(
        issuer="https://idp.test",
        client_id="h4k-client",
        client_secret="shh",
        redirect_uri="https://h4k.test/api/auth/callback",
        admin_role="h4k-admin",
        operator_role="h4k-operator",
    )
    client = auth.OidcClient(config)
    discovery = {
        "authorization_endpoint": "https://idp.test/auth",
        "token_endpoint": "https://idp.test/token",
        "jwks_uri": "https://idp.test/jwks",
    }
    monkeypatch.setattr(client, "discover", lambda: discovery)
    seen: dict = {}

    def _exchange(url, data):
        seen["url"] = url
        seen["form"] = data.decode()
        return {"id_token": "fake", "access_token": "a"}

    monkeypatch.setattr(client, "_fetch_json", _exchange)
    monkeypatch.setattr(
        auth,
        "verify_jwt",
        lambda token, disco, audience: {
            "sub": "u1",
            "aud": audience,
            "nonce": "n",
        },
    )

    url = client.authorization_url()
    assert url.startswith("https://idp.test/auth?")
    assert "code_challenge_method=S256" in url
    state = url.split("state=")[1].split("&")[0]
    nonce = client._pending[state]["nonce"]

    def _verify(token, disco, audience):
        return {"sub": "u1", "aud": audience, "nonce": nonce}

    monkeypatch.setattr(auth, "verify_jwt", _verify)
    result = client.exchange("code1", state)
    assert result["claims"]["sub"] == "u1"
    assert "grant_type=authorization_code" in seen["form"]
    assert "code_verifier=" in seen["form"]
    assert client.role_for({"roles": ["h4k-admin"]}) == "admin"
    assert client.role_for({"roles": ["h4k-operator"]}) == "operator"
    assert client.role_for({"roles": ["other"]}) == "viewer"
    assert client.role_for({"roles": "h4k-operator"}) == "operator"


def test_oidc_rejects_unknown_state():
    config = auth.OidcConfig(issuer="https://idp", client_id="c")
    client = auth.OidcClient(config)
    with pytest.raises(auth.AuthError):
        client.exchange("code", "nope")


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
def test_rate_limiter_headers_and_window():
    limiter = auth.RateLimiter(window=60)
    first = limiter.check("k", 2)
    second = limiter.check("k", 2)
    third = limiter.check("k", 2)
    assert first.allowed and second.allowed and not third.allowed
    assert third.remaining == 0
    assert third.headers()["X-RateLimit-Limit"] == "2"
    assert 0 < third.reset_seconds <= 60
    limiter.reset("k")
    assert limiter.check("k", 2).allowed


# ---------------------------------------------------------------------------
# Middleware integration
# ---------------------------------------------------------------------------
def test_auth_disabled_keeps_legacy_anonymous_admin(client):
    r = client.get("/api/jobs")
    assert r.status_code == 200
    assert r.headers["X-RateLimit-Limit"]


def test_middleware_enforces_keys_and_roles(client, monkeypatch):
    monkeypatch.setenv("H4K_AUTH_ENABLED", "1")
    monkeypatch.setenv(
        "H4K_API_KEYS",
        "root:admin:root-secret,view:viewer:view-secret,op:operator:op-secret",
    )
    main_module.reset_auth_cache()

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/jobs").status_code == 401
    assert client.get("/api/jobs", headers={"X-API-Key": "nope"}).status_code == 401

    viewer = {"X-API-Key": "view-secret"}
    operator = {"X-API-Key": "op-secret"}
    admin = {"X-API-Key": "root-secret"}
    assert client.get("/api/jobs", headers=viewer).status_code == 200
    # viewer cannot run an operator-class POST
    assert client.post("/api/autopilot/stop", headers=viewer).status_code == 403
    # operator passes authorization, then the route reports no run
    assert client.post("/api/autopilot/stop", headers=operator).status_code == 404
    # admin-only key management
    assert client.get("/api/auth/keys", headers=operator).status_code == 403
    keys = client.get("/api/auth/keys", headers=admin)
    assert keys.status_code == 200
    assert {k["name"] for k in keys.json()["keys"]} >= {"root", "view", "op"}
    me = client.get("/api/auth/me", headers=operator)
    assert me.json()["role"] == "operator"
    assert me.json()["method"] == "apikey"


def test_middleware_bearer_key_and_session_cookie(client, monkeypatch):
    monkeypatch.setenv("H4K_AUTH_ENABLED", "1")
    monkeypatch.setenv("H4K_API_KEYS", "root:admin:root-secret")
    main_module.reset_auth_cache()
    ok = client.get("/api/jobs", headers={"Authorization": "Bearer root-secret"})
    assert ok.status_code == 200

    token = auth.issue_session(
        {"sub": "sso-user", "role": "viewer"},
        main_module._auth_config().session_secret,
        600,
    )
    client.cookies.set(auth.SESSION_COOKIE, token)
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["method"] == "oidc"
    client.cookies.clear()


def test_rate_limit_applies_per_anonymous_ip(client, monkeypatch):
    monkeypatch.setenv("H4K_AUTH_ENABLED", "1")
    monkeypatch.setenv("H4K_RATE_LIMIT_ANON", "3")
    monkeypatch.setenv("H4K_API_KEYS", "root:admin:root-secret")
    main_module.reset_auth_cache()
    codes = [client.get("/api/health").status_code for _ in range(5)]
    assert 200 in codes and 429 in codes
    limited = client.get("/api/health")
    assert limited.status_code == 429
    assert "Retry-After" in limited.headers


def test_key_management_endpoints(client, monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_AUTH_ENABLED", "1")
    monkeypatch.setenv("H4K_API_KEYS", "root:admin:root-secret")
    monkeypatch.setenv("H4K_API_KEYS_FILE", str(tmp_path / "keys.json"))
    main_module.reset_auth_cache()
    admin = {"X-API-Key": "root-secret"}
    created = client.post(
        "/api/auth/keys",
        headers=admin,
        json={"name": "ci", "role": "viewer"},
    )
    assert created.status_code == 200
    plaintext = created.json()["key"]
    assert plaintext.startswith("h4k_")
    # the new key works immediately after a config refresh
    main_module.reset_auth_cache()
    assert client.get("/api/jobs", headers={"X-API-Key": plaintext}).status_code == 200
    listed = client.get("/api/auth/keys", headers=admin).json()
    assert any(k["name"] == "ci" for k in listed["keys"])
    deleted = client.delete("/api/auth/keys/ci", headers=admin)
    assert deleted.status_code == 200
    assert client.delete("/api/auth/keys/ci", headers=admin).status_code == 404


def test_auth_config_and_me_public(client):
    config = client.get("/api/auth/config").json()
    assert config["enabled"] is False
    assert config["oidc"]["enabled"] is False
    me = client.get("/api/auth/me").json()
    assert me["role"] == "admin"  # auth disabled = local single-operator


def test_oidc_endpoints_are_graceful_when_unconfigured(client):
    assert client.get("/api/auth/login").status_code == 400
    assert client.get("/api/auth/login-url").status_code == 400


def test_oidc_callback_issues_session(client, monkeypatch):
    monkeypatch.setenv("H4K_AUTH_ENABLED", "1")
    monkeypatch.setenv("H4K_API_KEYS", "root:admin:root-secret")
    monkeypatch.setenv("H4K_OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("H4K_OIDC_CLIENT_ID", "h4k-client")
    monkeypatch.setenv("H4K_OIDC_REDIRECT_URI", "http://testserver/api/auth/callback")
    main_module.reset_auth_cache()

    class _FakeOidc:
        def __init__(self, _config):
            pass

        def authorization_url(self, redirect_uri=""):
            return f"https://idp.test/auth?redirect_uri={redirect_uri}"

        def exchange(self, code, state):
            return {"tokens": {}, "claims": {"sub": "u1", "email": "u@test"}}

        def role_for(self, claims):
            return "operator"

    import routers.auth as auth_router_module

    auth_router_module._OIDC_CLIENT = None
    auth_router_module._OIDC_KEY = None
    monkeypatch.setattr(auth_router_module, "_OIDC", _FakeOidc)
    start = client.get("/api/auth/login", follow_redirects=False)
    assert start.status_code == 307
    assert start.headers["location"].startswith("https://idp.test/auth")
    callback = client.get(
        "/api/auth/callback?code=abc&state=xyz", follow_redirects=False
    )
    assert callback.status_code == 303
    assert callback.cookies.get(auth.SESSION_COOKIE)
    me = client.get("/api/auth/me")
    assert me.json()["role"] == "operator"
    client.cookies.clear()


def test_redirect_uri_and_bearer_helpers(monkeypatch):
    from types import SimpleNamespace

    import routers.auth as auth_router

    request = SimpleNamespace(base_url="http://h4k.test/")
    monkeypatch.delenv("H4K_OIDC_REDIRECT_URI", raising=False)
    assert auth_router._redirect_uri(request) == "http://h4k.test/api/auth/callback"
    assert auth_router._redirect_uri(request, "https://x/cb") == "https://x/cb"
    monkeypatch.setenv("H4K_OIDC_REDIRECT_URI", "https://env/cb")
    assert auth_router._redirect_uri(request) == "https://env/cb"
    assert auth_router.parse_bearer("Bearer abc") == "abc"
    assert auth_router.parse_bearer(" plain ") == "plain"


def test_verify_requires_a_credential_principal():
    from types import SimpleNamespace

    import routers.auth as auth_router

    anonymous = SimpleNamespace(
        state=SimpleNamespace(
            principal=auth.Principal("anon", "viewer", method="anonymous")
        )
    )
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        auth_router.auth_verify(anonymous)
    assert exc.value.status_code == 401


def test_callback_branch_errors(client, monkeypatch):
    monkeypatch.setenv("H4K_AUTH_ENABLED", "1")
    monkeypatch.setenv("H4K_API_KEYS", "root:admin:secret")
    monkeypatch.setenv("H4K_OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("H4K_OIDC_CLIENT_ID", "h4k")
    main_module.reset_auth_cache()
    import routers.auth as auth_router

    auth_router._OIDC_CLIENT = None
    auth_router._OIDC_KEY = None

    assert client.get("/api/auth/callback?error=denied").status_code == 401
    assert client.get("/api/auth/callback").status_code == 400

    class _BadOidc:
        def __init__(self, _config):
            pass

        def exchange(self, code, state):
            raise auth.AuthError(401, "bad exchange")

    monkeypatch.setattr(auth_router, "_OIDC", _BadOidc)
    assert client.get("/api/auth/callback?code=x&state=y").status_code == 401


def test_login_branch_errors(client, monkeypatch):
    monkeypatch.setenv("H4K_AUTH_ENABLED", "1")
    monkeypatch.setenv("H4K_API_KEYS", "root:admin:secret")
    monkeypatch.setenv("H4K_OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("H4K_OIDC_CLIENT_ID", "h4k")
    main_module.reset_auth_cache()
    import routers.auth as auth_router

    auth_router._OIDC_CLIENT = None
    auth_router._OIDC_KEY = None

    class _BadOidc:
        def __init__(self, _config):
            pass

        def authorization_url(self, redirect):
            raise auth.AuthError(502, "discovery failed")

    monkeypatch.setattr(auth_router, "_OIDC", _BadOidc)
    assert client.get("/api/auth/login").status_code == 502


def test_key_endpoints_reject_bad_role(client, monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_AUTH_ENABLED", "1")
    monkeypatch.setenv("H4K_API_KEYS", "root:admin:secret")
    monkeypatch.setenv("H4K_API_KEYS_FILE", str(tmp_path / "keys.json"))
    main_module.reset_auth_cache()
    r = client.post(
        "/api/auth/keys",
        headers={"X-API-Key": "secret"},
        json={"name": "x", "role": "root"},
    )
    assert r.status_code == 400
    assert (
        client.delete(
            "/api/auth/keys/nope", headers={"X-API-Key": "secret"}
        ).status_code
        == 404
    )
    assert (
        client.get("/api/auth/verify", headers={"X-API-Key": "secret"}).status_code
        == 200
    )


def test_oidc_login_url_with_fake_client(client, monkeypatch):
    monkeypatch.setenv("H4K_AUTH_ENABLED", "1")
    monkeypatch.setenv("H4K_API_KEYS", "root:admin:secret")
    monkeypatch.setenv("H4K_OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("H4K_OIDC_CLIENT_ID", "h4k")
    main_module.reset_auth_cache()
    import routers.auth as auth_router

    auth_router._OIDC_CLIENT = None
    auth_router._OIDC_KEY = None

    class _Fake:
        def __init__(self, _config):
            pass

        def authorization_url(self, redirect):
            return f"https://idp/auth?redirect={redirect}"

    monkeypatch.setattr(auth_router, "_OIDC", _Fake)
    r = client.get("/api/auth/login-url", headers={"X-API-Key": "secret"})
    assert r.status_code == 200
    assert r.json()["url"].startswith("https://idp/auth")


def test_jwt_verification_es256(monkeypatch):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "kid": "ec1",
        "crv": "P-256",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }
    header = _b64(json.dumps({"alg": "ES256", "kid": "ec1"}).encode())
    payload = _b64(
        json.dumps(
            {"sub": "ec-user", "aud": "h4k", "exp": int(time.time()) + 300}
        ).encode()
    )
    signature = private.sign(f"{header}.{payload}".encode(), ec.ECDSA(hashes.SHA256()))
    token = f"{header}.{payload}.{_b64(signature)}"

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"keys": [jwk]}).encode()

    monkeypatch.setattr(auth.urllib.request, "urlopen", lambda *a, **k: _Resp())
    claims = auth.verify_jwt(token, {"jwks_uri": "https://idp/jwks"}, audience="h4k")
    assert claims["sub"] == "ec-user"


def test_mask_key_and_config_helpers(tmp_path, monkeypatch):
    assert auth.mask_key("short") == "***"
    assert auth.mask_key("h4k_abcdefghijklmnop").startswith("h4k_ab")
    assert auth.OidcConfig(issuer="x", client_id="").enabled is False
    assert auth.OidcConfig(issuer="x", client_id="y").enabled is True
    bad = tmp_path / "keys.json"
    bad.write_text("{not json", encoding="utf-8")
    assert auth._read_key_file(bad) == []
    assert auth._runtime_dir().name == "data"
    limiter = auth.RateLimiter()
    limiter.check("x", 1)
    limiter.reset()
    assert limiter.check("x", 1).allowed


def test_oidc_fetch_json_without_tls_verification(monkeypatch):
    config = auth.OidcConfig(issuer="https://idp.test", client_id="c", verify_tls=False)
    client = auth.OidcClient(config)

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"authorization_endpoint": "a", "token_endpoint": "t", "jwks_uri": "j"}'

    class _Ctx:
        check_hostname = True
        verify_mode = None

    import ssl as ssl_module

    monkeypatch.setattr(ssl_module, "create_default_context", lambda: _Ctx())
    monkeypatch.setattr(auth.urllib.request, "urlopen", lambda *a, **k: _Resp())
    assert client.discover()["authorization_endpoint"] == "a"
