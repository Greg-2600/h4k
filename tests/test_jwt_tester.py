"""Backlog #50: JWT tester — crack + alg-confusion, lab-only."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from services.jwt_tester import (
    audit_token,
    confusion_test,
    crack_hmac,
    decode_token,
    sandbox_result,
    to_ledger,
)


def _b64e(obj: Any) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _hs(payload: dict[str, Any], secret: str, alg: str = "HS256") -> str:
    head = _b64e({"alg": alg, "typ": "JWT"})
    body = _b64e(payload)
    hashmod = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }[alg]
    sig = (
        base64.urlsafe_b64encode(
            hmac.new(secret.encode(), f"{head}.{body}".encode(), hashmod).digest()
        )
        .decode()
        .rstrip("=")
    )
    return f"{head}.{body}.{sig}"


NOW = int(time.time())
GOOD = _hs({"sub": "u", "exp": NOW + 3600}, "a-strong-secret-9x!")
WEAK = _hs({"sub": "u", "exp": NOW + 3600}, "secret")
NONE_TOK = f"{_b64e({'alg': 'none'})}.{_b64e({'sub': 'u'})}."
NOEXP = _hs({"sub": "u"}, "a-strong-secret-9x!")
LONG = _hs({"sub": "u", "exp": NOW + 90 * 24 * 3600}, "a-strong-secret-9x!")


def _kid_token() -> str:
    head = _b64e({"alg": "HS256", "kid": "../../etc/passwd"})
    body = _b64e({"sub": "u", "exp": NOW + 60})
    return f"{head}.{body}.x"


def test_decode_rejects() -> None:
    import pytest

    with pytest.raises(ValueError):
        decode_token("not-a-jwt")
    with pytest.raises(ValueError):
        decode_token("a.b")
    assert decode_token(GOOD)["header"]["alg"] == "HS256"


def test_audit_flags() -> None:
    out = audit_token(NONE_TOK, crack=False)
    assert any(
        f["severity"] == "CRITICAL" and "unsigned" in f["title"]
        for f in out["findings"]
    )
    out = audit_token(NOEXP, crack=False)
    assert any("never expire" in f["title"] for f in out["findings"])
    out = audit_token(LONG, crack=False)
    assert any("exceeds 30 days" in f["title"] for f in out["findings"])
    out = audit_token(_kid_token(), crack=False)
    assert any("kid" in f["title"] for f in out["findings"])
    out = audit_token(GOOD, crack=False)
    assert out["clean"] is True


def test_crack_weak_and_strong() -> None:
    assert crack_hmac(WEAK, ["x", "secret"], "HS256") == {
        "cracked": True,
        "secret": "secret",
        "attempts": 2,
    }
    out = crack_hmac(GOOD, ["x", "y"], "HS256")
    assert out == {"cracked": False, "attempts": 2}
    assert crack_hmac(GOOD, ["x"], "RS256")["error"].startswith("unsupported")
    out = audit_token(WEAK)
    assert any("cracked" in f["title"] for f in out["findings"])


MODE = "strict"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        ok = token == GOOD
        if MODE == "open" and token:
            try:
                head = json.loads(
                    base64.urlsafe_b64decode(token.split(".")[0] + "==").decode()
                )
                ok = ok or head.get("alg") == "none" or token.endswith(".")
            except (ValueError, IndexError):
                pass
        body = b"Welcome Logout" if ok else b"login required"
        self.send_response(200 if ok else 401)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        return


def _server() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/api"


def test_confusion_strict() -> None:
    global MODE
    MODE = "strict"
    srv, url = _server()
    try:
        out = confusion_test(url, GOOD, "Logout", timeout=5.0)
        assert out["clean"] is True
        assert {p["verdict"] for p in out["probes"]} == {"SAFE"}
    finally:
        srv.shutdown()
        srv.server_close()


def test_confusion_open_and_baseline() -> None:
    global MODE
    MODE = "open"
    srv, url = _server()
    try:
        out = confusion_test(url, GOOD, "Logout", timeout=5.0)
        by_probe = {p["name"]: p for p in out["probes"]}
        assert by_probe["alg-none"]["verdict"] == "FINDING"
        assert by_probe["alg-none"]["severity"] == "CRITICAL"
        out = confusion_test(url, GOOD, "Nope", timeout=5.0)
        assert "check token/marker" in out["note"]
    finally:
        MODE = "strict"
        srv.shutdown()
        srv.server_close()


def test_confusion_validation() -> None:
    import pytest

    with pytest.raises(ValueError):
        confusion_test("ftp://x", GOOD, "m")
    with pytest.raises(ValueError):
        confusion_test("http://h/", GOOD, " ")
    with pytest.raises(ValueError):
        confusion_test("http://127.0.0.1:1/", GOOD, "m", timeout=1.0)


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("http://lab.local/api")
    assert res["finding_count"] == 2 and res["clean"] is False
    rows = to_ledger("10.10.10.77", res["url"], res["findings"])
    assert len(rows) == 2
    assert rows[0]["module"] == "jwt-tester"
    assert rows[0]["cwe"] == "CWE-287"
    assert to_ledger("h", "u", []) == []


def _client(tmp_path: Any, monkeypatch: Any) -> Any:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_jwt_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/jwt/test", json={"token": GOOD, "host": "h"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0

    # Malformed token is a 400 even in sandbox.
    assert c.post("/api/jwt/test", json={"token": "junk"}).status_code == 400
    # Empty token is a 422 (required field).
    assert c.post("/api/jwt/test", json={"token": ""}).status_code in (400, 422)

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/jwt/test",
        json={
            "token": GOOD,
            "url": "http://10.10.10.77/api",
            "authed_marker": "x",
            "host": "10.10.10.77",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "jwt " in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/jwt/test",
            json={"token": GOOD, "host": "h", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope URL host is reported, never stored.
    r = c.post(
        "/api/jwt/test",
        json={
            "token": GOOD,
            "url": "http://192.0.2.9/api",
            "authed_marker": "x",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
