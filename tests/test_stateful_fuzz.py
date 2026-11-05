"""Backlog #56: stateful fuzz — login → authed-flow fuzz."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlsplit

from services.stateful_fuzz import fuzz_flow, login, sandbox_result, to_ledger


class _Handler(BaseHTTPRequestHandler):
    def _authed(self) -> bool:
        cookie = self.headers.get("Cookie", "")
        auth = self.headers.get("Authorization", "")
        return "session=abc" in cookie or auth == "Bearer tok123"

    def _answer(self, query: str, body: bytes) -> None:
        blob = (body + b" " + query.encode()).decode(errors="replace")
        if "A" * 100 in blob:
            payload, code = b"boom", 500
        elif "%x" in blob or "${7*7}" in blob:
            payload, code = b"exception: Traceback bad format", 200
        elif not self._authed():
            payload, code = b"login required", 401
        else:
            payload, code = b"ok Logout", 200
        self.send_response(code)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.path == "/login":
            try:
                creds = json.loads(raw.decode())
            except ValueError:
                creds = {}
            if creds.get("user") == "u" and creds.get("pass") == "p":
                body = b'{"token": "tok123"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=abc; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(403)
                self.send_header("Content-Length", "7")
                self.end_headers()
                self.wfile.write(b"denied")
            return
        self._answer(urlsplit(self.path).query, raw)

    def do_GET(self) -> None:
        self._answer(urlsplit(self.path).query, b"")

    def log_message(self, *args: Any) -> None:
        return


def _server() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_login_harvest() -> None:
    srv, base = _server()
    try:
        out = login(f"{base}/login", body={"user": "u", "pass": "p"})
        assert out["cookies"] == {"session": "abc"}
        out = login(
            f"{base}/login",
            body={"user": "u", "pass": "p"},
            json_field="token",
        )
        assert out["token"] == "tok123"
        import pytest

        with pytest.raises(ValueError):
            login(f"{base}/login", body={"user": "x", "pass": "y"})
        with pytest.raises(ValueError):
            login("not-a-url")
    finally:
        srv.shutdown()
        srv.server_close()


def test_fuzz_flow_live() -> None:
    srv, base = _server()
    try:
        out = fuzz_flow(
            f"{base}/login",
            login_body={"user": "u", "pass": "p"},
            steps=[
                {"method": "GET", "url": f"{base}/items", "fields": ["query:q"]},
                {
                    "method": "POST",
                    "url": f"{base}/items",
                    "fields": ["body:name"],
                    "body": {"name": "x"},
                },
            ],
            iterations=12,
            timeout=5.0,
        )
        assert out["logins"] == 12 and out["iterations"] == 12
        signals = {c["signal"] for c in out["candidates"]}
        assert "server-error" in signals
        assert "error-text" in signals
    finally:
        srv.shutdown()
        srv.server_close()


def test_fuzz_validation() -> None:
    import pytest

    with pytest.raises(ValueError):
        fuzz_flow("http://h/login", steps=[])
    with pytest.raises(ValueError):
        fuzz_flow("http://h/login", steps=[{"method": "GET"}])
    with pytest.raises(ValueError):
        fuzz_flow("ftp://h/login", steps=[{"url": "http://h/"}])


def test_ledger_skips_session_lost() -> None:
    rows = to_ledger(
        "h",
        "b",
        [
            {
                "mutation": "m",
                "step": "s",
                "signal": "session-lost",
                "sent": "x",
                "evidence": "e",
                "status": 200,
            },
            {
                "mutation": "m",
                "step": "s",
                "signal": "server-error",
                "sent": "x",
                "evidence": "e",
                "status": 500,
            },
        ],
    )
    assert len(rows) == 1 and rows[0]["cwe"] == "CWE-20"
    assert to_ledger("h", "b", []) == []


def test_sandbox_shapes() -> None:
    res = sandbox_result("http://lab.local")
    assert res["candidate_count"] == 2 and res["clean"] is False


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


FLOW = [
    {"method": "GET", "url": "http://10.10.10.77/items", "fields": ["query:q"]},
]


def test_stateful_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/stateful_fuzz",
        json={
            "login_url": "http://10.10.10.99/login",
            "login_body": {"user": "u", "pass": "p"},
            "flow": FLOW,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["candidate_count"] == 2 and body["ingested"] == 0

    assert (
        c.post("/api/stateful_fuzz", json={"login_url": "x", "flow": FLOW}).status_code
        == 400
    )
    assert (
        c.post(
            "/api/stateful_fuzz", json={"login_url": "http://h/login", "flow": []}
        ).status_code
        == 400
    )

    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/stateful_fuzz",
        json={
            "login_url": "http://10.10.10.99/login",
            "login_body": {"user": "u", "pass": "p"},
            "flow": [
                {
                    "method": "GET",
                    "url": "http://10.10.10.77/items",
                    "fields": ["query:q"],
                }
            ],
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "stateful-fuzz" in str(vulns)

    assert (
        c.post(
            "/api/stateful_fuzz",
            json={"login_url": "http://h/login", "flow": FLOW, "engagement_id": "nope"},
        ).status_code
        == 404
    )

    r = c.post(
        "/api/stateful_fuzz",
        json={
            "login_url": "http://192.0.2.9/login",
            "login_body": {"user": "u", "pass": "p"},
            "flow": [
                {
                    "method": "GET",
                    "url": "http://192.0.2.9/items",
                    "fields": ["query:q"],
                }
            ],
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
