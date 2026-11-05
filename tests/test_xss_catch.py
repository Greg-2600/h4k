"""Backlog #28: XSS catch lab (loopback catcher + replay)."""

from __future__ import annotations

import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from services import xss_catch


def _get(port: int, path: str = "/hook?token=abc123", cookie: str = "") -> int:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Cookie": cookie} if cookie else {},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()
        return int(getattr(resp, "status", 0) or 0)


def test_catch_roundtrip() -> None:
    info = xss_catch.start()
    try:
        assert info["running"] is True and info["port"] > 0
        code = _get(info["port"], "/hook?token=abc123", "session=xyz")
        assert code == 204
        hits = xss_catch.hits()
        assert len(hits) >= 1
        last = hits[-1]
        assert last["token"] == "abc123" and last["cookie"] == "session=xyz"
        assert last["client"] == "127.0.0.1"
        flushed = xss_catch.hits(clear=True)
        assert len(flushed) >= 1
        assert xss_catch.hits() == []
    finally:
        assert xss_catch.stop()["running"] is False


def test_replay_compares_baseline_and_cookie() -> None:
    class Echo(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"authed!" if self.headers.get("Cookie") else b"login"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Echo)
    port = server.server_address[1]
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    )
    thread.start()
    try:
        out = xss_catch.replay(f"http://127.0.0.1:{port}/", "session=xyz")
        assert out["session_live"] is True
        assert out["authed"]["length"] > out["baseline"]["length"]
        dead = xss_catch.replay("http://127.0.0.1:1/", "x=1")
        assert dead["session_live"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_sandbox_hits() -> None:
    hits = xss_catch.sandbox_hits()
    assert hits and hits[0]["token"] == "sandbox-token"


def test_xss_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.post("/api/xss/catch/start", json={})
    assert r.status_code == 200 and r.json()["running"] is True
    r = c.get("/api/xss/catch/hits")
    assert r.status_code == 200 and r.json()["count"] >= 1
    r = c.post("/api/xss/replay", json={})
    assert r.status_code == 400
