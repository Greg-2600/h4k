"""Backlog #54: crash bisection — input halve to minimal trigger."""

from __future__ import annotations

import base64
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from services.bisect import bisect_input, ddmin, sandbox_result


def test_ddmin_marker() -> None:
    data = b"AA" * 20 + b"TRIGGER" + b"BB" * 20
    out = ddmin(data, lambda c: b"TRIGGER" in c)
    assert out["minimal"] == b"TRIGGER"
    assert out["original_size"] == len(data) and out["minimal_size"] == 7
    assert out["rounds"] >= 1 and out["trace"]


def test_ddmin_uninteresting() -> None:
    with pytest.raises(ValueError):
        ddmin(b"abc", lambda c: False)
    with pytest.raises(ValueError):
        ddmin(b"", lambda c: True)


def test_ddmin_single_byte() -> None:
    out = ddmin(b"X", lambda c: c == b"X")
    assert out["minimal"] == b"X" and out["minimal_size"] == 1


class _Handler(BaseHTTPRequestHandler):
    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if b"TRIG" in body:
            payload, code = b"boom", 500
        else:
            payload, code = b"ok", 200
        self.send_response(code)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        self._answer()

    def log_message(self, *args: Any) -> None:
        return


def _server() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/crash"


def test_http_bisect_live() -> None:
    srv, url = _server()
    try:
        out = bisect_input(b"padding-TRIG-padding", url=url, status_ge=500, timeout=5.0)
        assert out["mode"] == "http"
        minimal = base64.b64decode(out["minimal_b64"])
        assert out["minimal_size"] == len(minimal)
        assert b"TRIG" in minimal
        assert out["minimal_size"] <= 8
        assert out["still_crashes"] is True
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_bisect_marker_mode() -> None:
    out = bisect_input(b"xxMARKERyy", marker="MARKER")
    assert out["mode"] == "marker"
    assert base64.b64decode(out["minimal_b64"]) == b"MARKER"


def test_validation() -> None:
    with pytest.raises(ValueError):
        bisect_input(b"", marker="x")
    with pytest.raises(ValueError):
        bisect_input(b"abc", marker="zzz")
    with pytest.raises(ValueError):
        bisect_input(b"abc", url="ftp://x", marker="a")
    with pytest.raises(ValueError):
        bisect_input(b"abc")
    with pytest.raises(ValueError):
        bisect_input(b"x" * (1_000_001), marker="x")
    with pytest.raises(ValueError):
        bisect_input(b"abc", url="http://127.0.0.1:1/", timeout=1.0)
    with pytest.raises(ValueError):
        bisect_input(b"abc", url="http://127.0.0.1:1/", marker="zzz", timeout=1.0)


def test_sandbox_shapes() -> None:
    res = sandbox_result()
    assert res["minimal_text"] == "TRIGGER"
    assert res["still_crashes"] is True and res["rounds"] > 0


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


def test_bisect_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/fuzz/bisect", json={"input": "AAATRIGGERBBB", "marker": "TRIGGER"})
    assert r.status_code == 200
    body = r.json()
    assert body["minimal_text"] == "TRIGGER" or body["sandbox"] is True
    assert body["still_crashes"] is True

    assert c.post("/api/fuzz/bisect", json={}).status_code == 400
    assert c.post("/api/fuzz/bisect", json={"input_b64": "!!!"}).status_code == 400
    assert (
        c.post("/api/fuzz/bisect", json={"input": "x", "marker": "zzz"}).status_code
        == 400
    )
