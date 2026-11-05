"""Backlog #57: rate-limit-aware fuzz — 429 backoff + jitter."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from services.ratefuzz import (
    _retry_after_seconds,
    probe_rate_limit,
    sandbox_result,
    to_ledger,
)

_hits = {"n": 0}


class _Handler(BaseHTTPRequestHandler):
    mode = "open"

    def do_GET(self) -> None:
        _hits["n"] += 1
        if type(self).mode == "limited" and _hits["n"] % 3 == 0:
            body = b"slow down"
            self.send_response(429)
            self.send_header("Retry-After", "1")
        else:
            body = b"ok"
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        return


def _server(mode: str) -> tuple[HTTPServer, str]:
    _Handler.mode = mode
    _hits["n"] = 0
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/api"


def test_retry_after_parse() -> None:
    assert _retry_after_seconds("5", 0.0) == 5.0
    assert _retry_after_seconds("99999", 0.0) == 30.0
    assert _retry_after_seconds("", 0.0) is None
    assert _retry_after_seconds("not-a-date", 0.0) is None
    assert _retry_after_seconds("Wed, 21 Oct 2099 07:28:00 GMT", 0.0) is not None


def test_open_server_no_throttle() -> None:
    srv, url = _server("open")
    try:
        slept: list[float] = []
        out = probe_rate_limit(url, requests=9, timeout=5.0, seed=1, sleep=slept.append)
        assert out["throttled"] == 0 and slept == []
        assert out["clean"] is False  # no throttle observed = the finding
        assert out["finding_count"] == 1
        assert all(t["action"] == "pass" for t in out["timeline"])
    finally:
        srv.shutdown()
        srv.server_close()


def test_limited_server_backs_off() -> None:
    srv, url = _server("limited")
    try:
        slept: list[float] = []
        out = probe_rate_limit(url, requests=9, timeout=5.0, seed=1, sleep=slept.append)
        assert out["throttled"] == 3
        assert len(slept) == 3 and all(s >= 1.0 for s in slept)
        assert out["clean"] is True  # honored throttles are not findings
        assert out["finding_count"] == 1  # the INFO note still listed
        assert out["honored_waits"] == [round(s, 2) for s in slept]
    finally:
        srv.shutdown()
        srv.server_close()


def test_unreachable_stops() -> None:
    out = probe_rate_limit("http://127.0.0.1:1/", requests=5, timeout=1.0)
    assert out["requests"] == 1
    assert out["timeline"][0]["action"] == "stop"


def test_validation() -> None:
    import pytest

    with pytest.raises(ValueError):
        probe_rate_limit("ftp://x/")


def test_sandbox_and_ledger() -> None:
    res = sandbox_result("http://lab.local/api")
    assert res["finding_count"] == 1 and res["clean"] is False
    rows = to_ledger("10.10.10.77", res["url"], res["findings"])
    assert len(rows) == 1 and rows[0]["cwe"] == "CWE-799"
    # INFO findings (honored throttles) never ledger.
    assert to_ledger("h", "u", [{"severity": "INFO"}]) == []
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


def test_rate_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/rate_fuzz", json={"url": "http://10.10.10.99/api"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 1 and body["ingested"] == 0

    assert c.post("/api/rate_fuzz", json={"url": "nope"}).status_code == 400

    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/rate_fuzz",
        json={"url": "http://10.10.10.77/api", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 1
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "rate-limit missing" in str(vulns)

    assert (
        c.post(
            "/api/rate_fuzz", json={"url": "http://h/", "engagement_id": "nope"}
        ).status_code
        == 404
    )

    r = c.post(
        "/api/rate_fuzz",
        json={"url": "http://192.0.2.9/api", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
