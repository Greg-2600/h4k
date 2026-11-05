"""Backlog #42: cloud metadata SSRF pack — 169.254 probes, opt-in."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from services.ssrf_pack import (
    PAYLOADS,
    _fetch,
    _verdict,
    probe_target,
    sandbox_result,
    to_ledger,
)


def test_pack_and_markers() -> None:
    assert len(PAYLOADS) == 10
    names = [n for n, _ in PAYLOADS]
    assert "aws-meta" in names and "hex-ip" in names
    verdict, _ = _verdict("ami-id instance-id here")
    assert verdict == "VULNERABLE"
    assert _verdict("ordinary page")[0] == "SAFE"


def test_probe_validation() -> None:
    import pytest

    with pytest.raises(ValueError):
        probe_target("")
    with pytest.raises(ValueError):
        probe_target("ftp://x/y")
    with pytest.raises(ValueError):
        probe_target("http://x/", method="DELETE")
    with pytest.raises(ValueError):
        probe_target("http://x/", payload_names=["nope"])


class _Handler(BaseHTTPRequestHandler):
    leak = False

    def _answer(self, query: str) -> None:
        params = parse_qs(urlsplit(self.path).query if "?" in self.path else query)
        _ = params
        body = (
            b"ami-id: i-123 instance-id: i-123" if type(self).leak else b"static page"
        )
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._answer(urlsplit(self.path).query)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self._answer(self.rfile.read(length).decode())

    def log_message(self, *args: Any) -> None:
        return


def _server(leak: bool) -> tuple[HTTPServer, int]:
    _Handler.leak = leak
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    return srv, srv.server_address[1]


def test_probe_live_safe_and_vulnerable() -> None:
    srv, port = _server(leak=False)
    try:
        out = probe_target(f"http://127.0.0.1:{port}/fetch", param="url", timeout=5.0)
        assert out["probe_count"] == 10 and out["at_risk"] is False
        assert out["vulnerable_count"] == 0
    finally:
        srv.shutdown()
        srv.server_close()
    srv, port = _server(leak=True)
    try:
        out = probe_target(
            f"http://127.0.0.1:{port}/fetch",
            param="u",
            method="POST",
            payload_names=["aws-meta", "azure-imds"],
            timeout=5.0,
        )
        assert out["probe_count"] == 2 and out["at_risk"] is True
        assert out["vulnerable"] == ["aws-meta", "azure-imds"]
        assert to_ledger("h", out["target"], out["probes"] + [{"verdict": "SAFE"}])
        rows = to_ledger("h", out["target"], out["probes"])
        assert len(rows) == 2 and rows[0]["severity"] == "CRITICAL"
        assert rows[0]["cwe"] == "CWE-918"
    finally:
        srv.shutdown()
        srv.server_close()


def test_fetch_never_raises() -> None:
    res = _fetch("http://127.0.0.1:1/none", "GET", "url", "x", timeout=1.0)
    assert res["status"] is None and "error" in res


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("http://lab.local/fetch")
    assert res["vulnerable_count"] == 1 and res["at_risk"] is True
    rows = to_ledger("10.10.10.77", res["target"], res["probes"])
    assert len(rows) == 1 and rows[0]["module"] == "ssrf-pack"
    assert to_ledger("h", "t", []) == []


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


def test_ssrf_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/ssrf/probe",
        json={"target": "http://10.10.10.99/fetch", "param": "url"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["vulnerable_count"] == 1 and body["ingested"] == 0

    # Non-URL target is a 400 even in sandbox.
    assert (
        c.post(
            "/api/ssrf/probe", json={"target": "not-a-url", "param": "url"}
        ).status_code
        == 400
    )

    # Ledger into a seeded engagement: hostname 10.10.10.99 is in scope.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/ssrf/probe",
        json={
            "target": "http://10.10.10.77/fetch",
            "param": "url",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 1
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "ssrf aws-meta" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/ssrf/probe",
            json={"target": "http://h/x", "param": "u", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope hostname is reported, never stored.
    r = c.post(
        "/api/ssrf/probe",
        json={
            "target": "http://192.0.2.9/fetch",
            "param": "url",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
