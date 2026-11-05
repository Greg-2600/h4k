"""Backlog #49: header/cookie session fuzz — auth-bypass leads."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from services.sessionfuzz import probe_session, sandbox_result, to_ledger

MODE = "strict"


class _Handler(BaseHTTPRequestHandler):
    def _answer(self) -> None:
        cookie = self.headers.get("Cookie", "")
        auth = self.headers.get("Authorization", "")
        authed = "session=valid" in cookie or auth == "Bearer valid"
        qs = parse_qs(urlsplit(self.path).query)
        privileged = qs.get("role") == ["admin"]
        if MODE == "open":
            authed = True
        if "session=bypass" in cookie:
            authed, privileged = True, True
        if "/private" in self.path and not authed:
            body = b"login required"
            self.send_response(401)
        elif privileged:
            body = b"Admin panel for root"
            self.send_response(200)
        elif authed:
            body = b"Welcome back Logout"
            self.send_response(200)
        else:
            body = b"login required"
            self.send_response(401)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._answer()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._answer()

    def log_message(self, *args: Any) -> None:
        return


def _server() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_strict_server_enforces() -> None:
    global MODE
    MODE = "strict"
    srv, base = _server()
    try:
        out = probe_session(
            f"{base}/private",
            cookies={"session": "valid"},
            authed_marker="Logout",
            privileged_marker="Admin panel",
            timeout=5.0,
        )
        assert out["probe_count"] > 10
        found = {p["name"] for p in out["probes"] if p["verdict"] == "FINDING"}
        assert found == {"inject-role-param"}  # stub honors role=admin params
        assert out["clean"] is False
        assert out["finding_count"] == 1
    finally:
        srv.shutdown()
        srv.server_close()


def test_open_server_flagged() -> None:
    global MODE
    MODE = "open"
    srv, base = _server()
    try:
        out = probe_session(
            f"{base}/private",
            cookies={"session": "valid"},
            authed_marker="Logout",
            privileged_marker="Admin panel",
            timeout=5.0,
        )
        assert out["clean"] is False
        by_probe = {p["name"]: p for p in out["probes"]}
        assert by_probe["strip-all"]["verdict"] == "FINDING"
        assert by_probe["strip-all"]["severity"] == "CRITICAL"
    finally:
        MODE = "strict"
        srv.shutdown()
        srv.server_close()


def test_privilege_escalation_path() -> None:
    global MODE
    MODE = "strict"
    srv, base = _server()
    try:
        out = probe_session(
            f"{base}/private?x=1",
            headers={"Authorization": "Bearer valid"},
            authed_marker="Logout",
            privileged_marker="Admin panel",
            timeout=5.0,
        )
        by_probe = {p["name"]: p for p in out["probes"]}
        assert by_probe["inject-role-param"]["verdict"] == "FINDING"
        assert by_probe["inject-role-param"]["severity"] == "HIGH"
    finally:
        srv.shutdown()
        srv.server_close()


def test_validation() -> None:
    import pytest

    with pytest.raises(ValueError):
        probe_session("not-a-url", authed_marker="x")
    with pytest.raises(ValueError):
        probe_session("http://h/", authed_marker="  ")
    with pytest.raises(ValueError):
        probe_session("http://127.0.0.1:1/", authed_marker="x", timeout=1.0)


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("http://lab.local/private")
    assert res["finding_count"] == 2 and res["clean"] is False
    rows = to_ledger("10.10.10.77", res["url"], res["findings"])
    assert len(rows) == 2
    assert rows[0]["module"] == "session-fuzz"
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


def test_session_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/session/fuzz",
        json={
            "url": "http://10.10.10.99/private",
            "cookies": {"session": "valid"},
            "authed_marker": "Logout",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0

    # Non-URL target, and missing marker, are 400s even in sandbox.
    assert (
        c.post(
            "/api/session/fuzz",
            json={"url": "nope", "authed_marker": "x"},
        ).status_code
        == 400
    )
    assert (
        c.post(
            "/api/session/fuzz",
            json={"url": "http://h/", "authed_marker": " "},
        ).status_code
        == 400
    )

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/session/fuzz",
        json={
            "url": "http://10.10.10.77/private",
            "cookies": {"session": "valid"},
            "authed_marker": "Logout",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "session-fuzz strip-all" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/session/fuzz",
            json={"url": "http://h/", "authed_marker": "x", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope hostname is reported, never stored.
    r = c.post(
        "/api/session/fuzz",
        json={
            "url": "http://192.0.2.9/private",
            "cookies": {"session": "valid"},
            "authed_marker": "Logout",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
