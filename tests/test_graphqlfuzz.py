"""Backlog #47: GraphQL introspection + fuzz — field/depth probes."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from services.graphqlfuzz import (
    _parse_schema,
    probe_endpoint,
    sandbox_result,
    to_ledger,
)

SCHEMA_DOC = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {"name": "Query", "fields": [{"name": "user"}, {"name": "users"}]},
                {"name": "Mutation", "fields": [{"name": "login"}]},
                {"name": "User", "fields": [{"name": "id"}, {"name": "name"}]},
            ],
        }
    }
}

MODES: dict[str, Any] = {"depth": "open", "batch": "open", "leak": False}


class _Handler(BaseHTTPRequestHandler):
    def _json(self, obj: Any, code: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode()
        try:
            doc = json.loads(raw)
        except ValueError:
            self._json({"errors": [{"message": "bad json"}]}, 400)
            return
        if isinstance(doc, list):
            if MODES["batch"] == "open":
                self._json([{"data": {"__typename": "Query"}} for _ in doc])
            else:
                self._json({"errors": [{"message": "batching disabled"}]}, 400)
            return
        query = doc.get("query", "")
        if "__schema" in query:
            self._json(SCHEMA_DOC)
        elif query.count("{") >= 10:
            if MODES["depth"] == "limited":
                self._json({"errors": [{"message": "max depth exceeded"}]})
            else:
                self._json({"data": {"user": {"user": "deep"}}})
        elif "(x:" in query:
            if MODES["leak"]:
                self._json({"errors": [{"message": "exception: Traceback boom"}]})
            else:
                self._json({"data": {"user": None}})
        else:
            self._json({"data": {"__typename": "Query"}})

    def log_message(self, *args: Any) -> None:
        return


def _server() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/graphql"


def test_parse_schema() -> None:
    out = _parse_schema(SCHEMA_DOC)
    assert out["queries"] == ["user", "users"]
    assert out["mutations"] == ["login"]
    assert out["types"]["User"] == ["id", "name"]
    assert _parse_schema({}) == {"queries": [], "mutations": [], "types": {}}


def test_open_server_all_findings() -> None:
    MODES.update(depth="open", batch="open", leak=True)
    srv, url = _server()
    try:
        out = probe_endpoint(url, depth=12, batch=5, timeout=5.0)
        by_probe = {p["name"]: p for p in out["probes"]}
        assert by_probe["introspection"]["verdict"] == "FINDING"
        assert by_probe["depth"]["verdict"] == "FINDING"
        assert by_probe["batching"]["verdict"] == "FINDING"
        assert by_probe["field-fuzz"]["verdict"] == "FINDING"
        assert out["finding_count"] == 4
        assert out["clean"] is False
    finally:
        srv.shutdown()
        srv.server_close()


def test_hardened_server_clean() -> None:
    MODES.update(depth="limited", batch="closed", leak=False)
    srv, url = _server()
    try:
        out = probe_endpoint(url, depth=12, batch=5, timeout=5.0)
        assert out["clean"] is False  # schema disclosure alone is a finding
        assert {p["name"]: p["verdict"] for p in out["probes"]} == {
            "introspection": "FINDING",  # schema still disclosed
            "depth": "SAFE",
            "batching": "SAFE",
            "field-fuzz": "SAFE",
        }
        assert out["finding_count"] == 1
    finally:
        srv.shutdown()
        srv.server_close()


def test_probe_validation() -> None:
    import pytest

    with pytest.raises(ValueError):
        probe_endpoint("not-a-url")
    with pytest.raises(ValueError):
        probe_endpoint("")


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("http://lab.local/graphql")
    assert res["finding_count"] == 2 and res["clean"] is False
    rows = to_ledger("10.10.10.77", res["url"], res["findings"])
    assert len(rows) == 2
    assert rows[0]["module"] == "graphql-fuzz"
    assert rows[0]["cwe"] == "CWE-200"
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


def test_graphql_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/graphql/fuzz",
        json={"url": "http://10.10.10.99/graphql"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0
    assert body["probe_count"] == 4

    # Non-URL target is a 400 even in sandbox.
    assert c.post("/api/graphql/fuzz", json={"url": "not-a-url"}).status_code == 400

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/graphql/fuzz",
        json={"url": "http://10.10.10.77/graphql", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "graphql introspection" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/graphql/fuzz",
            json={"url": "http://h/x", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope hostname is reported, never stored.
    r = c.post(
        "/api/graphql/fuzz",
        json={"url": "http://192.0.2.9/graphql", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
