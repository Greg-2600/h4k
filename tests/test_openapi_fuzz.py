"""Backlog #48: OpenAPI import → fuzz — spec-driven targets."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlsplit

from services.openapi_fuzz import (
    build_request,
    fuzz_targets,
    loads_spec,
    parse_spec,
    sandbox_result,
    to_ledger,
)

SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/items/{id}": {
            "get": {
                "operationId": "getItem",
                "parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "integer"}},
                    {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
                ],
            }
        },
        "/items": {
            "post": {
                "operationId": "createItem",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "age": {"type": "integer"},
                                    "tags": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                },
                            }
                        }
                    }
                },
            }
        },
    },
}

SWAGGER = {
    "swagger": "2.0",
    "paths": {
        "/ping": {"get": {"operationId": "ping"}},
    },
}


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: Any) -> None:
        body = json.dumps(obj).encode() if not isinstance(obj, bytes) else obj
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _observe(self, blob: str) -> tuple[int, Any] | None:
        if "A" * 100 in blob:
            return 500, {"error": "boom on oversize"}
        if "%x" in blob or "${7*7}" in blob:
            return 200, {"error": "exception: Traceback bad format"}
        if "' OR" in blob:
            return 500, {"error": "boom on sqli"}
        return None

    def do_GET(self) -> None:
        hit = self._observe(urlsplit(self.path).query + self.path)
        if hit:
            self._send(*hit)
        else:
            self._send(200, {"id": 1})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        hit = self._observe(self.rfile.read(length).decode(errors="replace"))
        if hit:
            self._send(*hit)
        else:
            self._send(200, {"ok": True})

    def log_message(self, *args: Any) -> None:
        return


def _server() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_parse_spec_openapi3() -> None:
    targets = parse_spec(SPEC)
    assert len(targets) == 2
    get = targets[0]
    assert get["method"] == "GET" and get["path"] == "/items/{id}"
    assert {p["name"] for p in get["params"]} == {"id", "verbose"}
    post = targets[1]
    assert {f["path"] for f in post["body_fields"]} == {"name", "age", "tags"}
    assert parse_spec(SWAGGER)[0]["operation"] == "ping"


def test_parse_spec_rejects() -> None:
    import pytest

    with pytest.raises(ValueError):
        parse_spec({})
    with pytest.raises(ValueError):
        parse_spec({"paths": {}})
    with pytest.raises(ValueError):
        parse_spec([])  # type: ignore[arg-type]
    assert loads_spec('{"a": 1}') == {"a": 1}
    assert loads_spec("a: 1") == {"a": 1}
    with pytest.raises(ValueError):
        loads_spec("{bad")
    with pytest.raises(ValueError):
        loads_spec("- just\n- a\n- list")
    with pytest.raises(ValueError):
        loads_spec("   ")


def test_build_request_templates() -> None:
    method, url, body, hds = build_request("http://h:1", parse_spec(SPEC)[0])
    assert method == "GET" and url == "http://h:1/items/1?verbose=True"
    method, url, body, hds = build_request("http://h:1/", parse_spec(SPEC)[1])
    assert method == "POST"
    assert json.loads(body.decode()) == {"name": "test", "age": 1, "tags": "test"}
    assert hds["Content-Type"] == "application/json"


def test_live_fuzz_catches_signals() -> None:
    srv, base = _server()
    try:
        out = fuzz_targets(base, parse_spec(SPEC), iterations=30, timeout=5.0)
        assert out["iterations"] == 30
        signals = {c["signal"] for c in out["candidates"]}
        assert "server-error" in signals
        assert "error-text" in signals
        assert out["candidate_count"] == len(out["candidates"]) > 0
    finally:
        srv.shutdown()
        srv.server_close()


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("http://lab.local")
    assert res["candidate_count"] == 2 and res["clean"] is False
    rows = to_ledger("10.10.10.77", res["base"], res["candidates"])
    assert len(rows) == 2
    assert rows[0]["module"] == "openapi-fuzz"
    assert rows[0]["cwe"] == "CWE-20"
    assert to_ledger("h", "b", []) == []


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


def test_openapi_router(tmp_path: Any, monkeypatch: Any) -> None:
    import routers.scan as scan_router

    c = _client(tmp_path, monkeypatch)
    assert c.post("/api/openapi_fuzz", json={"base_url": "ftp://x"}).status_code == 400
    assert (
        c.post(
            "/api/openapi_fuzz", json={"base_url": "http://h", "spec": "{bad"}
        ).status_code
        == 400
    )
    assert (
        c.post(
            "/api/openapi_fuzz", json={"base_url": "http://h", "spec": {}}
        ).status_code
        == 400
    )

    seen: dict[str, Any] = {}

    def _fake_bg(job: dict[str, Any], req: Any) -> None:
        seen["host"] = job["host"]
        from services.openapi_fuzz import sandbox_result, to_ledger

        result = sandbox_result(job["base"])
        job.update(
            {
                "targets": result["targets"],
                "iterations": result["iterations"],
                "candidates": result["candidates"],
                "count": result["candidate_count"],
                "clean": result["clean"],
                "ingested": 0,
                "skipped_out_of_scope": [],
                "status": "done",
            }
        )
        if req.engagement_id:
            from routers.engagement import get_store

            store = get_store()
            for entry in to_ledger(job["host"], job["base"], job["candidates"]):
                from services.engagement import ScopeError

                try:
                    job["ingested"] += store.record_vuln(
                        req.engagement_id, entry["host"], entry
                    )
                except (ScopeError, ValueError):
                    job["skipped_out_of_scope"].append(entry["host"])

    monkeypatch.setattr(scan_router, "_run_openapi_fuzz", _fake_bg)
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/openapi_fuzz",
        json={
            "base_url": "http://10.10.10.77:8080",
            "spec": SPEC,
            "iterations": 8,
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert seen["host"] == "10.10.10.77"
    r = c.get(f"/api/openapi_fuzz/{job_id}")
    body = r.json()
    assert body["status"] == "done" and body["count"] == 2
    assert body["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "openapi-fuzz" in str(vulns)

    r = c.post(f"/api/openapi_fuzz/{job_id}/abort")
    assert r.json()["status"] == "abort_requested"
    assert c.get("/api/openapi_fuzz/nope").status_code == 404
    assert c.post("/api/openapi_fuzz/nope/abort").status_code == 404
