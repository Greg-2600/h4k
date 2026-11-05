"""Backlog #45: WebSocket fuzz — frame mutation + replay."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from services.wsfuzz import (
    MUTATIONS,
    WsClient,
    fuzz_ws,
    sandbox_fuzz,
    to_ledger,
)

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_stub(handler) -> tuple[socket.socket, int]:
    """Raw-socket WS server: handshake, then per-frame `handler(send) -> action`."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]

    def _frame(payload: bytes, opcode: int = 0x1) -> bytes:
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([n])
        elif n < 65536:
            header += bytes([126]) + struct.pack(">H", n)
        else:
            header += bytes([127]) + struct.pack(">Q", n)
        return header + payload

    def _serve() -> None:
        count = 0
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.settimeout(10)
            try:
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                key = ""
                for line in head.decode().split("\r\n"):
                    if line.lower().startswith("sec-websocket-key:"):
                        key = line.split(":", 1)[1].strip()
                accept = base64.b64encode(
                    hashlib.sha1((key + GUID).encode()).digest()
                ).decode()
                conn.sendall(
                    f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode()
                )
                while True:
                    hdr = conn.recv(2)
                    if len(hdr) < 2:
                        break
                    length = hdr[1] & 0x7F
                    if length == 126:
                        length = struct.unpack(">H", conn.recv(2))[0]
                    elif length == 127:
                        length = struct.unpack(">Q", conn.recv(8))[0]
                    mask = conn.recv(4) if hdr[1] & 0x80 else b""
                    payload = b""
                    while len(payload) < length:
                        chunk = conn.recv(length - len(payload))
                        if not chunk:
                            break
                        payload += chunk
                    if mask:
                        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                    action = handler(count, payload)
                    count += 1
                    if action == "drop":
                        conn.close()
                        break
                    if action == "error":
                        conn.sendall(_frame(b"exception: boom in handler"))
                    else:
                        conn.sendall(_frame(b"ok:" + payload[:32]))
            except (OSError, ConnectionError):
                pass
            finally:
                with contextlib.suppress(OSError):
                    conn.close()

    threading.Thread(target=_serve, daemon=True).start()
    return srv, port


def test_mutations_deterministic() -> None:
    import random

    for name, fn in MUTATIONS:
        a = fn(b'{"a":1}', random.Random(7))
        b = fn(b'{"a":1}', random.Random(7))
        assert a == b, name
    assert len(MUTATIONS) >= 8


def test_client_handshake_refused() -> None:
    class Plain(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"nope"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            return

    srv = HTTPServer(("127.0.0.1", 0), Plain)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    try:
        import pytest

        with pytest.raises((ConnectionError, OSError)):
            WsClient(
                f"http://127.0.0.1:{srv.server_address[1]}/x".replace("http", "ws"),
                timeout=3.0,
            ).connect()
        with pytest.raises(ValueError):
            WsClient("http://x/y")
    finally:
        srv.shutdown()
        srv.server_close()


def test_live_fuzz_catches_signals() -> None:
    def _handler(count: int, _payload: bytes) -> str:
        if count % 5 == 4:
            return "drop"
        if count % 5 == 2:
            return "error"
        return "echo"

    srv, port = _ws_stub(_handler)
    try:
        out = fuzz_ws(
            f"ws://127.0.0.1:{port}/socket",
            seed='{"hello":1}',
            iterations=10,
            timeout=5.0,
            rng_seed=1,
        )
        assert out["iterations"] == 10
        signals = {c["signal"] for c in out["candidates"]}
        assert "dropped" in signals
        assert "error-text" in signals
        assert out["candidate_count"] == len(out["candidates"]) > 0
    finally:
        srv.close()


def test_live_fuzz_clean_server() -> None:
    srv, port = _ws_stub(lambda _c, _p: "echo")
    try:
        out = fuzz_ws(f"ws://127.0.0.1:{port}/s", seed="hi", iterations=6, timeout=5.0)
        assert out["clean"] is True and out["candidates"] == []
    finally:
        srv.close()


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_fuzz("ws://lab/x", '{"a":1}')
    assert res["candidate_count"] == 2 and res["clean"] is False
    rows = to_ledger("10.10.10.77", res["url"], res["candidates"])
    assert len(rows) == 2
    assert rows[0]["module"] == "ws-fuzz"
    assert rows[0]["cwe"] == "CWE-20"
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


def test_ws_router(tmp_path: Any, monkeypatch: Any) -> None:
    import routers.scan as scan_router

    c = _client(tmp_path, monkeypatch)
    assert c.post("/api/ws_fuzz", json={"url": "http://x/"}).status_code == 400
    assert c.post("/api/ws_fuzz", json={"url": "ws:///nohost"}).status_code == 400

    seen: dict[str, Any] = {}

    def _fake_bg(job: dict[str, Any], req: Any, host: str) -> None:
        seen["host"] = host
        from services.wsfuzz import sandbox_fuzz, to_ledger

        result = sandbox_fuzz(job["url"], job["seed"])
        job["candidates"] = result["candidates"]
        job["count"] = result["candidate_count"]
        job["clean"] = result["clean"]
        job["ingested"] = 0
        job["skipped_out_of_scope"] = []
        if req.engagement_id:
            from routers.engagement import get_store

            store = get_store()
            for entry in to_ledger(host, job["url"], job["candidates"]):
                from services.engagement import ScopeError

                try:
                    job["ingested"] += store.record_vuln(
                        req.engagement_id, entry["host"], entry
                    )
                except (ScopeError, ValueError):
                    job["skipped_out_of_scope"].append(entry["host"])
        job["status"] = "done"

    monkeypatch.setattr(scan_router, "_run_ws_fuzz", _fake_bg)
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/ws_fuzz",
        json={
            "url": "ws://10.10.10.77:8765/socket",
            "seed": '{"a":1}',
            "iterations": 8,
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert seen["host"] == "10.10.10.77"
    r = c.get(f"/api/ws_fuzz/{job_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "done" and body["count"] == 2
    assert body["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "ws-fuzz" in str(vulns)

    r = c.post(f"/api/ws_fuzz/{job_id}/abort")
    assert r.json()["status"] == "abort_requested"
    assert c.get("/api/ws_fuzz/nope").status_code == 404
    assert c.post("/api/ws_fuzz/nope/abort").status_code == 404
