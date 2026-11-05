"""Backlog #46: gRPC enumerator + fuzz — reflection + payload shapes."""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
from typing import Any

from services.grpcfuzz import (
    _dec_int,
    _enc_int,
    _hpack_decode,
    _hpack_literal,
    enumerate_and_fuzz,
    fuzz_method,
    reflect_services,
    sandbox_enumeration,
    to_ledger,
)

_F_HEADERS, _F_DATA, _F_RST, _F_SETTINGS = 1, 0, 3, 4


def lit(name: str, value: str) -> bytes:
    out = bytearray([0x00])
    nb, vb = name.encode(), value.encode()
    out += bytes([len(nb)]) + nb + bytes([len(vb)]) + vb
    return bytes(out)


def frame(ftype: int, flags: int, stream: int, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))[1:]
        + bytes([ftype, flags])
        + struct.pack(">I", stream)
        + payload
    )


def _read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def _stub_server(behavior: str) -> tuple[socket.socket, int, dict[str, Any]]:
    """Minimal h2 server: preface, SETTINGS, HEADERS+DATA, scripted replies."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]
    state: dict[str, Any] = {"count": 0, "paths": []}

    def _headers_for(stream: int) -> None:
        pass

    def _serve_one(conn: socket.socket) -> None:
        conn.settimeout(10)
        _read_exact(conn, 24)  # client preface
        hdr = _read_exact(conn, 9)  # SETTINGS
        length = struct.unpack(">I", b"\x00" + hdr[:3])[0]
        if length:
            _read_exact(conn, length)
        conn.sendall(frame(_F_SETTINGS, 0, 0, b""))
        stream = 0
        data = b""
        while True:
            try:
                hdr = _read_exact(conn, 9)
            except ConnectionError:
                return
            length = struct.unpack(">I", b"\x00" + hdr[:3])[0]
            ftype, flags, fstream = hdr[3], hdr[4], struct.unpack(">I", hdr[5:9])[0]
            payload = _read_exact(conn, length) if length else b""
            if ftype == _F_HEADERS:
                stream = fstream
                # Minimal literal-header decode to learn :path.
                pos, path = 0, ""
                try:
                    while pos < len(payload):
                        if payload[pos] != 0x00:
                            break
                        pos += 1
                        nlen = payload[pos]
                        pos += 1
                        name = payload[pos : pos + nlen].decode()
                        pos += nlen
                        vlen = payload[pos]
                        pos += 1
                        value = payload[pos : pos + vlen].decode()
                        pos += vlen
                        if name == ":path":
                            path = value
                except IndexError:
                    pass
                state["paths"].append(path)
                state["stream"] = stream
                _ = _headers_for(stream)
            elif ftype == _F_DATA and fstream == stream:
                data += payload
                if not flags & 0x1:
                    continue
                state["count"] += 1
                n = state["count"]
                if behavior == "reflect":
                    body = b"test.Echo test.Admin Method"
                    msg = b"\x00" + struct.pack(">I", len(body)) + body
                    conn.sendall(
                        frame(
                            _F_HEADERS,
                            0x4,
                            stream,
                            lit(":status", "200")
                            + lit("content-type", "application/grpc"),
                        )
                    )
                    conn.sendall(frame(_F_DATA, 0x0, stream, msg))
                    conn.sendall(
                        frame(
                            _F_HEADERS,
                            0x5,
                            stream,
                            lit("grpc-status", "0"),
                        )
                    )
                elif behavior == "cycle":
                    if n % 4 == 2:
                        conn.sendall(frame(_F_RST, 0, stream, struct.pack(">I", 8)))
                    elif n % 4 == 3:
                        conn.sendall(
                            frame(
                                _F_HEADERS,
                                0x5,
                                stream,
                                lit("grpc-status", "13"),
                            )
                        )
                    elif n % 4 == 0:
                        conn.close()
                        return
                    else:
                        msg = b"\x00" + struct.pack(">I", 2) + b"ok"
                        conn.sendall(
                            frame(
                                _F_HEADERS,
                                0x4,
                                stream,
                                lit(":status", "200")
                                + lit("content-type", "application/grpc"),
                            )
                        )
                        conn.sendall(frame(_F_DATA, 0x0, stream, msg))
                        conn.sendall(
                            frame(
                                _F_HEADERS,
                                0x5,
                                stream,
                                lit("grpc-status", "0"),
                            )
                        )

    def _serve() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                _serve_one(conn)
            except (OSError, ConnectionError):
                pass
            finally:
                with contextlib.suppress(OSError):
                    conn.close()

    threading.Thread(target=_serve, daemon=True).start()
    return srv, port, state


def test_hpack_roundtrip() -> None:
    block = _hpack_literal(":method", "POST") + _hpack_literal("x-a", "b")
    assert _hpack_decode(block) == {":method": "POST", "x-a": "b"}
    assert _hpack_decode(bytes([0x88]))[":status"] == "200"
    value, pos = _dec_int(bytes([0x0A]), 0, 7)
    assert (value, pos) == (10, 1)
    assert _enc_int(10, 7, 0x00) == bytes([0x0A])


def test_reflect_live() -> None:
    srv, port, _ = _stub_server("reflect")
    try:
        out = reflect_services("127.0.0.1", port, timeout=5.0)
        assert out["reflection"] is True
        assert "test.Echo" in out["services"]
        assert out["heuristic"] is True
    finally:
        srv.close()


def test_fuzz_live_signals() -> None:
    srv, port, _ = _stub_server("cycle")
    try:
        out = fuzz_method(
            "127.0.0.1",
            port,
            "/test.Echo/Echo",
            seed="hi",
            iterations=8,
            timeout=5.0,
            rng_seed=3,
        )
        assert out["iterations"] == 8
        signals = {c["signal"] for c in out["candidates"]}
        assert "rst" in signals
        assert "grpc-error" in signals
        assert "dropped" in signals
    finally:
        srv.close()


def test_fuzz_bad_path() -> None:
    import pytest

    with pytest.raises(ValueError):
        fuzz_method("127.0.0.1", 1, "nope", iterations=1)


def test_enumerate_and_fuzz_live() -> None:
    srv, port, _state = _stub_server("cycle")
    try:
        out = enumerate_and_fuzz(
            "127.0.0.1",
            port,
            method="/test.Echo/Echo",
            iterations=4,
            timeout=5.0,
        )
        assert out["candidate_count"] >= 1
    finally:
        srv.close()


def test_enumerate_unreachable() -> None:
    out = enumerate_and_fuzz("127.0.0.1", 1, iterations=1, timeout=1.0)
    assert out["reflection"] is False and "error" in out


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_enumeration("127.0.0.1", 50051)
    assert res["service_count"] == 2 and res["candidate_count"] == 2
    rows = to_ledger("10.10.10.77", 50051, res["services"], res["candidates"])
    assert len(rows) == 3  # reflection note + 2 signals
    assert rows[0]["severity"] == "MEDIUM" and rows[0]["cwe"] == "CWE-200"
    assert to_ledger("h", 1, [], []) == []


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


def test_grpc_router(tmp_path: Any, monkeypatch: Any) -> None:
    import routers.scan as scan_router

    c = _client(tmp_path, monkeypatch)
    assert c.post("/api/grpc_fuzz", json={"host": "", "port": 1}).status_code == 400
    assert c.post("/api/grpc_fuzz", json={"host": "h", "port": 99999}).status_code in (
        400,
        422,
    )
    assert (
        c.post(
            "/api/grpc_fuzz", json={"host": "h", "port": 1, "method": "nope"}
        ).status_code
        == 400
    )

    seen: dict[str, Any] = {}

    def _fake_bg(job: dict[str, Any], req: Any) -> None:
        seen["host"] = job["host"]
        from services.grpcfuzz import sandbox_enumeration, to_ledger

        result = sandbox_enumeration(job["host"], job.get("port", 0))
        job.update(
            {
                "services": result["services"],
                "service_count": result["service_count"],
                "method": result["method"],
                "reflection": result["reflection"],
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
            for entry in to_ledger(
                job["host"], job.get("port", 0), job["services"], job["candidates"]
            ):
                from services.engagement import ScopeError

                try:
                    job["ingested"] += store.record_vuln(
                        req.engagement_id, entry["host"], entry
                    )
                except (ScopeError, ValueError):
                    job["skipped_out_of_scope"].append(entry["host"])

    monkeypatch.setattr(scan_router, "_run_grpc_fuzz", _fake_bg)
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/grpc_fuzz",
        json={"host": "10.10.10.77", "port": 50051, "engagement_id": eid},
    )
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert seen["host"] == "10.10.10.77"
    r = c.get(f"/api/grpc_fuzz/{job_id}")
    body = r.json()
    assert body["status"] == "done" and body["count"] == 2
    assert body["ingested"] == 3
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "grpc reflection enabled" in str(vulns)

    r = c.post(f"/api/grpc_fuzz/{job_id}/abort")
    assert r.json()["status"] == "abort_requested"
    assert c.get("/api/grpc_fuzz/nope").status_code == 404
    assert c.post("/api/grpc_fuzz/nope/abort").status_code == 404
