"""Backlog #55: PCAP → seed replay — deterministic fuzz seeds."""

from __future__ import annotations

import base64
import socket
import struct
import threading
from typing import Any

from services.pcap_seeds import (
    load_source,
    parse_pcap,
    replay_flow,
    sandbox_parse,
)


def _frame(
    src: str, sport: int, dst: str, dport: int, seq: int, payload: bytes, proto: int = 6
) -> bytes:
    def ip(s: str) -> bytes:
        return bytes(int(x) for x in s.split("."))

    eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
    iph = (
        bytes([0x45, 0x00])
        + struct.pack(">HHHBBH", 20 + 20 + len(payload), 1, 0, 64, proto, 0)
        + ip(src)
        + ip(dst)
    )
    tcph = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x10, 8192, 0, 0)
    return eth + iph + tcph + payload


def _pcap(frames: list[bytes]) -> bytes:
    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", i, 0, len(frame), len(frame)) + frame
    return bytes(out)


def _sample() -> bytes:
    a = _frame("10.0.0.9", 43210, "10.0.0.5", 80, 1000, b"GET /")
    b = _frame("10.0.0.9", 43210, "10.0.0.5", 80, 1005, b" HTTP/1.0\r\n\r\n")
    dup = _frame("10.0.0.9", 43210, "10.0.0.5", 80, 1000, b"GET /")  # retransmit
    early = _frame("10.0.0.9", 43210, "10.0.0.5", 80, 1021, b"ZZZ")  # gap
    other = _frame("10.0.0.7", 53, "10.0.0.8", 53, 1, b"\x00", proto=17)  # UDP
    rev = _frame("10.0.0.5", 80, "10.0.0.9", 43210, 5000, b"HTTP/1.0 200 OK\r\n\r\n")
    return _pcap([b, a, dup, early, other, rev])


def test_parse_flows_and_reassembly() -> None:
    out = parse_pcap(_sample())
    assert out["packets"] == 6
    assert out["skipped"] == 1  # the UDP frame
    assert out["flow_count"] == 2
    by_key = {f["key"]: f for f in out["flows"]}
    fwd = by_key["10.0.0.9|43210|10.0.0.5|80"]
    assert fwd["bytes"] == len(b"GET / HTTP/1.0\r\n\r\nZZZ")
    assert fwd["packets"] == 4  # includes the retransmit
    assert out["seed_count"] == 2
    # Deterministic: same bytes in, same seeds out.
    assert parse_pcap(_sample()) == out


def test_bad_inputs() -> None:
    import pytest

    with pytest.raises(ValueError):
        parse_pcap(b"too short")
    with pytest.raises(ValueError):
        parse_pcap(b"\x00" * 64)
    with pytest.raises(ValueError):
        parse_pcap(b"x" * (5_000_001))
    with pytest.raises(ValueError):
        load_source("")
    with pytest.raises(ValueError):
        load_source("!!! not base64 !!!")
    assert load_source("base64:QUJD") == b"ABC"


def _echo_server(payloads: list[bytes]) -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve() -> None:
        conn, _ = srv.accept()
        data = b""
        try:
            conn.settimeout(5)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        finally:
            try:
                conn.sendall(b"ECHO:" + data[:100])
                conn.close()
            except OSError:
                pass

    threading.Thread(target=_serve, daemon=True).start()
    payloads.append(b"")
    return srv, port


def test_replay_live() -> None:
    seen: list[bytes] = []
    srv, port = _echo_server(seen)
    try:
        out = replay_flow("127.0.0.1", port, b"HELLO-seed", timeout=5.0)
        assert out["connected"] is True and out["sent"] == 10
        assert out["response"] == "ECHO:HELLO-seed"
    finally:
        srv.close()
    out = replay_flow("127.0.0.1", 1, b"x", timeout=1.0)
    assert out["connected"] is False and "error" in out
    import pytest

    with pytest.raises(ValueError):
        replay_flow("", 80, b"x")
    with pytest.raises(ValueError):
        replay_flow("127.0.0.1", 80, b"")


def test_sandbox_shapes() -> None:
    res = sandbox_parse()
    assert res["seed_count"] == 1 and res["flow_count"] == 1
    assert res["replay"]["connected"] is True


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


def test_pcap_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/pcap/seeds",
        json={"pcap_b64": base64.b64encode(_sample()).decode()},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["seed_count"] == 1 and body["flow_count"] == 1
    assert body["replay"]["connected"] is True

    assert c.post("/api/pcap/seeds", json={}).status_code == 400
    assert c.post("/api/pcap/seeds", json={"pcap_b64": "!!!"}).status_code == 400
    assert (
        c.post(
            "/api/pcap/seeds", json={"pcap_b64": base64.b64encode(b"0" * 64).decode()}
        ).status_code
        == 400
    )
