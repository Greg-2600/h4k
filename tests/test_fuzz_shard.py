"""Backlog #59: fuzz sharding — N workers, merged registry."""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
from typing import Any

import pytest
from services.fuzz_shard import build_slices, run_shard, sandbox_result


def test_slices_deterministic_and_disjoint() -> None:
    a = build_slices(3, 10, seed=7)
    b = build_slices(3, 10, seed=7)
    assert a == b
    assert len(a) == 3 and all(len(s) == 10 for s in a)
    flat = [p for s in a for _, p in s]
    assert len(set(flat)) == len(flat)  # no duplicated work
    other = build_slices(3, 10, seed=8)
    assert other != a
    capped = build_slices(99, 99999, seed=1)
    assert len(capped) == 8 and all(len(s) <= 2000 for s in capped)
    assert build_slices(0, 0, seed=1)[0]  # clamps, never explodes


def _rst_server() -> tuple[socket.socket, int]:
    """Accept then RST every connection (teardown on every input)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    srv.bind(("127.0.0.1", 0))
    srv.listen(32)
    port = srv.getsockname()[1]

    def _serve() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                with contextlib.suppress(OSError):
                    conn.recv(65536)
            finally:
                conn.close()

    threading.Thread(target=_serve, daemon=True).start()
    return srv, port


def test_sharded_run_merges_registry() -> None:
    srv, port = _rst_server()
    try:
        out = run_shard(
            "127.0.0.1", port, workers=2, iterations=6, seed=11, timeout=5.0
        )
        assert out["iterations"] == 12
        assert sum(w["iterations"] for w in out["worker_stats"]) == 12
        # Every input tore down the connection, yet the shared registry
        # reports one distinct crash — the merge works.
        assert out["candidate_count"] == 1
        assert out["clean"] is False
        assert out["errors"] == []
    finally:
        srv.close()


def test_shard_validation() -> None:
    with pytest.raises(ValueError):
        run_shard("", 80)


def test_sandbox_shapes() -> None:
    res = sandbox_result("10.9.9.9")
    assert res["host"] == "10.9.9.9"
    assert res["candidate_count"] == 1 and res["clean"] is False


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


def test_shard_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/fuzz/shard", json={"host": "10.10.10.99"})
    assert r.status_code == 200
    body = r.json()
    assert body["candidate_count"] == 1 and body["workers"] == 2
    assert body["host"] == "10.10.10.99"
    assert c.post("/api/fuzz/shard", json={}).status_code == 400
