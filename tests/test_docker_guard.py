"""Backlog #38: docker socket guard — detect + policy suggestion."""

from __future__ import annotations

from typing import Any

from services.docker_guard import (
    SOCKET_PATHS,
    _docker_group_member,
    _inspect_socket,
    detect,
    sandbox_result,
    to_ledger,
)


def test_inspect_socket_missing() -> None:
    out = _inspect_socket("/nonexistent-h4k-sock")
    assert out == {"path": "/nonexistent-h4k-sock", "present": False}


def test_inspect_socket_paths_tuple() -> None:
    assert "/var/run/docker.sock" in SOCKET_PATHS
    assert len(SOCKET_PATHS) >= 3


def test_group_member_shape() -> None:
    member, evidence = _docker_group_member()
    assert isinstance(member, bool) and isinstance(evidence, str)


def test_detect_shape() -> None:
    out = detect()
    assert set(out) >= {
        "sockets",
        "docker_group_member",
        "docker_host",
        "findings",
        "finding_count",
        "guarded",
    }
    assert out["finding_count"] == len(out["findings"])
    assert out["guarded"] == (not out["findings"])


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result()
    assert res["finding_count"] == 2 and res["guarded"] is False
    rows = to_ledger("10.10.10.77", res["findings"])
    assert len(rows) == 2
    assert rows[0]["name"] == "docker-guard socket-mounted"
    assert rows[0]["severity"] == "CRITICAL"
    assert rows[0]["module"] == "docker-guard"
    assert "policy=" in rows[0]["detail"]
    assert to_ledger("h", []) == []


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


def test_docker_guard_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/docker/guard", json={"host": "127.0.0.1"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0
    assert body["host"] == "127.0.0.1"

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/docker/guard",
        json={"host": "10.10.10.77", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "docker-guard socket-mounted" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/docker/guard",
            json={"host": "h", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope host is reported, never stored.
    r = c.post(
        "/api/docker/guard",
        json={"host": "192.0.2.9", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
