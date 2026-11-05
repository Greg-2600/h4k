"""Backlog #37: kubelet unauth audit — read-only checks."""

from __future__ import annotations

from typing import Any

import pytest
from services.kubelet_audit import (
    KubeletAuditor,
    parse_pod_list,
    sandbox_result,
    to_ledger,
)

PODS = '{"kind":"PodList","items":[{"a":1},{"b":2}]}'


def test_validation() -> None:
    with pytest.raises(ValueError):
        KubeletAuditor("", 10250)
    with pytest.raises(ValueError):
        KubeletAuditor("h", 0)
    with pytest.raises(ValueError):
        KubeletAuditor("h", 99999)


def test_parse_pod_list() -> None:
    assert parse_pod_list(PODS) == 2
    assert parse_pod_list("not json") == 0
    assert parse_pod_list("") == 0


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("10.10.10.77", 10250)
    assert res["finding_count"] == 2 and res["secure"] is False
    rows = to_ledger("10.10.10.77", 10250, res["findings"])
    assert len(rows) == 2
    assert rows[0]["name"] == "kubelet:10250 anonymous-pods"
    assert rows[0]["severity"] == "CRITICAL"
    assert rows[0]["module"] == "kubelet-audit"
    assert to_ledger("h", 10250, []) == []


def test_audit_unreachable() -> None:
    out = KubeletAuditor("127.0.0.1", 19999, timeout=1.0).audit()
    assert out["reachable"] is False
    assert out["findings"] == []


def test_audit_logic_canned_transport(monkeypatch: Any) -> None:
    auditor = KubeletAuditor("10.0.0.1", 10250, timeout=1.0)
    canned = {
        "/healthz": (200, "ok"),
        "/pods": (200, PODS),
        "/metrics": (200, "# HELP x"),
    }
    monkeypatch.setattr(
        KubeletAuditor, "_get", lambda _self, path: canned.get(path, (404, ""))
    )
    monkeypatch.setattr(KubeletAuditor, "_readonly_port_open", lambda _self: True)
    out = auditor.audit()
    assert out["reachable"] is True
    assert out["finding_count"] == 3
    assert out["secure"] is False
    assert {f["check"] for f in out["findings"]} == {
        "anonymous-pods",
        "metrics",
        "readonly-port-10255",
    }


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


def test_kubelet_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/kubelet/audit", json={"host": "127.0.0.1", "port": 10250})
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0

    # Bad port is a 400 even in sandbox.
    assert (
        c.post("/api/kubelet/audit", json={"host": "h", "port": 99999}).status_code
        == 400
    )

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/kubelet/audit",
        json={"host": "10.10.10.77", "port": 10250, "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "kubelet:10250 anonymous-pods" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/kubelet/audit",
            json={"host": "h", "port": 10250, "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope host is reported, never stored.
    r = c.post(
        "/api/kubelet/audit",
        json={"host": "192.0.2.9", "port": 10250, "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
