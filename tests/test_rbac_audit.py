"""Backlog #39: K8s RBAC audit — over-permissive roles flagged."""

from __future__ import annotations

from typing import Any

import pytest
from services.rbac_audit import audit_documents, sandbox_result, to_ledger

ADMIN = """
kind: ClusterRole
metadata: {name: deployer}
rules:
- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}
"""

READER = """
kind: ClusterRole
metadata: {name: reader}
rules:
- {apiGroups: [""], resources: ["secrets"], verbs: ["get", "list"]}
"""

PODS = """
kind: Role
metadata: {name: deploy, namespace: default}
rules:
- {apiGroups: [""], resources: ["pods"], verbs: ["create", "get"]}
"""

SAFE = """
kind: Role
metadata: {name: viewer, namespace: default}
rules:
- {apiGroups: [""], resources: ["pods"], verbs: ["get", "list"]}
"""

BINDING = """
kind: ClusterRoleBinding
metadata: {name: bad}
roleRef: {kind: ClusterRole, name: cluster-admin}
subjects:
- {kind: Group, name: system:authenticated}
"""


def test_flags_admin_equivalent() -> None:
    out = audit_documents([ADMIN])
    assert out["parsed"] == 1 and out["risky"] is False
    assert out["findings"][0]["severity"] == "CRITICAL"
    assert "cluster-admin" in out["findings"][0]["title"]


def test_flags_secret_read_and_pod_create() -> None:
    out = audit_documents([READER, PODS])
    by_title = " | ".join(f["title"] for f in out["findings"])
    assert "secret read" in by_title
    assert "pod creation" in by_title
    assert out["finding_count"] == 2


def test_safe_role_clean() -> None:
    out = audit_documents([SAFE])
    assert out == {
        "parsed": 1,
        "errors": [],
        "findings": [],
        "finding_count": 0,
        "risky": True,
    }


def test_binding_and_escalate() -> None:
    doc = BINDING.replace("cluster-admin", "custom")
    out = audit_documents([doc])
    assert any("system:authenticated" in f["title"] for f in out["findings"])
    esc = """
kind: ClusterRole
metadata: {name: escalator}
rules:
- {apiGroups: [""], resources: ["roles"], verbs: ["bind", "escalate"]}
"""
    assert any(
        "privilege-escalation" in f["title"] for f in audit_documents([esc])["findings"]
    )


def test_parse_errors_reported() -> None:
    with pytest.raises(ValueError):
        audit_documents([])
    out = audit_documents(["{{{", "", "kind: Service\nmetadata: {name: x}"])
    assert out["parsed"] == 1
    assert len(out["errors"]) == 3
    assert out["findings"] == []


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result()
    assert res["finding_count"] == 2 and res["risky"] is False
    rows = to_ledger("10.10.10.77", res["findings"])
    assert len(rows) == 2
    assert rows[0]["module"] == "rbac-audit"
    assert rows[0]["severity"] == "CRITICAL"
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


def test_rbac_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/rbac/audit", json={"documents": [ADMIN], "host": "h"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0
    assert body["parsed"] == 2

    # Empty documents is a 400 even in sandbox.
    assert c.post("/api/rbac/audit", json={"documents": []}).status_code == 400

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/rbac/audit",
        json={"documents": [ADMIN], "host": "10.10.10.77", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "rbac ClusterRole/deployer" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/rbac/audit",
            json={"documents": [ADMIN], "host": "h", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope host is reported, never stored.
    r = c.post(
        "/api/rbac/audit",
        json={"documents": [ADMIN], "host": "192.0.2.9", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
