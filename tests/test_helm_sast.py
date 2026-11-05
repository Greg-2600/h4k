"""Backlog #40: Helm chart SAST — templating + secret checks."""

from __future__ import annotations

from typing import Any

import pytest
from services.helm_sast import (
    parse_bundle,
    sandbox_result,
    scan_files,
    to_ledger,
)

DEPLOY = """
kind: Deployment
metadata: {name: app}
spec:
  template:
    spec:
      containers:
      - name: app
        image: registry/app:1.2.3
        securityContext: {runAsNonRoot: true, readOnlyRootFilesystem: true}
        resources: {limits: {cpu: 100m}}
"""

PRIV = """
kind: Deployment
metadata: {name: evil}
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - name: evil
        image: registry/evil:latest
        securityContext: {privileged: true}
        command: ["sh", "-c", "{{ .Values.cmd }}"]
"""

VALUES = """
db:
  password: hunter2-supersecret
image:
  tag: stable
"""

SECRET = """
kind: Secret
metadata: {name: creds}
type: Opaque
stringData:
  token: abcdef123456
"""

BUNDLE = "=== templates/deploy.yaml ===\n" + DEPLOY + "\n=== values.yaml ===\n" + VALUES


def test_parse_bundle() -> None:
    files = parse_bundle(BUNDLE)
    assert [f["path"] for f in files] == ["templates/deploy.yaml", "values.yaml"]
    assert parse_bundle("   \n  ") == []
    assert parse_bundle("just text") == [{"path": "chart.yaml", "content": "just text"}]


def test_clean_chart() -> None:
    out = scan_files([{"path": "templates/deploy.yaml", "content": DEPLOY}])
    assert out["finding_count"] == 0 and out["clean"] is True


def test_privileged_hostnetwork_latest_templated_cmd() -> None:
    out = scan_files([{"path": "templates/evil.yaml", "content": PRIV}])
    titles = " | ".join(f["title"] for f in out["findings"])
    assert "privileged" in titles
    assert "hostNetwork" in titles
    assert "floating image tag" in titles
    assert "template-controlled command" in titles
    assert out["clean"] is False


def test_values_secret_and_secret_manifest() -> None:
    out = scan_files(
        [
            {"path": "values.yaml", "content": VALUES},
            {"path": "templates/secret.yaml", "content": SECRET},
        ]
    )
    assert any(
        f["severity"] == "CRITICAL" and "db.password" in f["title"]
        for f in out["findings"]
    )
    assert any("plaintext token" in f["title"] for f in out["findings"])


def test_bad_yaml_reported() -> None:
    with pytest.raises(ValueError):
        scan_files([])
    out = scan_files([{"path": "bad.yaml", "content": "{{{ bad: [yaml"}])
    assert len(out["errors"]) == 1 and out["parsed"] == 0


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("lab/app")
    assert res["finding_count"] == 2 and res["clean"] is False
    rows = to_ledger("10.10.10.77", "lab/app", res["findings"])
    assert len(rows) == 2
    assert rows[0]["module"] == "helm-sast"
    assert rows[0]["severity"] == "CRITICAL"
    assert to_ledger("h", "c", []) == []


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


def test_helm_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/source/helm/scan",
        json={"chart": "lab/app", "bundle": BUNDLE, "host": "h"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0

    # Empty bundle is a 400 even in sandbox.
    assert (
        c.post("/api/source/helm/scan", json={"chart": "x", "bundle": "  "}).status_code
        == 400
    )

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/source/helm/scan",
        json={
            "chart": "lab/app",
            "bundle": BUNDLE,
            "host": "10.10.10.77",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "helm lab/app" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/source/helm/scan",
            json={"chart": "x", "bundle": BUNDLE, "host": "h", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope host is reported, never stored.
    r = c.post(
        "/api/source/helm/scan",
        json={
            "chart": "x",
            "bundle": BUNDLE,
            "host": "192.0.2.9",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
