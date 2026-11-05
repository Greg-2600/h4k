"""Backlog #41: Terraform/IaC scan — Checkov-style offline misconfigs."""

from __future__ import annotations

from typing import Any

import pytest
from services.terraform_scan import (
    _parse_blocks,
    parse_bundle,
    sandbox_result,
    scan_files,
    to_ledger,
)

SG = """
resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

RDS = """
resource "aws_db_instance" "app" {
  publicly_accessible = true
}
"""

S3 = """
resource "aws_s3_bucket" "logs" {
}
"""

VAR = """
variable "db_password" {
  default = "hunter2-secret"
}
"""

CLEAN_SG = """
resource "aws_security_group" "web" {
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"""

BUNDLE = "=== main.tf ===\n" + SG + "\n=== rds.tf ===\n" + RDS


def test_parse_bundle() -> None:
    files = parse_bundle(BUNDLE)
    assert [f["path"] for f in files] == ["main.tf", "rds.tf"]
    assert parse_bundle("   ") == []


def test_parse_blocks_shape() -> None:
    blocks = _parse_blocks(SG)
    assert len(blocks) == 1
    assert blocks[0]["labels"] == ["aws_security_group", "web"]
    assert len(blocks[0]["nested"]) == 1
    assert blocks[0]["nested"][0]["attrs"]["from_port"] == "22"


def test_open_sg_admin_port() -> None:
    out = scan_files([{"path": "main.tf", "content": SG}])
    assert out["finding_count"] == 1
    assert out["findings"][0]["check"] == "H4K-TF-SG-001"
    assert "admin port 22-22" in out["findings"][0]["title"]


def test_rds_and_s3() -> None:
    out = scan_files([{"path": "db.tf", "content": RDS + S3}])
    checks = {f["check"] for f in out["findings"]}
    assert "H4K-TF-RDS-001" in checks
    assert "H4K-TF-RDS-002" in checks
    assert "H4K-TF-S3-001" in checks


def test_secret_default_and_clean() -> None:
    out = scan_files([{"path": "vars.tf", "content": VAR}])
    assert out["findings"][0]["check"] == "H4K-TF-VAR-001"
    clean = scan_files([{"path": "main.tf", "content": CLEAN_SG}])
    assert clean["clean"] is True


def test_empty_bundle_rejected() -> None:
    with pytest.raises(ValueError):
        scan_files([])


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("lab/stack")
    assert res["finding_count"] == 2 and res["clean"] is False
    rows = to_ledger("10.10.10.77", "lab/stack", res["findings"])
    assert len(rows) == 2
    assert rows[0]["module"] == "terraform-scan"
    assert rows[0]["severity"] == "CRITICAL"
    assert to_ledger("h", "s", []) == []


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


def test_terraform_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/source/terraform/scan",
        json={"stack": "lab/stack", "bundle": BUNDLE, "host": "h"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0

    # Empty bundle is a 400 even in sandbox.
    assert (
        c.post(
            "/api/source/terraform/scan", json={"stack": "x", "bundle": "  "}
        ).status_code
        == 400
    )

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/source/terraform/scan",
        json={
            "stack": "lab/stack",
            "bundle": BUNDLE,
            "host": "10.10.10.77",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "tf lab/stack" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/source/terraform/scan",
            json={
                "stack": "x",
                "bundle": BUNDLE,
                "host": "h",
                "engagement_id": "nope",
            },
        ).status_code
        == 404
    )

    # Out-of-scope host is reported, never stored.
    r = c.post(
        "/api/source/terraform/scan",
        json={
            "stack": "x",
            "bundle": BUNDLE,
            "host": "192.0.2.9",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
