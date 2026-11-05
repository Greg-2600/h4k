"""Backlog #36: container image scan — trivy image → engagement vulns."""

from __future__ import annotations

from typing import Any

import pytest
from services.image_scan import (
    parse_trivy_doc,
    sandbox_result,
    scan_image,
    to_ledger,
    validate_image_ref,
)


def test_validate_image_ref() -> None:
    assert validate_image_ref("lab/app:latest") == "lab/app:latest"
    assert validate_image_ref("  nginx  ") == "nginx"
    with pytest.raises(ValueError):
        validate_image_ref("")
    with pytest.raises(ValueError):
        validate_image_ref("lab/app; rm -rf /")
    with pytest.raises(ValueError):
        validate_image_ref("app$(id)")


def test_parse_trivy_doc_flattens() -> None:
    doc = {
        "Results": [
            {
                "Target": "app (debian 12)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-0464",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.8",
                        "FixedVersion": "3.0.9",
                        "Severity": "HIGH",
                        "Title": "x509 DoS",
                    },
                    {"PkgName": "no-cve-here"},
                ],
            }
        ]
    }
    out = parse_trivy_doc(doc, "lab/app:latest")
    assert len(out) == 1
    assert out[0]["cve"] == "CVE-2023-0464"
    assert out[0]["severity"] == "HIGH"
    assert parse_trivy_doc({}, "x") == []


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("lab/app:latest")
    assert res["finding_count"] == 2 and res["success"] is True
    rows = to_ledger("10.10.10.5", res["image"], res["findings"])
    assert len(rows) == 2
    assert rows[0]["host"] == "10.10.10.5"
    assert "CVE-2023-0464" in rows[0]["name"]
    assert rows[0]["module"] == "trivy-image"
    assert to_ledger("h", "img", [{"no": "cve"}]) == []


def test_scan_image_no_trivy(monkeypatch: Any) -> None:
    import services.image_scan as mod

    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    out = scan_image("lab/app:latest")
    assert out["success"] is False and out["error"] == "trivy not installed"


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


def test_image_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/image/scan", json={"image": "lab/app:latest"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0

    # Bad ref is a 400 even in sandbox.
    assert c.post("/api/image/scan", json={"image": "x; rm -rf /"}).status_code == 400

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/image/scan",
        json={"image": "lab/app:latest", "host": "10.10.10.77", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "CVE-2023-0464" in str(vulns)

    # engagement_id without host is a 400; unknown engagement a 404.
    assert (
        c.post(
            "/api/image/scan",
            json={"image": "lab/app:latest", "engagement_id": eid},
        ).status_code
        == 400
    )
    assert (
        c.post(
            "/api/image/scan",
            json={"image": "lab/app:latest", "host": "h", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope host is reported, never stored.
    r = c.post(
        "/api/image/scan",
        json={"image": "lab/app:latest", "host": "192.0.2.9", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
