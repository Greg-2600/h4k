"""Backlog #69: license gate + SBOM diff + pin bot."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from services.supply_chain_policy import analyze, sandbox_result, to_ledger


def test_license_gate_defaults() -> None:
    result = analyze(
        current=[
            {"name": "a", "version": "1", "license": "MIT"},
            {"name": "b", "version": "1", "license": "GPL-3.0-only"},
            {"name": "c", "version": "1", "license": "MPL-2.0"},
            {"name": "d", "version": "1"},
            {"name": "e", "version": "1", "license": "Frobnicate-1.0"},
        ]
    )
    assert result["license_counts"] == {"allowed": 1, "warn": 3, "denied": 1}
    assert [row["name"] for row in result["denied"]] == ["b"]
    assert {row["name"] for row in result["warned"]} == {"c", "d", "e"}
    missing = next(row for row in result["warned"] if row["name"] == "d")
    assert missing["reason"] == "no license declared"
    unknown = next(row for row in result["warned"] if row["name"] == "e")
    assert unknown["matched"] == ["frobnicate-1.0"]


def test_license_expression_or_and_and_aliases() -> None:
    result = analyze(
        current=[
            {"name": "or", "version": "1", "license": "MIT OR GPL-3.0-only"},
            {"name": "and", "version": "1", "license": "MIT AND GPL-3.0-only"},
            {"name": "weak", "version": "1", "license": "MIT AND MPL-2.0"},
            {"name": "alias", "version": "1", "license": "Apache License 2.0"},
            {
                "name": "with",
                "version": "1",
                "license": "GPL-3.0-only WITH Classpath-exception-2.0",
            },
        ]
    )
    verdicts = {row["name"]: row["verdict"] for row in result["license_verdicts"]}
    assert verdicts == {
        "or": "allowed",
        "and": "denied",
        "weak": "warn",
        "alias": "allowed",
        "with": "denied",
    }


def test_license_overrides_win_over_defaults() -> None:
    denied = analyze(
        current=[{"name": "bsd", "version": "1", "license": "BSD-3-Clause"}],
        deny_licenses=["BSD-3-Clause"],
    )
    assert denied["license_verdicts"][0]["verdict"] == "denied"
    allowed = analyze(
        current=[{"name": "gpl", "version": "1", "license": "GPL-3.0-only"}],
        allow_licenses=["GPL-3.0-only"],
    )
    assert allowed["license_verdicts"][0]["verdict"] == "allowed"
    warned = analyze(
        current=[{"name": "zlib", "version": "1", "license": "Zlib"}],
        warn_licenses=["Zlib"],
    )
    assert warned["license_verdicts"][0]["verdict"] == "warn"


def test_sbom_diff_new_removed_upgrade_downgrade_and_cves() -> None:
    baseline = [
        {
            "name": "keep",
            "ecosystem": "pypi",
            "version": "1.0.0",
            "license": "MIT",
            "cves": ["CVE-OLD"],
        },
        {"name": "gone", "ecosystem": "pypi", "version": "2.0.0", "license": "MIT"},
        {"name": "up", "ecosystem": "pypi", "version": "1.0.0", "license": "MIT"},
        {"name": "down", "ecosystem": "pypi", "version": "2.0.0", "license": "MIT"},
        {"name": "same", "ecosystem": "pypi", "version": "1.0.0", "license": "MIT"},
    ]
    current = [
        {
            "name": "keep",
            "ecosystem": "pypi",
            "version": "1.0.0",
            "license": "MIT",
            "cves": ["CVE-NEW"],
        },
        {
            "name": "new",
            "ecosystem": "pypi",
            "version": "0.1.0",
            "license": "MIT",
            "cves": ["CVE-NEWDEP"],
        },
        {"name": "up", "ecosystem": "pypi", "version": "1.1.0", "license": "MIT"},
        {"name": "down", "ecosystem": "pypi", "version": "1.9.0", "license": "MIT"},
        {"name": "same", "ecosystem": "pypi", "version": "1.0.0", "license": "MIT"},
    ]
    diff = analyze(baseline=baseline, current=current)["diff"]
    assert [row["name"] for row in diff["new"]] == ["new"]
    assert [row["name"] for row in diff["removed"]] == ["gone"]
    assert diff["new_count"] == 1
    assert diff["removed_count"] == 1
    assert diff["changed_count"] == 2
    directions = {row["name"]: row["direction"] for row in diff["changed"]}
    assert directions == {"down": "downgrade", "up": "upgrade"}
    assert {row["cve"] for row in diff["new_cves"]} == {"CVE-NEW", "CVE-NEWDEP"}
    assert [row["cve"] for row in diff["resolved_cves"]] == ["CVE-OLD"]


def test_license_change_is_reported_as_changed() -> None:
    diff = analyze(
        baseline=[{"name": "lib", "version": "1", "license": "MIT"}],
        current=[{"name": "lib", "version": "1", "license": "Apache-2.0"}],
    )["diff"]
    assert diff["changed_count"] == 1
    assert diff["changed"][0]["direction"] == "license"
    assert diff["changed"][0]["license_changed"] is True


def test_pin_bot_suggests_upgrades_pins_and_security_fixes() -> None:
    result = analyze(
        baseline=[
            {"name": "vuln", "ecosystem": "pypi", "version": "1.0.0", "license": "MIT"}
        ],
        current=[
            {
                "name": "floating",
                "ecosystem": "npm",
                "version": "^1.2.0",
                "license": "MIT",
                "resolved": "1.2.5",
                "latest": "1.3.0",
            },
            {
                "name": "exact",
                "ecosystem": "pypi",
                "version": "2.0.0",
                "license": "MIT",
                "latest": "2.1.0",
            },
            {
                "name": "vuln",
                "ecosystem": "pypi",
                "version": "1.0.0",
                "license": "MIT",
                "cves": [{"id": "CVE-X", "fixed_version": "1.0.1"}],
            },
        ],
    )
    pins = {(row["name"], row["to"]): row for row in result["pin_bot"]}
    assert result["pin_count"] == 4
    assert pins[("floating", "1.3.0")]["kind"] == "pin"
    assert pins[("floating", "1.3.0")]["pinned"] == "floating@1.3.0"
    assert pins[("floating", "1.2.5")]["kind"] == "pin"
    assert pins[("exact", "2.1.0")]["kind"] == "upgrade"
    assert pins[("exact", "2.1.0")]["pinned"] == "exact==2.1.0"
    assert pins[("vuln", "1.0.1")]["kind"] == "security"
    assert "CVE-X" in pins[("vuln", "1.0.1")]["reason"]


def test_cyclonedx_components_and_purl_inputs() -> None:
    result = analyze(
        baseline=["pkg:pypi/lib@1.0"],
        current={
            "components": [
                {
                    "name": "lib",
                    "version": "1.0",
                    "purl": "pkg:pypi/lib@1.0",
                    "licenses": [{"license": {"id": "MIT"}}],
                    "cves": [{"id": "cve-2024-1", "severity": "high"}],
                }
            ]
        },
    )
    assert result["baseline_count"] == 1
    assert result["current_count"] == 1
    assert result["license_counts"]["allowed"] == 1
    assert result["diff"]["new_count"] == 0
    assert result["diff"]["new_cves"][0]["cve"] == "CVE-2024-1"
    assert result["diff"]["new_cves"][0]["severity"] == "HIGH"


def test_validation() -> None:
    with pytest.raises(ValueError, match="current dependencies required"):
        analyze()
    with pytest.raises(ValueError, match="current must be a list or an SBOM object"):
        analyze(current="not-a-list")
    with pytest.raises(ValueError, match="baseline must be a list or an SBOM object"):
        analyze(baseline={"dependencies": []}, current=["lib"])
    with pytest.raises(
        ValueError, match="dependency entries must be strings or objects"
    ):
        analyze(current=[42])
    with pytest.raises(ValueError, match="dependency name required"):
        analyze(current=[{}])


def test_to_ledger_maps_license_and_cve_findings() -> None:
    result = analyze(
        baseline=[{"name": "vuln", "version": "1.0.0", "license": "MIT"}],
        current=[
            {"name": "denied", "version": "1", "license": "GPL-3.0-only"},
            {"name": "warned", "version": "1", "license": "MPL-2.0"},
            {
                "name": "vuln",
                "version": "1.0.0",
                "license": "MIT",
                "cves": [{"id": "CVE-2024-9", "severity": "critical"}],
            },
        ],
    )
    rows = to_ledger("10.10.10.5", result)
    assert sorted(row["module"] for row in rows) == ["license", "license", "sbom-diff"]
    denied = next(row for row in rows if row["name"].startswith("license GPL"))
    assert denied["severity"] == "HIGH"
    assert denied["cwe"] == "CWE-1357"
    warned = next(row for row in rows if row["name"].startswith("license review"))
    assert warned["severity"] == "LOW"
    cve = next(row for row in rows if row["module"] == "sbom-diff")
    assert cve["severity"] == "CRITICAL"
    assert cve["reference"] == "CVE-2024-9"
    assert to_ledger("h", {}) == []


def test_sandbox_result_is_canned_and_deterministic() -> None:
    result = sandbox_result()
    assert result["sandbox"] is True
    assert result["baseline_count"] == 3
    assert result["current_count"] == 5
    assert result["license_counts"] == {"allowed": 2, "warn": 2, "denied": 1}
    assert result["diff"]["new_count"] == 3
    assert result["diff"]["removed_count"] == 1
    assert result["pin_count"] == 2
    assert len(to_ledger("h", result)) == 4
    assert sandbox_result() == result


def _client(tmp_path: Any, monkeypatch: Any, sandbox: bool) -> Any:
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1" if sandbox else "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_router_sandbox_and_validation(tmp_path: Any, monkeypatch: Any) -> None:
    client = _client(tmp_path, monkeypatch, sandbox=True)
    response = client.post(
        "/api/source/supply-chain/policy",
        json={"current": ["lodash@4.17.20"], "baseline": []},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is True
    assert body["current_count"] == 5
    assert body["license_counts"] == {"allowed": 2, "warn": 2, "denied": 1}
    assert body["ingested"] == 0
    assert client.post("/api/source/supply-chain/policy", json={}).status_code == 400
    assert (
        client.post(
            "/api/source/supply-chain/policy",
            json={"current": ["lodash"], "engagement_id": "nope"},
        ).status_code
        == 404
    )

    engagement = client.post("/api/engagement/sandbox-seed").json()["engagement"]
    response = client.post(
        "/api/source/supply-chain/policy",
        json={
            "current": ["lodash@4.17.20"],
            "host": "10.10.10.77",
            "engagement_id": engagement["id"],
        },
    )
    assert response.status_code == 200
    assert response.json()["ingested"] == 4
    vulns = client.get(f"/api/engagement/{engagement['id']}/vulns/effective").json()
    assert "license" in str(vulns)
    assert "sbom-diff" in str(vulns)

    out_of_scope = client.post(
        "/api/source/supply-chain/policy",
        json={
            "current": ["lodash@4.17.20"],
            "host": "203.0.113.9",
            "engagement_id": engagement["id"],
        },
    )
    assert out_of_scope.status_code == 200
    assert out_of_scope.json()["ingested"] == 0
    assert out_of_scope.json()["skipped_out_of_scope"] == ["203.0.113.9"]


def test_router_real_analysis_without_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
    client = _client(tmp_path, monkeypatch, sandbox=False)
    response = client.post(
        "/api/source/supply-chain/policy",
        json={
            "baseline": [
                {"name": "lib", "version": "1.0.0", "license": "MIT"},
            ],
            "current": [
                {
                    "name": "lib",
                    "version": "1.1.0",
                    "license": "GPL-3.0-only",
                    "cves": [{"id": "CVE-2024-1", "fixed_version": "1.1.1"}],
                }
            ],
            "allow_licenses": ["MIT"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is False
    assert body["license_counts"]["denied"] == 1
    assert body["diff"]["changed"][0]["direction"] == "upgrade"
    assert body["diff"]["new_cves"][0]["cve"] == "CVE-2024-1"
    assert body["pin_bot"][0]["to"] == "1.1.1"

    bad = client.post(
        "/api/source/supply-chain/policy",
        json={"current": "not-a-list"},
    )
    assert bad.status_code == 400
