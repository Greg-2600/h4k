"""Backlog #73: Exploit-DB search + MSF delta + technology -> CVE."""

from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager
from typing import Any

import pytest
from services.vuln_intel import (
    analyze,
    catalog_info,
    msf_delta,
    sandbox_result,
    search_exploits,
    tech_to_cve,
    to_ledger,
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def test_bundled_snapshot_is_real_and_well_formed() -> None:
    info = catalog_info()
    assert info["count"] > 50
    assert info["generated"] == "2026-11-28"
    assert "exploit-db.com" in info["source"]
    assert "subset" in info["note"]
    ids = [entry["id"] for entry in search_exploits(limit=50)["entries"]]
    assert len(ids) == len(set(ids))


def test_search_by_keyword_cve_platform_type_and_limits() -> None:
    log4j = search_exploits("log4j")
    assert log4j["total"] >= 2
    assert log4j["entries"][0]["id"] == "EDB-50590"
    assert "title" in log4j["entries"][0]["matched_on"]

    by_cve = search_exploits(cve="2021-44228")
    assert by_cve["cve"] == "CVE-2021-44228"
    assert by_cve["total"] == 3
    assert all("CVE-2021-44228" in entry["cves"] for entry in by_cve["entries"])

    by_id = search_exploits("EDB-42315")
    assert [entry["id"] for entry in by_id["entries"]] == ["EDB-42315"]
    assert "id" in by_id["entries"][0]["matched_on"]

    local_windows = search_exploits("", platform="Windows", etype="local")
    assert local_windows["total"] >= 1
    assert all(
        entry["platform"] == "Windows" and entry["type"] == "local"
        for entry in local_windows["entries"]
    )

    verified = search_exploits("", verified_only=True, limit=50)
    assert verified["total"] >= 1
    assert all(entry["verified"] for entry in verified["entries"])

    limited = search_exploits("", limit=3)
    assert limited["total"] == catalog_info()["count"]
    assert limited["count"] == 3
    assert len(limited["entries"]) == 3

    assert search_exploits("does-not-exist-anywhere")["entries"] == []
    with pytest.raises(ValueError, match="limit"):
        search_exploits(limit=0)
    with pytest.raises(ValueError, match="limit"):
        search_exploits(limit="many")


def test_msf_delta_names_new_modules_and_links_known_cves() -> None:
    delta = msf_delta(
        [
            "exploit/multi/http/log4shell_header_injection",
            "auxiliary/scanner/ssh/ssh_enumusers",
        ],
        [
            "auxiliary/scanner/ssh/ssh_enumusers",
            "exploit/multi/http/apache_normalize_path_rce",
        ],
    )
    assert delta["baseline_provided"] is True
    assert delta["current_count"] == 2
    assert delta["baseline_count"] == 2
    assert delta["persisted_count"] == 1
    assert delta["added"] == ["exploit/multi/http/log4shell_header_injection"]
    assert delta["removed"] == ["exploit/multi/http/apache_normalize_path_rce"]
    assert delta["added_with_cve"] == [
        {
            "module": "exploit/multi/http/log4shell_header_injection",
            "cve": "CVE-2021-44228",
        }
    ]
    as_objects = msf_delta([{"module": "exploit/a"}], [{"fullname": "exploit/b"}])
    assert as_objects["added"] == ["exploit/a"]
    assert as_objects["removed"] == ["exploit/b"]
    assert msf_delta(["exploit/a"], None)["baseline_provided"] is False
    with pytest.raises(ValueError, match="modules must be a list"):
        msf_delta("exploit/a", [])
    with pytest.raises(ValueError, match="modules must be strings"):
        msf_delta([123], [])


def test_technology_to_cve_is_version_aware() -> None:
    items = tech_to_cve(
        [
            "vsftpd 2.3.4",
            "vsftpd 3.0.3",
            "log4j 2.14.1",
            "apache 2.4.49",
            "apache 2.4.51",
            {"name": "smb"},
        ]
    )
    results = {(item["name"], item["version"]): item for item in items}
    assert [cve["id"] for cve in results[("vsftpd", "2.3.4")]["cves"]] == [
        "CVE-2011-2523"
    ]
    assert results[("vsftpd", "2.3.4")]["cves"][0]["_version_verified"] is True
    assert results[("vsftpd", "2.3.4")]["cves"][0]["exploits"]
    # A patched version outside every known range is not reported.
    assert results[("vsftpd", "3.0.3")]["cve_count"] == 0
    assert results[("apache", "2.4.51")]["cve_count"] == 0
    assert results[("apache", "2.4.49")]["cve_count"] == 1
    assert results[("log4j", "2.14.1")]["cve_count"] == 1
    assert results[("log4j", "2.14.1")]["cves"][0]["_version_verified"] is False
    assert results[("smb", "")]["cve_count"] >= 3
    assert all(
        cve["_version_verified"] is False for cve in results[("smb", "")]["cves"]
    )
    with pytest.raises(ValueError, match="technologies must be a list"):
        tech_to_cve("nginx 1.18.0")
    with pytest.raises(ValueError, match="strings or objects"):
        tech_to_cve([123])


def test_analyze_validates_input_and_combines_sections() -> None:
    with pytest.raises(ValueError, match="required"):
        analyze()
    with pytest.raises(ValueError, match="technologies must be a list"):
        analyze(technologies="log4j")
    with pytest.raises(ValueError, match="baseline_modules must be a list"):
        analyze(modules=["exploit/a"], baseline_modules="exploit/b")
    result = analyze(
        exploit_query="log4j",
        technologies=[{"name": "log4j", "version": "2.14.1"}],
        modules=["exploit/multi/http/log4shell_header_injection"],
        baseline_modules=["exploit/multi/http/apache_normalize_path_rce"],
    )
    assert result["sandbox"] is False
    assert result["catalog"]["count"] > 50
    assert result["exploits"]["count"] >= 2
    assert result["msf_delta"]["added_count"] == 1
    assert result["technologies"][0]["cve_count"] == 1
    assert result["summary"] == {
        "exploit_matches": result["exploits"]["count"],
        "technologies": 1,
        "technology_cves": 1,
        "technology_exploits": result["technologies"][0]["exploit_count"],
        "msf_added": 1,
        "msf_added_with_cve": 1,
    }
    assert "No network" not in result["limitations"]
    assert "Offline" in result["limitations"]


def test_ledger_rows_cover_linked_cves_and_new_modules() -> None:
    result = analyze(
        technologies=[{"name": "vsftpd", "version": "2.3.4"}],
        modules=["exploit/multi/http/log4shell_header_injection"],
        baseline_modules=[],
    )
    rows = to_ledger("10.10.10.77", result)
    assert {row["module"] for row in rows} == {"vuln-intel", "msf-delta"}
    assert {row["reference"] for row in rows} == {"CVE-2011-2523", "CVE-2021-44228"}
    assert all(row["host"] == "10.10.10.77" for row in rows)
    assert all(row["cwe"] == "CWE-1104" for row in rows)
    assert len({(row["name"], row["reference"]) for row in rows}) == len(rows)


def test_sandbox_result_is_canned_and_deterministic() -> None:
    result = sandbox_result()
    assert result == sandbox_result()
    assert result["sandbox"] is True
    assert result["exploits"]["count"] >= 1
    assert result["technologies"][0]["name"] == "log4j"
    assert result["msf_delta"]["added_count"] == 1
    assert len(to_ledger("h", result)) >= 2
    json.dumps(result)


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


def test_router_sandbox_validation_and_ledger(tmp_path: Any, monkeypatch: Any) -> None:
    client = _client(tmp_path, monkeypatch, sandbox=True)
    response = client.post(
        "/api/source/vuln-intel",
        json={"exploit_query": "ignored", "technologies": ["ignored"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is True
    assert body["exploits"]["count"] >= 1
    assert client.post("/api/source/vuln-intel", json={}).status_code == 400
    assert (
        client.post(
            "/api/source/vuln-intel",
            json={"modules": ["exploit/a"], "engagement_id": "nope"},
        ).status_code
        == 404
    )

    engagement = client.post("/api/engagement/sandbox-seed").json()["engagement"]
    response = client.post(
        "/api/source/vuln-intel",
        json={
            "exploit_query": "log4j",
            "technologies": [{"name": "log4j", "version": "2.14.1"}],
            "host": "10.10.10.77",
            "engagement_id": engagement["id"],
        },
    )
    assert response.status_code == 200
    assert response.json()["ingested"] >= 2
    vulns = client.get(f"/api/engagement/{engagement['id']}/vulns/effective").json()
    assert "vuln-intel" in str(vulns)

    out_of_scope = client.post(
        "/api/source/vuln-intel",
        json={
            "technologies": [{"name": "log4j", "version": "2.14.1"}],
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
        "/api/source/vuln-intel",
        json={
            "exploit_query": "log4j",
            "technologies": [
                {"name": "vsftpd", "version": "2.3.4"},
                {"name": "apache", "version": "2.4.51"},
            ],
            "modules": ["exploit/multi/http/log4shell_header_injection"],
            "baseline_modules": ["exploit/multi/http/apache_normalize_path_rce"],
            "exploit_limit": 2,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is False
    assert body["catalog"]["count"] > 50
    assert body["exploits"]["count"] == 2
    assert body["technologies"][0]["cves"][0]["id"] == "CVE-2011-2523"
    assert body["technologies"][1]["cve_count"] == 0
    assert body["msf_delta"]["added"] == [
        "exploit/multi/http/log4shell_header_injection"
    ]
    assert body["summary"]["msf_added_with_cve"] == 1

    assert (
        client.post("/api/source/vuln-intel", json={"technologies": [123]}).status_code
        == 400
    )
    assert (
        client.post(
            "/api/source/vuln-intel",
            json={"modules": [123]},
        ).status_code
        == 400
    )
