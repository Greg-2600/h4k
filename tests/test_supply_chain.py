"""Backlog #68: typosquat heuristics + SLSA/build-info provenance ingest."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from services.supply_chain import analyze, sandbox_result, to_ledger


def _v1_provenance() -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "pkg:npm/acme-app@1.2.3", "digest": {"sha256": "a" * 64}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "externalParameters": {
                    "source": {"uri": "git+https://github.com/acme/app@abc123"}
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/acme/app@abc123",
                        "digest": {"gitCommit": "abc123"},
                    }
                ],
            },
            "runDetails": {"builder": {"id": "https://github.com/actions/runner"}},
        },
    }


def _v02_provenance() -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {"name": "pkg:pypi/acme-lib@0.9.0", "digest": {"sha256": "b" * 64}}
        ],
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "predicate": {
            "builder": {"id": "https://localhost/builder"},
            "materials": [],
        },
    }


def test_typosquat_edit_distance() -> None:
    result = analyze(packages=[{"name": "reqeusts", "ecosystem": "pypi"}])
    verdict = result["packages"][0]
    assert verdict["verdict"] == "suspicious"
    assert verdict["severity"] == "HIGH"
    kinds = {signal["kind"] for signal in verdict["signals"]}
    assert "typosquat" in kinds
    assert verdict["signals"][0]["target"] == "requests"
    assert result["suspicious_count"] == 1
    assert result["typosquats"] == [verdict]


def test_exact_popular_and_allowlisted_are_ok() -> None:
    result = analyze(packages=["requests", "react"])
    assert [v["verdict"] for v in result["packages"]] == ["ok", "ok"]
    assert result["suspicious_count"] == 0
    suppressed = analyze(packages=["reqeusts"], allowlist=["Reqeusts"])
    assert suppressed["packages"][0]["verdict"] == "ok"


def test_homoglyph_ascii_and_unicode() -> None:
    ascii_result = analyze(packages=[{"name": "reques7s", "ecosystem": "pypi"}])
    assert ascii_result["packages"][0]["signals"][0]["kind"] == "homoglyph"
    unicode_result = analyze(packages=[{"name": "r\u0435quests", "ecosystem": "pypi"}])
    assert unicode_result["packages"][0]["signals"][0]["kind"] == "homoglyph"
    assert unicode_result["packages"][0]["signals"][0]["target"] == "requests"


def test_non_ascii_without_a_target_is_a_lead() -> None:
    result = analyze(packages=["zz\u0430"])
    assert result["packages"][0]["signals"][0]["kind"] == "non_ascii"
    assert result["packages"][0]["verdict"] == "suspicious"


def test_separator_and_combosquat() -> None:
    separator = analyze(packages=[{"name": "react.dom", "ecosystem": "npm"}])
    assert separator["packages"][0]["signals"][0]["kind"] == "separator_confusion"
    combos = analyze(packages=[{"name": "python_requests", "ecosystem": "pypi"}])
    assert combos["packages"][0]["signals"][0]["kind"] == "combosquat"
    trailing = analyze(packages=[{"name": "lodash3", "ecosystem": "npm"}])
    assert trailing["packages"][0]["signals"][0]["kind"] == "combosquat"
    legit = analyze(packages=[{"name": "react-dom", "ecosystem": "npm"}])
    assert legit["packages"][0]["verdict"] == "ok"


def test_scope_confusion() -> None:
    evil = analyze(packages=[{"name": "@evil/lodash", "ecosystem": "npm"}])
    assert evil["packages"][0]["signals"][0]["kind"] == "scope_confusion"
    trusted = analyze(packages=[{"name": "@types/react", "ecosystem": "npm"}])
    assert trusted["packages"][0]["verdict"] == "ok"


def test_purl_and_unknown_ecosystem() -> None:
    result = analyze(packages=["pkg:pypi/reqeusts@1.0.0"])
    verdict = result["packages"][0]
    assert verdict["name"] == "reqeusts"
    assert verdict["ecosystem"] == "pypi"
    assert verdict["version"] == "1.0.0"
    assert verdict["verdict"] == "suspicious"
    merged = analyze(packages=["react"])
    assert merged["packages"][0]["verdict"] == "ok"


def test_provenance_complete_v1() -> None:
    result = analyze(provenance=[_v1_provenance()])
    record = result["provenance"][0]
    assert record["flavor"] == "slsa-v1"
    assert record["status"] == "complete"
    assert record["score"] == 100
    assert record["builder"] == "https://github.com/actions/runner"
    assert record["digest"].startswith("sha256:")
    assert record["pinned"] is True
    assert record["materials"] == 1
    assert record["warnings"] == []
    assert result["provenance_complete"] == 1


def test_provenance_partial_v02() -> None:
    result = analyze(provenance=[_v02_provenance()])
    record = result["provenance"][0]
    assert record["flavor"] == "slsa-v0.2"
    assert record["status"] == "partial"
    assert record["score"] == 60
    assert "builder identity is local/loopback" in record["warnings"]
    assert "missing source uri" in record["warnings"]
    assert "no resolved materials" in record["warnings"]


def test_in_toto_statement_with_string_materials() -> None:
    result = analyze(
        provenance=[
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": "pkg:npm/acme-in-toto@2.0.0",
                        "digest": {"sha256": "e" * 64},
                    }
                ],
                "predicate": {
                    "builder": {"id": "https://ci.example/builder"},
                    "invocation": {
                        "configSource": {
                            "uri": "git+https://github.com/acme/in-toto@deadbeef"
                        }
                    },
                    "materials": ["git+https://github.com/acme/in-toto@deadbeef"],
                },
            }
        ]
    )
    record = result["provenance"][0]
    assert record["flavor"] == "in-toto"
    assert record["status"] == "complete"
    assert record["materials"] == 1
    assert record["pinned"] is True
    assert record["warnings"] == []


def test_slsa_v01_with_dict_subject() -> None:
    result = analyze(
        provenance=[
            {
                "_type": "https://in-toto.io/Statement/v0.1",
                "subject": {
                    "name": "pkg:pypi/acme-old@1.0",
                    "digest": {"gitCommit": "abc123"},
                },
                "predicateType": "https://slsa.dev/provenance/v0.1",
                "predicate": {
                    "builder": {"id": "https://ci.example/builder"},
                    "invocation": {
                        "configSource": {
                            "uri": "git+https://github.com/acme/old@abc123"
                        }
                    },
                    "materials": [],
                },
            }
        ]
    )
    record = result["provenance"][0]
    assert record["flavor"] == "slsa-v0.1"
    assert record["digest"] == "gitCommit:abc123"
    assert record["status"] == "complete"
    assert "no resolved materials" in record["warnings"]


def test_generic_build_info_record() -> None:
    result = analyze(
        provenance=[
            {
                "package": "acme-wheel",
                "version": "2.0.0",
                "builder": "https://ci.example/build",
                "source": "https://github.com/acme/wheel@deadbeef",
                "digest": {"sha256": "c" * 64},
                "materials": [{"uri": "git+https://github.com/acme/wheel@deadbeef"}],
            }
        ]
    )
    record = result["provenance"][0]
    assert record["flavor"] == "build-info"
    assert record["status"] == "complete"
    assert record["package"] == "acme-wheel"


def test_provenance_unknown_and_unpinned() -> None:
    unknown = analyze(provenance=[{"package": "mystery-wheel", "version": "1"}])
    record = unknown["provenance"][0]
    assert record["status"] == "unknown"
    assert record["score"] == 0
    assert "unrecognized provenance format" in record["warnings"]

    unpinned = analyze(
        provenance=[
            {
                "package": "loose",
                "builder": "https://ci.example/build",
                "source": "https://github.com/acme/loose",
                "digest": {"sha256": "d" * 64},
                "materials": [{"uri": "https://github.com/acme/loose"}],
            }
        ]
    )
    assert unpinned["provenance"][0]["status"] == "partial"
    assert unpinned["provenance"][0]["pinned"] is False
    assert "source is not pinned to a commit/digest" in (
        unpinned["provenance"][0]["warnings"]
    )


def test_missing_subject_digest_is_partial() -> None:
    record = _v1_provenance()
    record["subject"] = [{"name": "pkg:npm/acme-app@1.2.3"}]
    result = analyze(provenance=[record])
    assert result["provenance"][0]["status"] == "partial"
    assert "subject has no digest" in result["provenance"][0]["warnings"]


def test_validation() -> None:
    with pytest.raises(ValueError, match="packages or provenance required"):
        analyze()
    with pytest.raises(ValueError, match="packages must be a list"):
        analyze(packages="requests")
    with pytest.raises(ValueError, match="provenance must be a list"):
        analyze(provenance={"package": "acme"})
    with pytest.raises(ValueError, match="package name required"):
        analyze(packages=[{}])
    with pytest.raises(ValueError, match="package entries must be strings or objects"):
        analyze(packages=[42])
    with pytest.raises(ValueError, match="provenance entries must be objects"):
        analyze(provenance=["not-an-object"])


def test_to_ledger_maps_signals_and_provenance_gaps() -> None:
    result = analyze(
        packages=[
            {"name": "reqeusts", "ecosystem": "pypi"},
            {"name": "requests", "ecosystem": "pypi"},
        ],
        provenance=[_v1_provenance(), _v02_provenance()],
    )
    rows = to_ledger("10.10.10.5", result)
    modules = sorted(row["module"] for row in rows)
    assert modules == ["provenance", "typosquat"]
    typo = next(row for row in rows if row["module"] == "typosquat")
    assert typo["severity"] == "HIGH"
    assert typo["cwe"] == "CWE-1357"
    assert "reqeusts" in typo["name"]
    assert "requests" in typo["reference"]
    prov = next(row for row in rows if row["module"] == "provenance")
    assert prov["severity"] == "MEDIUM"
    assert "partial" in prov["name"]
    assert to_ledger("h", {"typosquats": [], "provenance": []}) == []


def test_sandbox_result_is_canned_and_deterministic() -> None:
    result = sandbox_result()
    assert result["sandbox"] is True
    assert result["package_count"] == 4
    assert result["suspicious_count"] == 2
    assert result["provenance_count"] == 3
    assert result["provenance_complete"] == 1
    assert result["provenance_partial"] == 1
    assert result["provenance_unknown"] == 1
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
        "/api/source/supply-chain",
        json={"packages": ["reqeusts"], "provenance": [_v1_provenance()]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is True
    assert body["suspicious_count"] == 2
    assert body["ingested"] == 0
    assert client.post("/api/source/supply-chain", json={}).status_code == 400
    assert (
        client.post(
            "/api/source/supply-chain",
            json={"packages": ["reqeusts"], "engagement_id": "nope"},
        ).status_code
        == 404
    )

    engagement = client.post("/api/engagement/sandbox-seed").json()["engagement"]
    response = client.post(
        "/api/source/supply-chain",
        json={
            "packages": ["reqeusts"],
            "host": "10.10.10.77",
            "engagement_id": engagement["id"],
        },
    )
    assert response.status_code == 200
    assert response.json()["ingested"] == 4
    vulns = client.get(f"/api/engagement/{engagement['id']}/vulns/effective").json()
    assert "typosquat" in str(vulns)
    assert "provenance" in str(vulns)

    out_of_scope = client.post(
        "/api/source/supply-chain",
        json={
            "packages": ["reqeusts"],
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
        "/api/source/supply-chain",
        json={
            "packages": [
                {"name": "reqeusts", "ecosystem": "pypi"},
                {"name": "requests", "ecosystem": "pypi"},
            ],
            "provenance": [_v1_provenance(), _v02_provenance()],
            "allowlist": [],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is False
    assert body["suspicious_count"] == 1
    assert body["provenance_complete"] == 1
    assert body["provenance_partial"] == 1
    assert body["typosquats"][0]["name"] == "reqeusts"

    bad = client.post(
        "/api/source/supply-chain",
        json={"provenance": ["not-an-object"]},
    )
    assert bad.status_code == 400
