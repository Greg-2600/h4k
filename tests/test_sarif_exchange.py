"""Backlog #61: SARIF import/export — Semgrep interchange."""

from __future__ import annotations

from typing import Any

from services.sarif_exchange import h4k_to_sarif, sandbox_roundtrip, sarif_to_h4k

SEMGREP_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep OSS",
                    "version": "1.80.0",
                    "rules": [
                        {
                            "id": "python.lang.security.audit.exec-detected",
                            "name": "dynamic-execution-detected",
                            "shortDescription": {"text": "exec() with user input"},
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {
                                "tags": ["security", "CWE-95"],
                                "precision": "high",
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python.lang.security.audit.exec-detected",
                    "ruleIndex": 0,
                    "level": "warning",
                    "message": {"text": "exec() with user input"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app.py"},
                                "region": {
                                    "startLine": 42,
                                    "startColumn": 5,
                                    "endLine": 42,
                                    "endColumn": 20,
                                },
                            }
                        }
                    ],
                },
                {"ruleId": "x", "level": "bogus-level"},
                "not-a-result",
            ],
        }
    ],
}

H4K_FINDINGS = [
    {
        "rule_id": "sast-secret-http",
        "name": "Hardcoded credential",
        "severity": "critical",
        "cwe": "CWE-798",
        "file": "app.py",
        "line": 12,
        "code": "token = 'x'",
        "description": "hardcoded",
    },
    {
        "rule_id": "sast-secret-http",
        "name": "Hardcoded credential",
        "severity": "critical",
        "cwe": "CWE-798",
        "file": "b.py",
        "line": 3,
        "code": "",
        "description": "hardcoded",
    },
    {
        "rule_id": "mystery",
        "name": "odd",
        "severity": "weird-level",
        "cwe": "",
        "file": "c.py",
        "line": "NaN",
    },
]


def test_export_levels_and_dedup() -> None:
    sarif = h4k_to_sarif(H4K_FINDINGS)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 2  # one rule deduped
    assert run["tool"]["driver"]["rules"][0]["properties"]["tags"] == [
        "security",
        "CWE-798",
    ]
    levels = [r["level"] for r in run["results"]]
    assert levels == ["error", "error", "warning"]  # unknown severity → warning
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
        == 12
    )
    assert run["results"][1]["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 3
    }
    with_sorted = h4k_to_sarif(H4K_FINDINGS, tool_name="x")
    assert with_sorted["runs"][0]["tool"]["driver"]["name"] == "x"


def test_import_semgrep_shape() -> None:
    out = sarif_to_h4k(SEMGREP_SARIF)
    assert out["tool"] == "Semgrep OSS"
    assert out["finding_count"] == 2  # "not-a-result" skipped with an error
    found = out["findings"][0]
    assert found["rule_id"] == "python.lang.security.audit.exec-detected"
    assert found["name"] == "dynamic-execution-detected"
    assert found["severity"] == "medium"  # warning → medium
    assert found["cwe"] == "CWE-95"  # picked up from the rule's tags
    assert found["file"] == "app.py" and found["line"] == 42
    assert found["origin"] == "Semgrep OSS"  # noted, not relabeled
    assert out["findings"][1]["file"] == "?"  # location-less still converts
    assert len(out["errors"]) == 1 and out["skipped"] == 0


def test_import_rejects() -> None:
    import pytest

    with pytest.raises(ValueError):
        sarif_to_h4k({})
    with pytest.raises(ValueError):
        sarif_to_h4k({"runs": []})
    with pytest.raises(ValueError):
        sarif_to_h4k([])  # type: ignore[arg-type]
    out = sarif_to_h4k({"version": "2.1.0", "runs": [{"tool": {}, "results": "nope"}]})
    assert out["finding_count"] == 0 and len(out["errors"]) == 1


def test_roundtrip_preserves() -> None:
    back = sarif_to_h4k(h4k_to_sarif(H4K_FINDINGS))
    by_file = {f["file"]: f for f in back["findings"]}
    assert by_file["app.py"]["cwe"] == "CWE-798"
    assert by_file["app.py"]["severity"] == "critical"
    assert by_file["app.py"]["line"] == 12
    assert by_file["app.py"]["code"] == "token = 'x'"
    assert len(back["findings"]) == 3


def test_sandbox_shapes() -> None:
    res = sandbox_roundtrip()
    assert res["sarif_result_count"] == 1 and res["lossless"] is True
    assert res["roundtrip"]["finding_count"] == 1


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


def test_sarif_router(tmp_path: Any, monkeypatch: Any) -> None:
    import json

    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/source/sarif/export", json={"findings": H4K_FINDINGS})
    assert r.status_code == 200
    assert r.json()["sarif"]["version"] == "2.1.0"
    assert c.post("/api/source/sarif/export", json={"findings": []}).status_code == 400

    r = c.post("/api/source/sarif/import", json={"sarif": SEMGREP_SARIF})
    assert r.status_code == 200
    body = r.json()
    # Sandbox answers the canned round-trip regardless of the paste
    # (live parsing is covered by unit tests).
    assert body["finding_count"] == 1 and body["tool"] == "h4k-sast"
    assert body["findings"][0]["cwe"] == "CWE-798"
    assert c.post("/api/source/sarif/import", json={"sarif": {}}).status_code == 400
    assert c.post("/api/source/sarif/import", json={"sarif": "{bad"}).status_code == 400
    assert (
        c.post(
            "/api/source/sarif/import", json={"sarif": json.dumps(SEMGREP_SARIF)}
        ).status_code
        == 200
    )
