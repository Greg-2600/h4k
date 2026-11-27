"""Backlog #67: vulnerable-dependency → sink paths + VEX statements."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from services.taint_pack import parse_bundle
from services.vuln_vex import analyze, sandbox_result, to_ledger

BUNDLE = """=== app.py ===
import yaml
def load_config():
    raw = request.args.get('cfg')
    return yaml.load(raw)
=== clean.py ===
import yaml
def load(p):
    return yaml.safe_load(open(p))
=== util.js ===
const _ = require('lodash');
function merge(q) { return _.merge({}, q); }
"""

DEPS: list[dict[str, Any]] = [
    {
        "name": "pyyaml",
        "version": "3.13",
        "cve": "CVE-2017-18342",
        "severity": "CRITICAL",
        "fixed_version": "5.1",
    },
    {
        "name": "lodash",
        "version": "4.17.11",
        "cve": "CVE-2019-10744",
        "severity": "CRITICAL",
    },
]


def _bundle(*blocks: str) -> list[dict[str, str]]:
    return [
        {"path": path, "content": content}
        for path, content in (block.split("|", 1) for block in blocks)
    ]


def test_vulnerable_dependency_to_sink_path() -> None:
    result = analyze(DEPS, parse_bundle(BUNDLE))
    affected = [s for s in result["statements"] if s["status"] == "affected"]
    assert [s["cve"] for s in affected] == ["CVE-2017-18342"]
    assert result["affected"] == 1
    assert result["not_affected"] == 1
    assert result["matched_rules"] == 2
    assert result["path_count"] == 1
    path = result["paths"][0]
    assert path["file"] == "app.py"
    assert path["sink_line"] == 4
    assert "request.args" in path["source"]
    assert path["cwe"] == "CWE-502"
    assert "line 3" in path["evidence"]
    assert "not a runtime proof" in result["limitations"]
    assert result["sandbox"] is False


def test_not_affected_when_component_not_imported() -> None:
    result = analyze([DEPS[1]], _bundle("app.py|import os\nx = os.getcwd()\n"))
    statement = result["statements"][0]
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "component_not_imported"
    assert statement["justification_type"] == "component_not_present"
    assert result["path_count"] == 0


def test_not_affected_when_no_tainted_sink() -> None:
    result = analyze(
        [DEPS[0]],
        _bundle(
            "app.py|import yaml\ndef go():\n    return yaml.safe_load(open('c'))\n"
        ),
    )
    statement = result["statements"][0]
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "no_tainted_path_in_provided_sources"
    assert statement["justification_type"] == "vulnerable_code_not_in_execute_path"
    assert "app.py:1" in statement["justification_detail"]


def test_sanitizer_in_window_clears_the_path() -> None:
    result = analyze(
        [DEPS[0]],
        _bundle(
            "app.py|import yaml\n"
            "raw = request.args.get('cfg')\n"
            "yaml.load(shlex.quote(raw))\n"
        ),
    )
    assert result["statements"][0]["status"] == "not_affected"
    assert result["path_count"] == 0


def test_operator_justification_overrides_verdict() -> None:
    files = _bundle(
        "app.py|import yaml\nraw = request.args.get('cfg')\nyaml.load(raw)\n"
    )
    result = analyze(
        DEPS,
        files,
        justifications=[
            {
                "cve": "CVE-2017-18342",
                "reason": "loader only receives an operator-controlled file",
            }
        ],
    )
    statement = result["statements"][0]
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "operator_assertion"
    assert statement["justification_type"] == "operator_assertion"
    assert "operator-controlled" in statement["justification_detail"]
    assert statement["source"] == "operator"
    assert statement["path_count"] == 1
    assert to_ledger("h", result["statements"]) == []


def test_package_keyed_justification_and_custom_type() -> None:
    result = analyze(
        DEPS[:1],
        _bundle("app.py|import yaml\nraw = request.args['x']\nyaml.load(raw)\n"),
        justifications=[
            {
                "package": "PyYAML",
                "reason": "config loader is not reachable from the web tier",
                "justification_type": "vulnerable_code_not_in_execute_path",
            }
        ],
    )
    assert result["statements"][0]["status"] == "not_affected"
    assert result["statements"][0]["justification_type"] == "operator_assertion"
    assert result["affected"] == 0


def test_maven_and_scoped_package_names_resolve() -> None:
    maven = analyze(
        [{"name": "org.apache.logging.log4j:log4j-core", "cve": "CVE-2021-44228"}],
        _bundle(
            "App.java|import org.apache.logging.log4j.Logger;\n"
            "String x = request.getParameter('q');\n"
            "LOGGER.info('${jndi:ldap://x}');\n"
        ),
    )
    assert maven["statements"][0]["status"] == "affected"
    assert maven["statements"][0]["cwe"] == "CWE-917"
    scoped = analyze(
        [{"name": "@scope/yaml", "cve": "CVE-2017-18342"}],
        _bundle("app.js|import yaml from 'yaml'\nraw = req.query.x\nyaml.load(raw)\n"),
    )
    assert scoped["statements"][0]["status"] == "affected"


def test_unknown_library_is_under_investigation() -> None:
    result = analyze(
        [{"name": "mystery", "cve": "CVE-2020-0001"}],
        _bundle("app.py|import mystery\nmystery.do_thing(x)\n"),
    )
    statement = result["statements"][0]
    assert statement["status"] == "under_investigation"
    assert statement["justification"] == "no_library_rule"
    assert result["not_affected"] == 0
    assert result["affected"] == 0


def test_purl_and_multiple_cves() -> None:
    result = analyze(
        [
            {
                "purl": "pkg:pypi/PyYAML@3.13",
                "cves": ["CVE-A", "CVE-B"],
            }
        ],
        _bundle("app.py|import yaml\nraw = request.args['x']\nyaml.load(raw)\n"),
    )
    assert [s["cve"] for s in result["statements"]] == ["CVE-A", "CVE-B"]
    assert all(s["status"] == "affected" for s in result["statements"])
    assert result["cves"] == ["CVE-A", "CVE-B"]
    assert result["path_count"] == 2


def test_bad_entries_rejected() -> None:
    files = _bundle("app.py|import yaml\nyaml.load(x)\n")
    with pytest.raises(ValueError, match="dependencies required"):
        analyze([], files)
    with pytest.raises(ValueError, match="bundle or files required"):
        analyze(DEPS, [])
    with pytest.raises(ValueError, match="name or purl required"):
        analyze([{"cve": "CVE-X"}], files)
    with pytest.raises(ValueError, match="justification reason required"):
        analyze(DEPS, files, justifications=[{"cve": "CVE-X"}])
    with pytest.raises(ValueError, match="justification needs cve or package"):
        analyze(DEPS, files, justifications=[{"reason": "why"}])
    with pytest.raises(ValueError, match="justification entries must be objects"):
        analyze(DEPS, files, justifications=["not-an-object"])
    with pytest.raises(ValueError, match="dependency entries must be objects"):
        analyze(["not-an-object"], files)


def test_deterministic_and_ledger_shape() -> None:
    files = _bundle("app.py|import yaml\nraw = request.args['x']\nyaml.load(raw)\n")
    assert analyze(DEPS[:1], files) == analyze(DEPS[:1], files)
    rows = to_ledger("10.10.10.5", analyze(DEPS[:1], files)["statements"])
    assert len(rows) == 1
    assert rows[0]["module"] == "vuln-vex"
    assert rows[0]["reference"] == "CVE-2017-18342"
    assert rows[0]["cwe"] == "CWE-502"
    assert "tainted_path_to_vulnerable_api" in rows[0]["detail"]
    assert to_ledger("h", []) == []


def test_sandbox_result_is_canned_and_ledgers() -> None:
    result = sandbox_result()
    assert result["sandbox"] is True
    assert result["affected"] == 1 and result["not_affected"] == 2
    assert result["path_count"] == 1
    statuses = {s["cve"]: s["status"] for s in result["statements"]}
    assert statuses["CVE-2019-10744"] == "not_affected"
    assert statuses["CVE-2021-44228"] == "not_affected"
    rows = to_ledger("h", result["statements"])
    assert len(rows) == 1 and rows[0]["reference"] == "CVE-2017-18342"
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
        "/api/source/vuln-vex",
        json={"bundle": BUNDLE, "dependencies": DEPS},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is True
    assert body["affected"] == 1 and body["not_affected"] == 2
    assert body["ingested"] == 0
    assert (
        client.post("/api/source/vuln-vex", json={"dependencies": DEPS}).status_code
        == 400
    )
    assert (
        client.post("/api/source/vuln-vex", json={"bundle": BUNDLE}).status_code == 400
    )
    assert (
        client.post(
            "/api/source/vuln-vex",
            json={"bundle": BUNDLE, "dependencies": DEPS, "engagement_id": "nope"},
        ).status_code
        == 404
    )

    engagement = client.post("/api/engagement/sandbox-seed").json()["engagement"]
    response = client.post(
        "/api/source/vuln-vex",
        json={
            "bundle": BUNDLE,
            "dependencies": DEPS,
            "host": "10.10.10.77",
            "engagement_id": engagement["id"],
        },
    )
    assert response.status_code == 200
    assert response.json()["ingested"] == 1
    vulns = client.get(f"/api/engagement/{engagement['id']}/vulns/effective").json()
    assert "vuln-vex" in str(vulns)

    out_of_scope = client.post(
        "/api/source/vuln-vex",
        json={
            "bundle": BUNDLE,
            "dependencies": DEPS,
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
        "/api/source/vuln-vex",
        json={
            "files": _bundle(
                "app.py|import yaml\nraw = request.args['x']\nyaml.load(raw)\n"
            ),
            "dependencies": DEPS[:1],
            "justifications": [],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is False
    assert body["affected"] == 1 and body["path_count"] == 1
    assert body["statements"][0]["cve"] == "CVE-2017-18342"

    bad = client.post(
        "/api/source/vuln-vex",
        json={
            "files": [{"path": "a.py", "content": "import yaml"}],
            "dependencies": [{}],
        },
    )
    assert bad.status_code == 400
