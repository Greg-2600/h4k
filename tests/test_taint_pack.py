"""Backlog #62: taint rules pack — source→sink Python/JS/PHP."""

from __future__ import annotations

from typing import Any

from services.taint_pack import parse_bundle, sandbox_result, scan_files, to_ledger

PY_VULN = """import os, sys
def ping():
    host = request.args.get('h')
    os.system('ping -c1 ' + host)
"""

PY_SAFE = """import os, shlex
def ping():
    host = request.args.get('h')
    os.system('ping -c1 ' + shlex.quote(host))
"""

PY_CLEAN = """def add(a, b):
    return a + b
"""

JS_VULN = """const name = req.query.name;
document.getElementById('x').innerHTML = name;
"""

PHP_VULN = """<?php
$n = $_GET['n'];
echo $n;
$res = mysql_query("SELECT * FROM u WHERE n='" . $_GET['n'] . "'");
?>"""

PHP_SAFE = """<?php
$n = $_GET['n'];
echo htmlspecialchars($n);
?>"""

BUNDLE = (
    "=== app.py ===\n"
    + PY_VULN
    + "\n=== safe.py ===\n"
    + PY_SAFE
    + "\n=== clean.py ===\n"
    + PY_CLEAN
    + "\n=== app.js ===\n"
    + JS_VULN
    + "\n=== index.php ===\n"
    + PHP_VULN
    + "\n=== safe.php ===\n"
    + PHP_SAFE
    + "\n=== README.md ===\n# docs\n"
)


def test_parse_bundle() -> None:
    files = parse_bundle(BUNDLE)
    assert [f["path"] for f in files] == [
        "app.py",
        "safe.py",
        "clean.py",
        "app.js",
        "index.php",
        "safe.php",
        "README.md",
    ]
    assert parse_bundle("   ") == []


def test_detects_tainted_flows() -> None:
    out = scan_files(parse_bundle(BUNDLE))
    rules = {f["rule_id"] for f in out["findings"]}
    assert "taint-py-cmd-injection" in rules
    assert "taint-js-xss" in rules
    assert "taint-php-sqli" in rules
    assert out["clean"] is False
    assert out["parsed"] == 6
    assert out["skipped"] == ["README.md"]


def test_sanitized_and_clean_pass() -> None:
    out = scan_files(
        [
            {"path": "safe.py", "content": PY_SAFE},
            {"path": "clean.py", "content": PY_CLEAN},
            {"path": "safe.php", "content": PHP_SAFE},
        ]
    )
    assert out == {
        "files": 3,
        "parsed": 3,
        "skipped": [],
        "findings": [],
        "finding_count": 0,
        "clean": True,
    }


def test_window_and_case() -> None:
    code = (
        "q = request.args['q']\n"
        + "\n".join(f"# pad {i}" for i in range(10))
        + "\neval(q)\n"
    )
    out = scan_files([{"path": "a.py", "content": code}])
    assert out["clean"] is True  # source outside the 6-line window
    close = "q = request.args['q']\nx = 1\neval(q)\n"
    out = scan_files([{"path": "a.py", "content": close}])
    assert any(f["rule_id"] == "taint-py-code-injection" for f in out["findings"])


def test_empty_bundle_rejected() -> None:
    import pytest

    with pytest.raises(ValueError):
        scan_files([])


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("taint-pack")
    assert res["finding_count"] == 2 and res["clean"] is False
    rows = to_ledger("10.10.10.77", "taint-pack", res["findings"])
    assert len(rows) == 2
    assert rows[0]["module"] == "taint-pack"
    assert rows[0]["cwe"] == "CWE-78"
    assert to_ledger("h", "p", []) == []


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


def test_taint_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/source/taint/scan",
        json={"bundle": BUNDLE, "host": "h"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0

    assert c.post("/api/source/taint/scan", json={"bundle": "  "}).status_code == 400

    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/source/taint/scan",
        json={"bundle": BUNDLE, "host": "10.10.10.77", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "taint taint-pack" in str(vulns)

    assert (
        c.post(
            "/api/source/taint/scan",
            json={"bundle": BUNDLE, "host": "h", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    r = c.post(
        "/api/source/taint/scan",
        json={"bundle": BUNDLE, "host": "192.0.2.9", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
