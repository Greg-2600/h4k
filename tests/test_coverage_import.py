"""Backlog #60: coverage HTML import — llvm-cov badge in UI."""

from __future__ import annotations

import json
from typing import Any

import pytest
from services.coverage_import import (
    load_import,
    parse_export,
    sandbox_result,
    store_import,
    with_badge,
)

EXPORT = {
    "data": [
        {
            "files": [
                {
                    "filename": "vuln.c",
                    "summary": {
                        "lines": {"covered": 60, "count": 70},
                        "regions": {"covered": 30, "count": 35},
                        "functions": {"covered": 5, "count": 5},
                        "branches": {"covered": 10, "count": 20},
                    },
                },
                {
                    "filename": "main.c",
                    "summary": {
                        "lines": {"covered": 27, "count": 30},
                        "regions": {"covered": 11, "count": 15},
                        "functions": {"covered": 4, "count": 5},
                        "branches": {"covered": 20, "count": 20},
                    },
                },
            ],
            "totals": {
                "lines": {"covered": 87, "count": 100},
                "regions": {"covered": 41, "count": 50},
                "functions": {"covered": 9, "count": 10},
                "branches": {"covered": 30, "count": 40},
            },
        }
    ],
    "type": "llvm.coverage.json.export",
    "version": "3.0.1",
}

HTML = """<html><body><table>
<tr><th>File</th><th></th><th>Lines</th><th></th></tr>
<tr><td>Totals</td><td></td><td>87 (87/100)</td><td>87.0%</td><td>82.0%</td></tr>
<tr><td>vuln.c</td><td></td><td>60 (60/70)</td><td>85.7%</td><td>80.0%</td></tr>
<tr><td>main.c</td><td></td><td>27 (27/30)</td><td>90.0%</td><td>84.0%</td></tr>
</table></body></html>"""


def test_json_exact() -> None:
    out = parse_export(json.dumps(EXPORT))
    assert out["format"] == "llvm-json" and out["heuristic"] is False
    assert out["file_count"] == 2
    assert out["totals"]["lines"] == {"covered": 87, "count": 100, "pct": 87.0}
    assert out["totals"]["branches"]["pct"] == 75.0


def test_html_heuristic() -> None:
    out = parse_export(HTML, "html")
    assert out["format"] == "llvm-html" and out["heuristic"] is True
    assert out["file_count"] == 2
    assert out["totals"]["lines"]["pct"] == 87.0
    assert out["totals"]["regions"]["pct"] == 82.0
    auto = parse_export(HTML)
    assert auto["format"] == "llvm-html"


def test_rejects() -> None:
    with pytest.raises(ValueError):
        parse_export("   ")
    with pytest.raises(ValueError):
        parse_export("x" * 5_000_001)
    with pytest.raises(ValueError):
        parse_export('{"nope": true}', "json")
    with pytest.raises(ValueError):
        parse_export("<html><body>hi</body></html>", "html")
    with pytest.raises(ValueError):
        parse_export("{}", "yaml")
    with pytest.raises(ValueError):
        parse_export("[1, 2]")


def test_store_roundtrip_and_badge(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    assert load_import() is None
    stored = store_import(parse_export(json.dumps(EXPORT)), source="paste")
    assert stored["badge"]["label"] == "87.0% lines"
    assert stored["badge"]["grade"] == "good"
    assert stored["source"] == "paste"
    again = load_import()
    assert again is not None and again["badge"] == stored["badge"]
    assert with_badge({})["badge"]["label"] == "0.0% lines"
    assert sandbox_result()["badge"]["label"] == "87.0% lines"


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


def test_coverage_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.get("/api/coverage")
    assert r.status_code == 200 and r.json()["sandbox"] is True
    r = c.post("/api/coverage/import", json={"export": json.dumps(EXPORT)})
    assert r.status_code == 200
    assert r.json()["badge"]["label"] == "87.0% lines"
    assert c.post("/api/coverage/import", json={"export": "  "}).status_code == 400
    assert c.post("/api/coverage/import", json={"export": "{bad"}).status_code == 400
    assert (
        c.post(
            "/api/coverage/import", json={"export": "<p>hi</p>", "format": "html"}
        ).status_code
        == 400
    )
