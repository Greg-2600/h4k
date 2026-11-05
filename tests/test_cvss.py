"""Backlog #24: CVSS v4 re-score with audit trail."""

from __future__ import annotations

from typing import Any

import pytest
from services.cvss import parse_vector, score_v31, score_vector, severity_for


def test_v31_known_vectors() -> None:
    # Heartbleed -> 7.5, EternalBlue (v3.x backport) -> 8.1, Log4Shell -> 10.0
    assert (
        score_v31(
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")["metrics"]
        )
        == 7.5
    )
    assert (
        score_v31(
            parse_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")["metrics"]
        )
        == 8.1
    )
    assert (
        score_v31(
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")["metrics"]
        )
        == 10.0
    )
    assert (
        score_v31(
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["metrics"]
        )
        == 9.8
    )


def test_v31_rejects_bad_vectors() -> None:
    with pytest.raises(ValueError):
        parse_vector("AV:N/AC:L")
    with pytest.raises(ValueError):
        parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N")
    with pytest.raises(ValueError):
        parse_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")


def test_v40_validated_not_computed() -> None:
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    with pytest.raises(ValueError, match="asserted"):
        score_vector(v)
    out = score_vector(v, asserted=9.3)
    assert out == {
        "version": "4.0",
        "metrics": parse_vector(v)["metrics"],
        "score": 9.3,
        "computed": False,
    }
    with pytest.raises(ValueError):
        parse_vector("CVSS:4.0/AV:N/AC:L")
    with pytest.raises(ValueError):
        score_vector(v, asserted=11)


def test_severity_bands() -> None:
    assert [
        severity_for(s) for s in (10.0, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, 0.0)
    ] == [
        "critical",
        "critical",
        "high",
        "high",
        "medium",
        "medium",
        "low",
        "low",
        "none",
    ]


def test_override_ledger(tmp_path: Any) -> None:
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "cvss.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    store.record_vuln(eng["id"], "10.0.0.5", {"name": "Old Vuln", "severity": "low"})
    out = store.record_override(
        eng["id"],
        "10.0.0.5",
        "Old Vuln",
        "critical",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        score=10.0,
        rationale="verified RCE",
        actor="tester",
    )
    assert out["old_severity"] == "low" and out["new_severity"] == "critical"
    eff = store.effective_vulns(eng["id"])
    assert eff[0]["severity"] == "critical"
    assert eff[0]["override"]["actor"] == "tester"
    assert len(store.list_overrides(eng["id"])) == 1
    # out-of-scope hosts are refused, never recorded
    try:
        store.record_override(eng["id"], "8.8.8.8", "X", "high")
    except Exception:
        pass
    else:
        raise AssertionError("out-of-scope override must raise")
    assert len(store.list_overrides(eng["id"])) == 1


def test_override_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "cvss-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eid = c.post(
        "/api/engagement", json={"name": "acme", "scope": ["10.0.0.0/24"]}
    ).json()["id"]
    store.record_vuln(eid, "10.0.0.5", {"name": "V", "severity": "low"})
    r = c.post(
        f"/api/engagement/{eid}/vulns/override",
        json={
            "host": "10.0.0.5",
            "name": "V",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "rationale": "verified",
            "actor": "tester",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["new_severity"] == "critical"
    r = c.get(f"/api/engagement/{eid}/vulns/effective")
    assert r.json()["vulns"][0]["severity"] == "critical"
    r = c.get(f"/api/engagement/{eid}/vulns/overrides")
    assert len(r.json()["overrides"]) == 1
    assert (
        c.post(f"/api/engagement/{eid}/vulns/override", json={"host": "h"}).status_code
        == 400
    )
    assert (
        c.post(
            f"/api/engagement/{eid}/vulns/override",
            json={"host": "10.0.0.5", "name": "V", "vector": "bogus"},
        ).status_code
        == 400
    )
    assert c.get("/api/engagement/nope/vulns/overrides").status_code == 404
