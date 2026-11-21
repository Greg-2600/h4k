# Attack paths to objectives + coverage ledger: store methods, graph ranking,
# report output and the engagement API. Uses a temp engagement DB and a fake
# finding store where needed; no network.
from contextlib import asynccontextmanager

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services.attack_plan import AttackPathService
from services.engagement import EngagementStore, ScopeError
from services.findings import FindingStore


@pytest.fixture()
def store(tmp_path):
    return EngagementStore(tmp_path / "engagements.db")


@pytest.fixture()
def engagement(store):
    return store.create_engagement("Lab", ["10.0.0.0/24"])


def _seed(store, engagement):
    eid = engagement["id"]
    for host in ("10.0.0.5", "10.0.0.9", "10.0.0.10"):
        store.upsert_asset(eid, host, os="linux")
        store.upsert_service(eid, host, {"port": 445, "service": "smb"})
    # one credential reaches the pivot; another reaches the objective
    for host in ("10.0.0.5", "10.0.0.9"):
        store.record_credential(
            eid,
            "svc",
            "P@ss1",
            service="smb",
            origin_host=host,
            origin_port=445,
            verified=True,
        )
    for host in ("10.0.0.9", "10.0.0.10"):
        store.record_credential(
            eid,
            "admin",
            "P@ss2",
            service="smb",
            origin_host=host,
            origin_port=445,
            verified=True,
        )
    store.add_objective(
        eid, "10.0.0.10", label="Domain controller", criticality="critical"
    )
    return eid


def test_objective_store_scope_validation_and_delete(store, engagement):
    eid = engagement["id"]
    obj = store.add_objective(eid, "10.0.0.10", label="DC", criticality="critical")
    assert obj["host"] == "10.0.0.10"
    assert store.objectives(eid)[0]["label"] == "DC"
    assert store.summary(eid)["objectives"] == 1
    with pytest.raises(ScopeError):
        store.add_objective(eid, "192.168.99.1")
    with pytest.raises(ValueError):
        store.add_objective(eid, "10.0.0.10", kind="bogus")
    with pytest.raises(ValueError):
        store.add_objective(eid, "10.0.0.10", criticality="urgent")
    assert store.delete_objective(eid, "10.0.0.10") is True
    assert store.delete_objective(eid, "10.0.0.10") is False


def test_coverage_store_upsert_and_gaps(store, engagement):
    eid = engagement["id"]
    entry = store.record_coverage(
        eid, "10.0.0.10", "sqli", "needs_follow_up", port=443, reason="blocked"
    )
    assert entry["outcome"] == "needs_follow_up"
    assert store.coverage(eid, "10.0.0.10")[0]["risk_area"] == "sqli"
    store.record_coverage(
        eid, "10.0.0.10", "sqli", "reported", port=443, evidence_id="E-1"
    )
    assert store.coverage(eid)[0]["outcome"] == "reported"
    assert store.summary(eid)["coverage_entries"] == 1
    with pytest.raises(ValueError):
        store.record_coverage(eid, "10.0.0.10", "xss", "done")
    with pytest.raises(ScopeError):
        store.record_coverage(eid, "192.168.99.1", "xss", "no_issue_found")


def test_paths_rank_from_foothold_to_objective(store, engagement, tmp_path):
    eid = _seed(store, engagement)
    findings = FindingStore(tmp_path / "findings.db")
    finding = findings.create_finding(
        "SMB signing not required",
        severity="high",
        engagement_id=eid,
        host="10.0.0.9",
        port=445,
        technique="T1557.001",
    )
    evidence = findings.add_evidence(finding["id"], content="proof")
    findings.record_retest(
        finding["id"],
        verdict="reproduced",
        summary="confirmed",
        evidence_ids=[evidence["id"]],
    )
    result = AttackPathService(store, findings).evaluate(eid, start_hosts=["10.0.0.5"])
    assert result["ok"] is True
    assert result["objectives"][0]["host"] == "10.0.0.10"
    assert result["paths"]
    best = result["paths"][0]
    # the evidence-backed finding on the pivot makes 10.0.0.9 the best foothold
    assert best["foothold"] == "10.0.0.5"
    assert best["chain"] == "10.0.0.5 → 10.0.0.9 → 10.0.0.10"
    assert best["objective_criticality"] == "critical"
    assert best["risk"] == "critical"
    assert "T1021.002" in best["techniques"]
    assert "T1557.001" in best["techniques"]
    assert any(f["id"] == finding["id"] for f in best["findings"])
    assert best["verified_findings"] == 1
    assert best["evidence"]
    assert result["reachable_objectives"] == ["10.0.0.10"]


def test_paths_empty_and_unreachable(store, engagement):
    eid = engagement["id"]
    store.add_objective(eid, "10.0.0.10", label="DC")
    store.add_objective(eid, "10.0.0.99", label="Not in the graph")
    result = AttackPathService(
        store, FindingStore(store.path.parent / "f.db")
    ).evaluate(eid)
    assert result["paths"] == []
    assert {o["host"] for o in result["unreachable_objectives"]} == {
        "10.0.0.10",
        "10.0.0.99",
    }
    assert result["risk"] == "low"


def test_paths_ignore_unverified_credentials_and_unproven_findings(
    store, engagement, tmp_path
):
    eid = engagement["id"]
    store.upsert_asset(eid, "10.0.0.5")
    store.upsert_asset(eid, "10.0.0.10")
    store.record_credential(
        eid, "svc", "P@ss", service="smb", origin_host="10.0.0.5", verified=False
    )
    store.record_credential(
        eid, "svc", "P@ss", service="smb", origin_host="10.0.0.10", verified=False
    )
    findings = FindingStore(tmp_path / "findings.db")
    findings.create_finding(
        "Unproven critical", severity="critical", engagement_id=eid, host="10.0.0.5"
    )
    store.add_objective(eid, "10.0.0.10")
    result = AttackPathService(store, findings).evaluate(eid)
    assert result["paths"] == []
    assert result["footholds"] == []


def test_coverage_gaps_and_report(store, engagement, tmp_path):
    eid = _seed(store, engagement)
    store.record_coverage(eid, "10.0.0.10", "sqli", "no_issue_found")
    store.record_coverage(eid, "10.0.0.9", "xss", "needs_follow_up", reason="WAF")
    findings = FindingStore(tmp_path / "findings.db")
    result = AttackPathService(store, findings).evaluate(eid)
    assert result["coverage"]["entries"] == 2
    assert result["coverage"]["tested"] == 1
    assert result["coverage"]["gaps"] == 1
    assert result["coverage"]["gap_entries"][0]["risk_area"] == "xss"
    section = AttackPathService(store, findings).report_section(eid)
    assert "## Attack paths & coverage" in section
    assert "Domain controller" in section
    assert "Coverage" in section
    assert "xss" in section


def test_delete_engagement_cascades_objectives_and_coverage(store, engagement):
    eid = engagement["id"]
    store.add_objective(eid, "10.0.0.10")
    store.record_coverage(eid, "10.0.0.10", "sqli", "no_issue_found")
    assert store.delete_engagement(eid) is True
    assert store.objectives(eid) == []
    assert store.coverage(eid) == []


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@pytest.fixture()
def client(monkeypatch, tmp_path):
    import app_state
    import routers.engagement as engagement_router

    class _CveStub:
        cves: tuple = ()
        path = "stub.json"

        def refresh(self) -> bool:
            return False

    app_state.msf_client = None
    app_state.cve_db = _CveStub()  # type: ignore[assignment]
    app_state.active_engagement_id = None
    engagement_router._store = EngagementStore(tmp_path / "api-engagements.db")

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    main_module.reset_auth_cache()
    yield TestClient(main_module.app)
    engagement_router._store = None
    main_module.reset_auth_cache()


def test_api_objectives_coverage_paths(client):
    eng = client.post(
        "/api/engagement", json={"name": "Lab", "scope": ["10.0.0.0/24"]}
    ).json()
    eid = eng["id"]
    obj = client.post(
        f"/api/engagement/{eid}/objectives",
        json={"host": "10.0.0.10", "label": "DC", "criticality": "critical"},
    )
    assert obj.status_code == 200
    assert obj.json()["label"] == "DC"
    listed = client.get(f"/api/engagement/{eid}/objectives").json()
    assert listed["objectives"][0]["host"] == "10.0.0.10"
    assert "critical" in listed["criticalities"]

    cov = client.post(
        f"/api/engagement/{eid}/coverage",
        json={
            "host": "10.0.0.10",
            "port": 443,
            "risk_area": "sqli",
            "outcome": "no_issue_found",
        },
    )
    assert cov.status_code == 200
    assert client.get(f"/api/engagement/{eid}/coverage").json()["coverage"]
    assert client.get(f"/api/engagement/{eid}/paths").status_code == 200
    report = client.get(f"/api/engagement/{eid}/paths/report?fmt=md").json()
    assert report["fmt"] == "md"
    assert "Attack paths & coverage" in report["content"]
    assert client.get(f"/api/engagement/{eid}/paths/report?fmt=json").json()["report"][
        "objectives"
    ]
    assert (
        client.delete(f"/api/engagement/{eid}/objectives?host=10.0.0.10").status_code
        == 200
    )


def test_api_validation_and_404(client):
    eng = client.post(
        "/api/engagement", json={"name": "Lab", "scope": ["10.0.0.0/24"]}
    ).json()
    eid = eng["id"]
    assert (
        client.post(
            f"/api/engagement/{eid}/objectives",
            json={"host": "192.168.99.1"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/engagement/{eid}/objectives",
            json={"host": "10.0.0.10", "kind": "bogus"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/engagement/{eid}/coverage",
            json={"host": "10.0.0.10", "risk_area": "x", "outcome": "done"},
        ).status_code
        == 400
    )
    assert client.get("/api/engagement/nope/paths").status_code == 404
    assert client.get("/api/engagement/nope/objectives").status_code == 404
    assert client.get("/api/engagement/nope/coverage").status_code == 404
    assert (
        client.delete(f"/api/engagement/{eid}/objectives?host=10.0.0.99").status_code
        == 404
    )


def test_api_paths_from_host_and_ui_ids(client):
    eng = client.post(
        "/api/engagement", json={"name": "Lab", "scope": ["10.0.0.0/24"]}
    ).json()
    eid = eng["id"]
    assert (
        client.get(f"/api/engagement/{eid}/paths?from_host=10.0.0.5").status_code == 200
    )
    from pathlib import Path

    web = Path(__file__).resolve().parents[1] / "h4k" / "web"
    html = (web / "ops.html").read_text(encoding="utf-8")
    js = (web / "ops.js").read_text(encoding="utf-8")
    for ident in (
        "paths-card",
        "paths-summary",
        "paths-output",
        "paths-status",
        "obj-host",
        "obj-label",
        "obj-kind",
        "obj-criticality",
        "obj-tbody",
        "obj-empty",
        "cov-host",
        "cov-port",
        "cov-risk",
        "cov-outcome",
        "cov-reason",
        "btn-obj-add",
        "btn-cov-add",
        "btn-ap-refresh",
        "btn-ap-report",
    ):
        assert f'id="{ident}"' in html, f"missing #{ident}"
    for ident in (
        "paths-summary",
        "paths-output",
        "obj-tbody",
        "obj-empty",
        "btn-obj-add",
        "btn-cov-add",
        "btn-ap-refresh",
        "btn-ap-report",
    ):
        assert ident in js
