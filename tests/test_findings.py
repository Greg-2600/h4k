# Evidence-bound findings + retest verdicts: store, validation, report, API,
# and the UI contract. The store is SQLite under tmp_path; no network.
from contextlib import asynccontextmanager
from pathlib import Path

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services.findings import FindingError, FindingNotFound, FindingStore


@pytest.fixture()
def store(tmp_path):
    return FindingStore(tmp_path / "findings.db")


@pytest.fixture()
def client(monkeypatch, tmp_path):
    import app_state
    import routers.findings as findings_router

    class _CveStub:
        cves: tuple = ()
        path = "stub.json"

        def refresh(self) -> bool:
            return False

    app_state.msf_client = None
    app_state.cve_db = _CveStub()  # type: ignore[assignment]
    app_state.active_engagement_id = None
    findings_router._store = FindingStore(tmp_path / "api-findings.db")

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    main_module.reset_auth_cache()
    yield TestClient(main_module.app)
    findings_router.reset_store()
    main_module.reset_auth_cache()


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
def test_create_list_get_and_summary(store):
    finding = store.create_finding(
        "Unauthenticated RCE",
        severity="critical",
        source="scan",
        host="10.0.0.5",
        port=8080,
        service="http",
        cwe="CWE-94",
        technique="T1190",
        description="exec() on caller input",
    )
    assert finding["id"].startswith("F-")
    assert finding["severity"] == "critical"
    assert finding["status"] == "open"
    assert finding["evidence_count"] == 0
    assert finding["evidence_backed"] is False
    assert finding["verified"] is False

    listed = store.list_findings()
    assert [f["id"] for f in listed] == [finding["id"]]
    assert store.list_findings(severity="high") == []
    assert [f["id"] for f in store.list_findings(q="exec")] == [finding["id"]]
    assert store.summary()["findings"] == 1
    assert store.summary()["by_severity"] == {"critical": 1}


def test_create_validation(store):
    for kwargs in (
        {"title": ""},
        {"title": "x", "severity": "urgent"},
        {"title": "x", "status": "done"},
    ):
        with pytest.raises(FindingError):
            store.create_finding(**kwargs)
    with pytest.raises(FindingNotFound):
        store.get_finding("F-missing")


def test_update_and_delete_cascade(store):
    finding = store.create_finding("title", severity="medium")
    updated = store.update_finding(finding["id"], {"status": "fixed", "title": "new"})
    assert updated["status"] == "fixed"
    assert updated["title"] == "new"
    assert store.update_finding(finding["id"], {})["id"] == finding["id"]
    assert store.update_finding(finding["id"], {"unknown": "ignored"})["title"] == "new"
    for bad in ({"severity": "nope"}, {"status": "nope"}, {"title": " "}):
        with pytest.raises(FindingError):
            store.update_finding(finding["id"], bad)
    evidence = store.add_evidence(finding["id"], content="proof")
    store.record_retest(
        finding["id"],
        verdict="fixed",
        summary="gone",
        evidence_ids=[evidence["id"]],
    )
    assert store.delete_finding(finding["id"]) is True
    assert store.delete_finding(finding["id"]) is False
    with pytest.raises(FindingNotFound):
        store.get_finding(finding["id"])


def test_evidence_hashes_bounds_and_metadata(store):
    finding = store.create_finding("title")
    item = store.add_evidence(
        finding["id"],
        content="GET / HTTP/1.1",
        kind="request",
        label="probe",
        metadata={"status": 200, "host": "10.0.0.5"},
    )
    assert item["sha256"]
    assert item["chars"] == len("GET / HTTP/1.1")
    assert len(item["sha256"]) == 64
    items = store.evidence(finding["id"])
    assert items[0]["label"] == "probe"
    assert items[0]["metadata"]["status"] == 200

    with pytest.raises(FindingError):
        store.add_evidence(finding["id"], content="")
    with pytest.raises(FindingError):
        store.add_evidence(finding["id"], content="x", kind="bogus")
    with pytest.raises(FindingNotFound):
        store.add_evidence("F-missing", content="x")

    long = "x" * (300 * 1024)
    item = store.add_evidence(finding["id"], content=long)
    assert item["chars"] == 256 * 1024


def test_retest_requires_evidence_and_updates_status(store):
    finding = store.create_finding("title")
    with pytest.raises(FindingError, match="cite at least one evidence"):
        store.record_retest(finding["id"], verdict="reproduced", summary="still there")
    with pytest.raises(FindingError):
        store.record_retest(
            finding["id"], verdict="maybe", summary="x", evidence_ids=[]
        )

    proof = store.add_evidence(finding["id"], content="proof")
    reproduced = store.record_retest(
        finding["id"],
        verdict="reproduced",
        summary="still there",
        evidence_ids=[proof["id"]],
    )
    assert reproduced["finding_status"] == "open"
    assert reproduced["verified"] is True
    assert store.get_finding(finding["id"])["verified"] is True

    fixed = store.record_retest(
        finding["id"], verdict="fixed", summary="patched", evidence_ids=[proof["id"]]
    )
    assert fixed["finding_status"] == "fixed"
    assert store.get_finding(finding["id"])["status"] == "fixed"

    # an inconclusive retest does not change a fixed finding
    inconclusive = store.record_retest(
        finding["id"],
        verdict="inconclusive",
        summary="WAF blocked",
        evidence_ids=[proof["id"]],
    )
    assert inconclusive["finding_status"] == "fixed"
    assert len(store.retests(finding["id"])) == 3


def test_retest_can_create_inline_evidence(store):
    finding = store.create_finding("title")
    result = store.record_retest(
        finding["id"],
        verdict="reproduced",
        summary="replayed",
        inline_evidence="new response body",
        tested_by="operator",
    )
    assert len(result["evidence_ids"]) == 1
    evidence = store.evidence(finding["id"])
    assert evidence[0]["kind"] == "retest-output"
    assert evidence[0]["content"] == "new response body"


def test_retest_rejects_foreign_evidence(store):
    first = store.create_finding("one")
    second = store.create_finding("two")
    foreign = store.add_evidence(second["id"], content="other")
    with pytest.raises(FindingError, match="does not belong"):
        store.record_retest(
            first["id"],
            verdict="reproduced",
            summary="x",
            evidence_ids=[foreign["id"]],
        )


def test_report_markdown_and_empty_section(store):
    assert "No evidence-backed findings" in store.report_section()
    finding = store.create_finding(
        "RCE | in worker", severity="high", host="10.0.0.5", port=8080
    )
    proof = store.add_evidence(finding["id"], content="post body", kind="request")
    store.record_retest(
        finding["id"],
        verdict="reproduced",
        summary="confirmed",
        evidence_ids=[proof["id"]],
    )
    section = store.report_section()
    assert "## Finding ledger" in section
    assert "RCE \\| in worker" in section
    assert "reproduced" in section
    assert proof["sha256"][:16] in section
    assert "Ledger totals: 1 findings, 1 verified" in section
    markdown = store.report_markdown()
    assert markdown.startswith("# Evidence-backed finding ledger")
    assert "A finding without cited evidence is a lead" in markdown


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
def test_api_crud_and_evidence(client):
    created = client.post(
        "/api/findings",
        json={
            "title": "Open RCE",
            "severity": "critical",
            "source": "scan",
            "host": "10.0.0.5",
            "port": 8080,
        },
    )
    assert created.status_code == 200
    finding = created.json()
    assert finding["id"].startswith("F-")

    listing = client.get("/api/findings").json()
    assert listing["count"] == 1
    assert listing["summary"]["findings"] == 1
    assert client.get("/api/findings/summary").json()["findings"] == 1
    assert client.get(f"/api/findings/{finding['id']}").status_code == 200

    patched = client.patch(
        f"/api/findings/{finding['id']}", json={"status": "in_progress"}
    )
    assert patched.json()["status"] == "in_progress"

    evidence = client.post(
        f"/api/findings/{finding['id']}/evidence",
        json={
            "kind": "http_exchange",
            "label": "exploit",
            "content": "POST /render/cadquery\n\nid -> root",
        },
    )
    assert evidence.status_code == 200
    evidence_id = evidence.json()["id"]
    listed = client.get(f"/api/findings/{finding['id']}/evidence").json()
    assert listed["count"] == 1
    assert listed["evidence"][0]["sha256"]

    retest = client.post(
        f"/api/findings/{finding['id']}/retest",
        json={
            "verdict": "reproduced",
            "summary": "same response",
            "evidence_ids": [evidence_id],
        },
    )
    assert retest.status_code == 200
    assert retest.json()["verified"] is True
    assert client.get(f"/api/findings/{finding['id']}/retests").json()["count"] == 1

    report = client.get("/api/findings/report?fmt=md").json()
    assert report["fmt"] == "md"
    assert "Open RCE" in report["content"]
    json_report = client.get("/api/findings/report?fmt=json").json()
    assert json_report["summary"]["findings"] == 1

    assert client.delete(f"/api/findings/{finding['id']}").status_code == 200
    assert client.get(f"/api/findings/{finding['id']}").status_code == 404


def test_api_validation_and_404s(client):
    assert client.post("/api/findings", json={}).status_code == 400
    assert (
        client.post(
            "/api/findings", json={"title": "x", "severity": "nope"}
        ).status_code
        == 400
    )
    assert client.get("/api/findings/F-nope").status_code == 404
    assert (
        client.patch("/api/findings/F-nope", json={"status": "fixed"}).status_code
        == 404
    )
    assert client.delete("/api/findings/F-nope").status_code == 404
    assert (
        client.post("/api/findings/F-nope/evidence", json={"content": "x"}).status_code
        == 404
    )
    assert client.get("/api/findings/F-nope/evidence").status_code == 404
    assert (
        client.post(
            "/api/findings/F-nope/retest", json={"verdict": "fixed", "summary": "x"}
        ).status_code
        == 404
    )
    assert client.get("/api/findings/F-nope/retests").status_code == 404


def test_api_retest_needs_evidence(client):
    finding = client.post("/api/findings", json={"title": "x"}).json()
    r = client.post(
        f"/api/findings/{finding['id']}/retest",
        json={"verdict": "fixed", "summary": "looks gone"},
    )
    assert r.status_code == 400
    assert "evidence" in r.json()["detail"]


def test_api_scope_is_enforced_when_engagement_given(client, monkeypatch):
    import services.engagement as engagement_service

    class _FakeStore:
        def list_engagements(self):
            return [{"id": "e1"}]

        def in_scope(self, engagement_id, host):
            return engagement_id == "e1" and host == "10.0.0.5"

    monkeypatch.setattr(engagement_service, "EngagementStore", _FakeStore)
    assert (
        client.post(
            "/api/findings",
            json={"title": "x", "engagement_id": "e2", "host": "10.0.0.5"},
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/api/findings",
            json={"title": "x", "engagement_id": "e1", "host": "10.0.0.6"},
        ).status_code
        == 403
    )
    ok = client.post(
        "/api/findings",
        json={"title": "x", "engagement_id": "e1", "host": "10.0.0.5"},
    )
    assert ok.status_code == 200


def test_session_report_includes_finding_ledger(client, monkeypatch, tmp_path):
    import services.findings as findings_service

    store = FindingStore(tmp_path / "session-findings.db")
    finding = store.create_finding("Reported finding", severity="high")
    proof = store.add_evidence(finding["id"], content="proof")
    store.record_retest(
        finding["id"],
        verdict="reproduced",
        summary="confirmed",
        evidence_ids=[proof["id"]],
    )
    monkeypatch.setattr(findings_service, "FindingStore", lambda *a, **k: store)
    report = client.get("/api/session/report?fmt=md").json()
    assert "## Finding ledger" in report["content"]
    assert "Reported finding" in report["content"]


def test_ui_contract_ids_exist():
    web = Path(__file__).resolve().parents[1] / "h4k" / "web"
    html = (web / "ops.html").read_text(encoding="utf-8")
    js = (web / "ops.js").read_text(encoding="utf-8")
    for ident in (
        "findings-card",
        "fl-summary",
        "fl-tbody",
        "fl-empty",
        "fl-select",
        "fl-title",
        "fl-severity",
        "fl-source",
        "fl-host",
        "fl-port",
        "fl-description",
        "fl-evidence-kind",
        "fl-evidence-label",
        "fl-evidence-text",
        "fl-verdict",
        "fl-retest-summary",
        "fl-retest-evidence",
        "fl-output",
        "fl-status",
        "btn-fl-create",
        "btn-fl-add-evidence",
        "btn-fl-retest",
        "btn-fl-report",
        "btn-fl-refresh",
    ):
        assert f'id="{ident}"' in html, f"missing #{ident}"
    for ident in (
        "fl-summary",
        "fl-tbody",
        "fl-empty",
        "fl-select",
        "fl-verdict",
        "fl-output",
        "fl-status",
        "btn-fl-create",
        "btn-fl-retest",
        "btn-fl-report",
        "btn-fl-refresh",
    ):
        assert ident in js
