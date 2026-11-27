"""Backlog #72: disclosure tracker + CVSS builder + CWE browser."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from services.disclosure_pack import (
    CWE_ENTRIES,
    analyze,
    build_cvss,
    build_timeline,
    cvss_catalog,
    cwe_lookup,
    cwe_suggest,
    sandbox_result,
)

HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V4_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
BASIC_METRICS = {
    "AV": "N",
    "AC": "L",
    "PR": "N",
    "UI": "N",
    "S": "U",
    "C": "H",
    "I": "N",
    "A": "N",
}


def test_timeline_dates_and_reminders_are_deterministic() -> None:
    timeline = build_timeline("2026-01-01", as_of="2026-02-15")
    assert timeline == build_timeline("2026-01-01", as_of="2026-02-15")
    assert timeline["reported_at"] == "2026-01-01"
    assert timeline["as_of"] == "2026-02-15"
    assert timeline["deadline"] == "2026-04-01"
    assert timeline["disclosure_days"] == 90
    assert timeline["days_remaining"] == 45
    assert timeline["elapsed_days"] == 45
    assert timeline["status"] == "open"
    assert timeline["phase"] == "vendor-fix"
    assert [(item["label"], item["date"]) for item in timeline["reminders"]] == [
        ("Report sent", "2026-01-01"),
        ("30-day check-in", "2026-01-31"),
        ("60-day check-in", "2026-03-02"),
        ("7-day deadline warning", "2026-03-25"),
        ("Disclosure deadline", "2026-04-01"),
    ]
    assert [item["state"] for item in timeline["reminders"]] == [
        "past",
        "past",
        "upcoming",
        "upcoming",
        "upcoming",
    ]
    assert timeline["next_reminder"]["date"] == "2026-03-02"
    assert "90 days" in timeline["policy"]


def test_timeline_status_and_phase_transitions() -> None:
    assert build_timeline("2026-01-01", as_of="2025-12-31")["status"] == "scheduled"
    assert build_timeline("2026-01-01", as_of="2026-01-20")["phase"] == "triage"
    assert build_timeline("2026-01-01", as_of="2026-03-25")["status"] == "due_soon"
    due = build_timeline("2026-01-01", as_of="2026-04-01")
    assert (due["status"], due["phase"], due["days_remaining"]) == (
        "due",
        "disclosure-window",
        0,
    )
    overdue = build_timeline("2026-01-01", as_of="2026-04-02")
    assert (overdue["status"], overdue["phase"], overdue["days_remaining"]) == (
        "overdue",
        "expired",
        -1,
    )
    assert overdue["next_reminder"] is None


def test_timeline_extension_moves_deadline_and_warnings() -> None:
    timeline = build_timeline("2026-01-01", as_of="2026-01-01", extension_days=30)
    assert timeline["deadline"] == "2026-05-01"
    assert timeline["base_days"] == 90
    assert timeline["extension_days"] == 30
    assert timeline["disclosure_days"] == 120
    assert timeline["reminders"][-1]["date"] == "2026-05-01"
    assert timeline["reminders"][-2]["label"] == "7-day deadline warning"
    short = build_timeline("2026-01-01", as_of="2026-01-01", disclosure_days=5)
    assert [item["label"] for item in short["reminders"]] == [
        "Report sent",
        "Disclosure deadline",
    ]


def test_timeline_default_as_of_is_report_date() -> None:
    timeline = build_timeline("2026-01-01")
    assert timeline == build_timeline("2026-01-01", as_of="2026-01-01")
    assert timeline["as_of"] == "2026-01-01"
    assert timeline["days_remaining"] == 90


def test_build_cvss_from_picked_metrics_and_vector() -> None:
    built = build_cvss(metrics=BASIC_METRICS)
    assert built["version"] == "3.1"
    assert built["vector"] == HIGH_VECTOR
    assert built["score"] == 7.5
    assert built["severity"] == "high"
    assert built["computed"] is True
    assert built["metric_labels"]["AV"] == "Network"
    assert built["metric_labels"]["C"] == "High"
    assert build_cvss(vector=HIGH_VECTOR) == built
    critical = build_cvss(metrics={**BASIC_METRICS, "I": "H", "A": "H"})
    assert critical["score"] == 9.8
    assert critical["severity"] == "critical"
    changed = build_cvss(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert changed["score"] == 6.1
    assert changed["severity"] == "medium"
    catalog = cvss_catalog()
    assert [metric["key"] for metric in catalog] == [
        "AV",
        "AC",
        "PR",
        "UI",
        "S",
        "C",
        "I",
        "A",
    ]
    assert all(metric["options"] for metric in catalog)


def test_build_cvss_v4_score_is_asserted_not_guessed() -> None:
    with pytest.raises(ValueError, match="asserted"):
        build_cvss(vector=V4_VECTOR)
    scored = build_cvss(vector=V4_VECTOR, asserted_score=9.3)
    assert scored["version"] == "4.0"
    assert scored["score"] == 9.3
    assert scored["severity"] == "critical"
    assert scored["computed"] is False
    with pytest.raises(ValueError, match="0-10"):
        build_cvss(vector=V4_VECTOR, asserted_score=11)
    with pytest.raises(ValueError, match=r"bad v4\.0"):
        build_cvss(vector=V4_VECTOR.replace("AT:N", "AT:X"), asserted_score=5)


def test_build_cvss_validation() -> None:
    with pytest.raises(ValueError, match="vector or metrics"):
        build_cvss()
    with pytest.raises(ValueError, match="missing CVSS metrics"):
        build_cvss(metrics={"AV": "N"})
    with pytest.raises(ValueError, match=r"bad v3\.1 AV"):
        build_cvss(metrics={**BASIC_METRICS, "AV": "X"})
    with pytest.raises(ValueError, match=r"CVSS:3\.1"):
        build_cvss(vector="CVSS:2.0/AV:N")


def test_cwe_dictionary_browse_lookup_and_suggest() -> None:
    entries = cwe_suggest("", limit=50)
    assert [entry["id"] for entry in entries] == sorted(
        (entry["id"] for entry in CWE_ENTRIES),
        key=lambda item: int(item.split("-")[1]),
    )
    assert [entry["id"] for entry in cwe_suggest("", limit=3)] == [
        "CWE-20",
        "CWE-22",
        "CWE-77",
    ]
    assert cwe_lookup("79")["name"] == "Cross-site Scripting"
    assert cwe_lookup("CWE-89")["name"] == "SQL Injection"
    assert cwe_lookup("cwe_918")["name"] == "Server-Side Request Forgery"
    assert cwe_lookup("99999") is None
    assert cwe_suggest("sql injection")[0]["id"] == "CWE-89"
    assert cwe_suggest("ssrf")[0]["id"] == "CWE-918"
    assert cwe_suggest("CWE-416")[0]["id"] == "CWE-416"
    assert cwe_suggest("not-a-real-weakness") == []
    assert len(cwe_suggest("injection", limit=2)) == 2


def test_cwe_dictionary_is_well_formed() -> None:
    ids = [entry["id"] for entry in CWE_ENTRIES]
    assert len(ids) == len(set(ids))
    for entry in CWE_ENTRIES:
        assert entry["id"].startswith("CWE-")
        assert entry["id"][4:].isdigit()
        for field in ("name", "category", "description", "mitigation"):
            assert entry[field].strip()
        assert entry["keywords"]


def test_analyze_validates_input_and_combines_sections() -> None:
    with pytest.raises(ValueError, match="required"):
        analyze()
    with pytest.raises(ValueError, match="cvss must be an object"):
        analyze(cvss=HIGH_VECTOR)
    with pytest.raises(ValueError, match="cwe_ids must be a list"):
        analyze(cwe_ids="CWE-79")
    with pytest.raises(ValueError, match="reported_at must be an ISO date"):
        analyze(reported_at="tomorrow")
    result = analyze(
        reported_at="2026-01-01",
        as_of="2026-04-01",
        vendor="Example",
        title="Demo finding",
        cvss={"metrics": BASIC_METRICS},
        cwe_query="sql injection",
        cwe_ids=["79", "99999"],
        cwe_browse=True,
        cwe_limit=3,
    )
    assert result["timeline"]["status"] == "due"
    assert result["timeline"]["vendor"] == "Example"
    assert result["cvss"]["score"] == 7.5
    assert result["cvss_catalog"]
    assert [entry["id"] for entry in result["cwe"]["matches"]] == [
        "CWE-89",
        "CWE-77",
        "CWE-78",
    ]
    assert [entry["id"] for entry in result["cwe"]["selected"]] == ["CWE-79"]
    assert result["cwe"]["unknown"] == ["99999"]
    assert "No network" in result["limitations"]
    assert result["sandbox"] is False


def test_sandbox_result_is_canned_and_deterministic() -> None:
    result = sandbox_result()
    assert result == sandbox_result()
    assert result["sandbox"] is True
    assert result["timeline"]["reported_at"] == "2026-01-01"
    assert result["cvss"]["score"] == 7.5
    assert result["cwe"]["matches"][0]["id"] == "CWE-89"


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
        "/api/source/disclosure-pack",
        json={"reported_at": "ignored", "cwe_query": "ignored"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is True
    assert body["cvss"]["score"] == 7.5
    assert client.post("/api/source/disclosure-pack", json={}).status_code == 400


def test_router_real_analysis_without_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
    client = _client(tmp_path, monkeypatch, sandbox=False)
    response = client.post(
        "/api/source/disclosure-pack",
        json={
            "reported_at": "2026-01-01",
            "as_of": "2026-04-01",
            "cvss": {"vector": HIGH_VECTOR},
            "cwe_query": "sql injection",
            "cwe_ids": ["79", "99999"],
            "vendor": "Example Vendor",
            "title": "Demo finding",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is False
    assert body["timeline"]["deadline"] == "2026-04-01"
    assert body["timeline"]["status"] == "due"
    assert body["cvss"]["score"] == 7.5
    assert body["cwe"]["matches"][0]["id"] == "CWE-89"
    assert body["cwe"]["unknown"] == ["99999"]
    assert (
        client.post(
            "/api/source/disclosure-pack", json={"reported_at": "not-a-date"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/source/disclosure-pack",
            json={"cvss": {"vector": V4_VECTOR}},
        ).status_code
        == 400
    )
