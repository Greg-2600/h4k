# Endpoint telemetry (#94): normalization, Sigma-style rules, SQLite store,
# burst aggregation, queries, summary, and the HTTP API.
from contextlib import asynccontextmanager

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services import telemetry


@pytest.fixture()
def store(tmp_path):
    return telemetry.TelemetryStore(tmp_path / "telemetry.db")


@pytest.fixture()
def client(monkeypatch, tmp_path):
    import app_state
    import routers.telemetry as tel_router

    class _CveStub:
        cves: tuple = ()
        path = "stub.json"

        def refresh(self) -> bool:
            return False

    app_state.msf_client = None
    app_state.cve_db = _CveStub()  # type: ignore[assignment]
    app_state.active_engagement_id = None

    tel_router._store = telemetry.TelemetryStore(tmp_path / "api-telemetry.db")

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    main_module.reset_auth_cache()
    yield TestClient(main_module.app)
    tel_router.reset_store()
    main_module.reset_auth_cache()


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def test_normalize_common_shapes():
    sysmon = telemetry.normalize(
        {
            "EventID": "1",
            "Computer": "ws01.lab",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Message": "powershell.exe -EncodedCommand AAA",
            "TimeCreated": "2026-01-01T10:00:00Z",
        }
    )
    assert sysmon["host"] == "ws01.lab"
    assert sysmon["event_id"] == "1"
    assert sysmon["ts"] == "2026-01-01T10:00:00+00:00"
    assert sysmon["message"].startswith("powershell")

    osquery = telemetry.normalize(
        {
            "host": "mac.lab",
            "timestamp": 1767225600,
            "event": {"id": "shell_history", "source": "osquery"},
            "msg": "curl http://x",
        }
    )
    assert osquery["source"] == "osquery"
    assert osquery["ts"].startswith("2026-01-01")

    zeek = telemetry.normalize(
        {
            "ts": "1767225600.5",
            "@timestamp": "",
            "event": {"dataset": "dns"},
            "query": "x",
        }
    )
    assert zeek["source"] == "dns"
    assert zeek["message"] == ""


def test_event_uid_is_stable_and_dedupes():
    event = {
        "ts": "2026-01-01T00:00:00Z",
        "host": "h",
        "event_id": "1",
        "message": "same",
    }
    a = telemetry.normalize(dict(event))
    b = telemetry.normalize(dict(event))
    assert a["event_uid"] == b["event_uid"]
    explicit = telemetry.normalize({**event, "event_uid": "fixed"})
    assert explicit["event_uid"] == "fixed"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
def _event(message, event_id="", source="sysmon", host="h"):
    return telemetry.normalize(
        {"message": message, "event_id": event_id, "source": source, "host": host}
    )


@pytest.mark.parametrize(
    "event,rule",
    [
        (_event("powershell.exe -EncodedCommand SQBFAFgA"), "PS-ENCODED"),
        (_event("procdump accessed lsass.exe memory"), "LSASS-ACCESS"),
        (
            _event("Kerberos service ticket, encryption type 0x17", "4769", "security"),
            "KERBEROAST",
        ),
        (_event("TGT preauth 0x0", "4768", "security"), "ASREP-ROAST"),
        (_event("Security log cleared", "1102", "security"), "LOG-CLEARED"),
        (_event("A new service was installed", "7045", "system"), "SERVICE-CREATED"),
        (_event("scheduled task create", "", "system"), "SCHEDULED-TASK"),
        (_event("useradd backdoor", "", "auditd"), "NEW-USER"),
        (_event("member added to group", "4728", "security"), "GROUP-CHANGE"),
        (_event("smb share access from 10.0.0.5", "5140", "security"), "SMB-LATERAL"),
        (_event("CreateRemoteThread into explorer"), "PROCESS-INJECTION"),
        (
            _event("Set-MpPreference -DisableBehaviorMonitoring $true"),
            "DEFENDER-DISABLED",
        ),
        (
            _event("dns query " + "A" * 60, "", "dns"),
            "DNS-TUNNEL",
        ),
        (_event("modbus fc=16 write multiple registers"), "MODBUS-WRITE"),
        (
            _event("mqtt CONNACK rejected return_code=5", "connack", "mqtt"),
            "MQTT-BRUTE",
        ),
    ],
)
def test_rules_match_their_signature(event, rule):
    hits = [r["id"] for r in telemetry._match_rules(event)]
    assert rule in hits


def test_rule_catalog_is_well_formed():
    catalog = telemetry.rules()
    ids = {r["id"] for r in catalog}
    assert len(ids) == len(catalog)
    for rule in catalog:
        assert rule["technique"].startswith("T")
        assert rule["severity"] in {"low", "medium", "high", "critical"}


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
def test_ingest_dedupes_and_creates_detections(store):
    events = [
        {"event_uid": "e1", "host": "h1", "message": "powershell -enc AAAA"},
        {"event_uid": "e2", "host": "h1", "message": "procdump lsass.exe"},
        {"event_uid": "e1", "host": "h1", "message": "powershell -enc AAAA"},
    ]
    result = store.ingest(events)
    assert result["accepted"] == 2
    assert result["duplicates"] == 1
    rule_ids = {d["rule_id"] for d in result["detections"]}
    assert {"PS-ENCODED", "LSASS-ACCESS"} <= rule_ids
    summary = store.summary()
    assert summary["events"] == 2
    assert summary["detections"] >= 2
    assert summary["by_source"]["manual"] == 2


def test_failed_logon_burst_aggregation(store):
    events = [
        {
            "event_uid": f"f{i}",
            "host": "dc01",
            "event_id": "4625",
            "message": "failed logon",
        }
        for i in range(10)
    ]
    result = store.ingest(events)
    rules = {d["rule_id"] for d in result["detections"]}
    assert "FAILED-LOGON-BURST" in rules
    # ingesting the same burst again does not duplicate the aggregate
    again = store.ingest(events)
    assert again["duplicates"] == 10
    detections = [d for d in store.detections() if d["rule_id"] == "FAILED-LOGON-BURST"]
    assert len(detections) == 1


def test_query_filters(store):
    store.ingest(
        [
            {
                "event_uid": "a",
                "host": "h1",
                "source": "sysmon",
                "message": "alpha",
                "severity": "high",
            },
            {"event_uid": "b", "host": "h2", "source": "auditd", "message": "beta"},
        ]
    )
    assert [e["event_uid"] for e in store.events(host="h1")] == ["a"]
    assert [e["event_uid"] for e in store.events(source="auditd")] == ["b"]
    assert [e["event_uid"] for e in store.events(q="alpha")] == ["a"]
    assert [e["event_uid"] for e in store.events(severity="high")] == ["a"]
    assert store.events(limit=1)[0]["event_uid"] == "b"
    assert store.events(since="2999-01-01T00:00:00+00:00") == []


def test_reset(store):
    store.ingest([{"event_uid": "a", "message": "x"}])
    assert store.reset()["status"] == "reset"
    assert store.summary()["events"] == 0


def test_simulate_demo_creates_chain_detections(store):
    demo = telemetry.simulate_demo()
    result = store.ingest(demo["events"], source=demo["source"])
    rules = {d["rule_id"] for d in result["detections"]}
    assert {
        "PS-ENCODED",
        "KERBEROAST",
        "ASREP-ROAST",
        "LSASS-ACCESS",
        "MODBUS-WRITE",
    } <= rules


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
def test_api_ingest_query_summary_and_rules(client):
    rules = client.get("/api/telemetry/rules").json()
    assert rules["max_batch"] == telemetry.MAX_BATCH
    assert any(r["id"] == "PS-ENCODED" for r in rules["rules"])

    ingest = client.post(
        "/api/telemetry/events",
        json={
            "source": "test",
            "events": [
                {"event_uid": "1", "host": "h", "message": "powershell -enc AAA"},
                {"event_uid": "2", "host": "h", "message": "hello"},
            ],
        },
    )
    assert ingest.status_code == 200
    assert ingest.json()["accepted"] == 2
    assert ingest.json()["detection_count"] >= 1

    events = client.get("/api/telemetry/events?host=h").json()
    assert events["count"] == 2
    detections = client.get("/api/telemetry/detections").json()
    assert detections["count"] >= 1
    summary = client.get("/api/telemetry/summary").json()
    assert summary["events"] == 2
    assert summary["rules"] == len(telemetry.rules())


def test_api_accepts_a_single_event_and_validates(client):
    single = client.post(
        "/api/telemetry/events",
        json={"message": "useradd x", "host": "h", "event_uid": "single"},
    )
    assert single.status_code == 200
    assert single.json()["accepted"] == 1
    assert client.post("/api/telemetry/events", json={}).status_code == 400
    assert (
        client.post("/api/telemetry/events", json={"events": [1, 2]}).status_code == 400
    )
    too_many = [{"message": "x"} for _ in range(telemetry.MAX_BATCH + 1)]
    assert (
        client.post("/api/telemetry/events", json={"events": too_many}).status_code
        == 400
    )


def test_api_simulate_and_reset(client):
    sim = client.post("/api/telemetry/simulate")
    assert sim.status_code == 200
    assert sim.json()["note"].startswith("canned")
    assert sim.json()["detection_count"] >= 4
    assert client.post("/api/telemetry/reset").json()["status"] == "reset"
    assert client.get("/api/telemetry/summary").json()["events"] == 0


def test_normalizer_edge_cases_and_row_parsing():
    assert telemetry.normalize(123)["message"] == "123"
    assert telemetry._norm_ts("not-a-date") == "not-a-date"
    assert telemetry._norm_ts(10**30).startswith("20")
    assert telemetry._norm_ts(None)
    assert (
        telemetry.TelemetryStore._row({"data": "not json", "event_uid": "x"})["data"]
        == "not json"
    )


def test_broken_rule_is_contained(monkeypatch):
    original = list(telemetry._RULES)
    try:
        telemetry._RULES.append(
            {
                "id": "BROKEN",
                "title": "broken",
                "severity": "low",
                "technique": "T0000",
                "description": "raises",
                "match": lambda e: (_ for _ in ()).throw(RuntimeError("x")),
            }
        )
        hits = telemetry._match_rules(telemetry.normalize({"message": "x"}))
        assert all(h["id"] != "BROKEN" for h in hits)
    finally:
        telemetry._RULES[:] = original


def test_summary_on_empty_store(store):
    summary = store.summary()
    assert summary["events"] == 0
    assert summary["detections"] == 0
    assert summary["first_event"] is None


def test_norm_ts_numeric_string_and_naive_iso():
    assert telemetry._norm_ts("1767225600").startswith("2026-01-01")
    assert telemetry._norm_ts("2026-01-01T00:00:00").endswith("+00:00")
