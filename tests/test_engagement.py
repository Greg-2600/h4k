# Tests for the engagement store and the credential propagation engine.
# Fully offline: the DB lives in tmp_path and Metasploit is a fake, so no
# network, no daemon, and no real authentication is ever attempted.
import pytest
from services.engagement import (
    EngagementStore,
    ScopeError,
    _normalize_scope,
    db_path,
    parse_scope,
)
from services.propagate import MAX_ATTEMPTS, PropagationService, _origin_of


@pytest.fixture
def store(tmp_path):
    return EngagementStore(tmp_path / "engagements.db")


@pytest.fixture
def eng(store):
    return store.create_engagement("acme red", ["10.0.0.0/24"])


def _report():
    return {
        "hosts": [
            {
                "address": "10.0.0.5",
                "services": [
                    {"port": 22, "service": "ssh"},
                    {"port": 80, "service": "http"},
                ],
            },
            {"address": "10.0.0.9", "services": [{"port": 22, "service": "ssh"}]},
            {
                "address": "192.168.5.5",
                "services": [{"port": 22, "service": "ssh"}],
            },
        ],
        "fingerprints": [
            {
                "host": "10.0.0.5",
                "os": "Linux",
                "vendor": "Acme",
                "technology": ["Apache"],
            }
        ],
        "credentials": [
            {
                "host": "10.0.0.5",
                "port": 22,
                "service": "ssh",
                "user": "root",
                "password": "toor",
                "verified": True,
            }
        ],
        "vulns": [
            {
                "host": "10.0.0.5",
                "name": "OpenSSH outdated",
                "severity": "medium",
                "cwe": "CWE-1104",
            }
        ],
    }


class FakeMsf:
    """Records every login attempt and succeeds only for hosts in `good`."""

    def __init__(self, good=()):
        self.good = set(good)
        self.calls = []

    def execute(self, kind, module, opts):
        self.calls.append((module, opts["RHOSTS"], opts["RPORT"], opts["USERNAME"]))
        return opts["RHOSTS"] in self.good


# ---- engagement lifecycle --------------------------------------------------


def test_create_engagement(store):
    e = store.create_engagement("acme", ["10.0.0.0/24", "10.1.1.5"], "notes here")
    assert e["name"] == "acme"
    assert e["scope"] == ["10.0.0.0/24", "10.1.1.5/32"]
    assert e["notes"] == "notes here"
    assert e["id"]


def test_create_requires_name_and_scope(store):
    with pytest.raises(ValueError, match="name"):
        store.create_engagement("  ", ["10.0.0.0/24"])
    with pytest.raises(ValueError, match="scope"):
        store.create_engagement("acme", [])
    with pytest.raises(ValueError, match="scope"):
        store.create_engagement("acme", ["not-an-ip"])


def test_db_is_not_world_readable(store):
    # the file holds verified credentials in the clear
    assert store.path.stat().st_mode & 0o077 == 0


def test_list_and_delete_engagement(store, eng):
    assert [e["id"] for e in store.list_engagements()] == [eng["id"]]
    assert store.delete_engagement(eng["id"]) is True
    assert store.get_engagement(eng["id"]) is None
    assert store.delete_engagement(eng["id"]) is False


def test_delete_cascades_to_child_rows(store, eng):
    store.ingest_scan(eng["id"], _report())
    store.delete_engagement(eng["id"])
    assert store.assets(eng["id"]) == []
    assert store.credentials(eng["id"]) == []
    assert store.access(eng["id"]) == []
    assert store.attempted_pairs(eng["id"]) == set()


def test_db_path_prefers_runtime_dir(monkeypatch, tmp_path):
    monkeypatch.setattr("services.engagement._RUNTIME_DIR", tmp_path)
    assert db_path().parent == tmp_path


# ---- scope is the authorization boundary -----------------------------------


def test_scope_normalization():
    nets = _normalize_scope(["10.0.0.0/24", "10.0.0.5", "10.0.0.0/24", "junk", ""])
    assert [str(n) for n in nets] == ["10.0.0.0/24", "10.0.0.5/32"]


def test_parse_scope_splits_on_commas_and_space():
    assert parse_scope("10.0.0.0/24, 10.1.1.5 10.2.2.2") == [
        "10.0.0.0/24",
        "10.1.1.5",
        "10.2.2.2",
    ]
    assert parse_scope("   ") == []


def test_in_scope(store, eng):
    assert store.in_scope(eng["id"], "10.0.0.5") is True
    assert store.in_scope(eng["id"], "10.0.0.255") is True
    assert store.in_scope(eng["id"], "10.0.1.5") is False
    assert store.in_scope(eng["id"], "not-an-ip") is False


def test_ingest_skips_out_of_scope_hosts(store, eng):
    out = store.ingest_scan(eng["id"], _report())
    # the 192.168.5.5 host is recorded nowhere, and the operator is told
    assert out["skipped_out_of_scope"] == ["192.168.5.5"]
    assert [a["host"] for a in store.assets(eng["id"])] == ["10.0.0.5", "10.0.0.9"]


def test_ingest_rejects_out_of_scope_credential(store, eng):
    report = _report()
    report["credentials"] = [
        {
            "host": "192.168.5.5",
            "port": 22,
            "service": "ssh",
            "user": "u",
            "password": "p",
            "verified": True,
        }
    ]
    store.ingest_scan(eng["id"], report)
    assert store.credentials(eng["id"]) == []


def test_direct_write_outside_scope_raises(store, eng):
    with pytest.raises(ScopeError, match="outside the authorized scope"):
        store.record_credential(
            eng["id"], "u", "p", "ssh", origin_host="192.168.5.5", verified=True
        )
    with pytest.raises(ScopeError):
        store.upsert_asset(eng["id"], "8.8.8.8")
    with pytest.raises(ScopeError):
        store.record_attempt(eng["id"], "8.8.8.8", 22, "ssh", "u", "p", "failed")


def test_ingest_unknown_engagement_raises(store):
    with pytest.raises(ValueError, match="unknown engagement"):
        store.ingest_scan("nope", _report())


# ---- ingest ----------------------------------------------------------------


def test_ingest_absorbs_report(store, eng):
    out = store.ingest_scan(eng["id"], _report())
    assert out["added"] == {"assets": 2, "services": 3, "credentials": 1, "vulns": 1}
    s = store.summary(eng["id"])
    assert s["assets"] == 2
    assert s["services"] == 3
    assert s["vulns"] == 1
    assert s["verified_credentials"] == 1


def test_ingest_is_idempotent(store, eng):
    store.ingest_scan(eng["id"], _report())
    again = store.ingest_scan(eng["id"], _report())
    assert again["added"] == {"assets": 0, "services": 0, "credentials": 0, "vulns": 0}
    assert store.summary(eng["id"])["assets"] == 2


def test_ingest_merges_fingerprint_data(store, eng):
    store.ingest_scan(eng["id"], _report())
    assets = {a["host"]: a for a in store.assets(eng["id"])}
    assert assets["10.0.0.5"]["os"] == "Linux"
    assert assets["10.0.0.5"]["vendor"] == "Acme"
    assert assets["10.0.0.5"]["technology"] == ["Apache"]
    # a later scan with no fingerprint must not erase what we already knew
    store.upsert_asset(eng["id"], "10.0.0.5")
    again = {a["host"]: a for a in store.assets(eng["id"])}
    assert again["10.0.0.5"]["os"] == "Linux"
    assert again["10.0.0.5"]["vendor"] == "Acme"


def test_upsert_service_ignores_portless(store, eng):
    assert store.upsert_service(eng["id"], "10.0.0.5", {"service": "ssh"}) == 0


def test_ingest_tolerates_report_without_optional_sections(store, eng):
    out = store.ingest_scan(
        eng["id"],
        {
            "hosts": [{"address": "10.0.0.5", "services": []}],
            "vulns": [],
            "credentials": [],
        },
    )
    assert out["added"]["assets"] == 1


def test_touch_updates_timestamp(store, eng):
    before = eng["updated_at"]
    store.touch(eng["id"])
    assert store.get_engagement(eng["id"])["updated_at"] >= before


# ---- credential access ledger ---------------------------------------------


def test_one_credential_many_hosts_is_one_cred_many_accesses(store, eng):
    # the fan-out is the whole point: 1 credential, 2 access grants
    for host in ("10.0.0.5", "10.0.0.9"):
        store.record_credential(
            eng["id"],
            "root",
            "toor",
            "ssh",
            origin_host=host,
            origin_port=22,
            verified=True,
        )
    creds = store.credentials(eng["id"])
    assert len(creds) == 1
    assert len(creds[0]["hosts"]) == 2
    assert store.summary(eng["id"])["access_grants"] == 2
    assert store.summary(eng["id"])["pivotable_credentials"] == 1
    assert store.summary(eng["id"])["pivot_hosts"] == 1


def test_unverified_access_does_not_mark_credential_verified(store, eng):
    store.record_credential(
        eng["id"], "u", "p", "ssh", origin_host="10.0.0.5", verified=False
    )
    assert store.credentials(eng["id"])[0]["verified"] is False
    assert store.verified_credentials(eng["id"]) == []


def test_record_credential_requires_user(store, eng):
    assert store.record_credential(eng["id"], "", "p", "ssh") == 0


def test_verified_flag_is_sticky(store, eng):
    store.record_credential(
        eng["id"], "u", "p", "ssh", origin_host="10.0.0.5", verified=False
    )
    store.record_credential(
        eng["id"], "u", "p", "ssh", origin_host="10.0.0.5", verified=True
    )
    assert store.credentials(eng["id"])[0]["verified"] is True


# ---- graph -----------------------------------------------------------------


def test_graph_pivot_edge_lists_only_verified_hosts(store, eng):
    store.ingest_scan(eng["id"], _report())
    store.record_credential(
        eng["id"],
        "root",
        "toor",
        "ssh",
        origin_host="10.0.0.9",
        origin_port=22,
        verified=True,
    )
    edges = store.graph(eng["id"])["edges"]
    pivot = next(e for e in edges if e["type"] == "pivot")
    # reached because we logged in there, not because both hosts run ssh
    assert pivot["source"] == "10.0.0.5"
    assert pivot["reaches"] == ["10.0.0.9"]
    assert pivot["verified"] is True


def test_graph_has_no_pivot_edge_for_single_host_cred(store, eng):
    store.ingest_scan(eng["id"], _report())
    edges = store.graph(eng["id"])["edges"]
    assert not [e for e in edges if e["type"] == "pivot"]
    # but the access itself is still an edge
    assert [e for e in edges if e["type"] == "credential"]


def test_graph_nodes_and_service_edges(store, eng):
    store.ingest_scan(eng["id"], _report())
    g = store.graph(eng["id"])
    assert {n["id"] for n in g["nodes"]} == {"10.0.0.5", "10.0.0.9"}
    assert g["nodes"][0]["type"] == "host"
    svc_edges = [e for e in g["edges"] if e["type"] == "service"]
    assert len(svc_edges) == 3
    assert g["summary"]["assets"] == 2


# ---- attempt ledger --------------------------------------------------------


def test_attempt_ledger_records_hits_and_misses(store, eng):
    store.record_attempt(eng["id"], "10.0.0.5", 22, "ssh", "root", "toor", "verified")
    store.record_attempt(eng["id"], "10.0.0.9", 22, "ssh", "root", "toor", "failed")
    pairs = store.attempted_pairs(eng["id"])
    assert ("10.0.0.5", 22, "ssh", "root", "toor") in pairs
    assert ("10.0.0.9", 22, "ssh", "root", "toor") in pairs
    assert len(store.attempts(eng["id"])) == 2


def test_attempt_ledger_is_idempotent(store, eng):
    for result in ("failed", "verified"):
        store.record_attempt(eng["id"], "10.0.0.5", 22, "ssh", "root", "toor", result)
    rows = store.attempts(eng["id"])
    assert len(rows) == 1
    assert rows[0]["result"] == "verified"


# ---- propagation -----------------------------------------------------------


def _prop_store(store, eng, services=((22, "ssh"), (3306, "mysql"))):
    store.ingest_scan(
        eng["id"],
        {
            "hosts": [
                {"address": h, "services": [{"port": p, "service": s}]}
                for h, p, s in [
                    ("10.0.0.5", 22, "ssh"),
                    ("10.0.0.9", 22, "ssh"),
                    ("10.0.0.11", 3306, "mysql"),
                ]
            ],
            "credentials": [
                {
                    "host": "10.0.0.5",
                    "port": 22,
                    "service": "ssh",
                    "user": "root",
                    "password": "toor",
                    "verified": True,
                }
            ],
        },
    )
    return services


def test_plan_is_a_dry_run(store, eng):
    _prop_store(store, eng)
    msf = FakeMsf()
    plan = PropagationService(msf, store).plan(eng["id"])
    # 3 services, minus the (host, service) the cred already came from
    assert plan["credentials"] == 1
    assert plan["attempts"] == 2
    assert msf.calls == []


def test_plan_skips_services_without_login_module(store, eng):
    store.ingest_scan(
        eng["id"],
        {
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 80, "service": "http"}]},
                {
                    "address": "10.0.0.9",
                    "services": [{"port": 443, "service": "https"}],
                },
            ],
            "credentials": [
                {
                    "host": "10.0.0.5",
                    "port": 80,
                    "service": "http",
                    "user": "admin",
                    "password": "admin",
                    "verified": True,
                }
            ],
        },
    )
    # http_login exists, so both are targets except the origin service
    plan = PropagationService(FakeMsf(), store).plan(eng["id"])
    assert plan["attempts"] == 1


def test_run_finds_lateral_movement(store, eng):
    _prop_store(store, eng)
    msf = FakeMsf(good={"10.0.0.9"})
    res = PropagationService(msf, store).run(eng["id"])
    assert res["planned"] == 2
    assert res["attempted"] == 2
    assert res["verified"] == 1
    assert res["failed"] == 1
    assert res["lateral_moves"] == 1
    assert res["reached"][0]["new_host"] == "10.0.0.9"
    assert res["reached"][0]["lateral"] is True
    # the successful login is now recorded as access on the new host
    cred = store.credentials(eng["id"])[0]
    assert {h["host"] for h in cred["hosts"]} == {"10.0.0.5", "10.0.0.9"}


def test_run_is_idempotent_via_attempt_ledger(store, eng):
    _prop_store(store, eng)
    svc = PropagationService(FakeMsf(good={"10.0.0.9"}), store)
    svc.run(eng["id"])
    second = svc.run(eng["id"])
    # a miss was recorded too, so nothing is retried
    assert second["planned"] == 0
    assert second["attempted"] == 0


def test_failed_replay_is_not_recorded_as_a_credential(store, eng):
    _prop_store(store, eng)
    PropagationService(FakeMsf(good=set()), store).run(eng["id"])
    # the failed mysql attempt lives in the ledger, not in credentials
    assert store.summary(eng["id"])["credentials"] == 1
    assert len(store.attempts(eng["id"])) == 2


def test_run_respects_max_attempts(store, eng):
    _prop_store(store, eng)
    res = PropagationService(FakeMsf(), store).run(eng["id"], max_attempts=1)
    assert res["attempted"] == 1
    assert res["capped"] is True


def test_run_cannot_exceed_hard_cap(store, eng):
    _prop_store(store, eng)
    msf = FakeMsf()
    res = PropagationService(msf, store).run(eng["id"], max_attempts=MAX_ATTEMPTS * 10)
    assert res["attempted"] <= MAX_ATTEMPTS


def test_propagation_only_uses_verified_credentials(store, eng):
    _prop_store(store, eng)
    store.record_credential(
        eng["id"], "ghost", "nope", "ssh", origin_host="10.0.0.5", verified=False
    )
    msf = FakeMsf()
    PropagationService(msf, store).run(eng["id"])
    # the unverified credential was never attempted anywhere
    assert all(call[3] != "ghost" for call in msf.calls)


def test_propagation_never_replays_at_the_origin(store, eng):
    _prop_store(store, eng)
    msf = FakeMsf(good={"10.0.0.5"})
    PropagationService(msf, store).run(eng["id"])
    # root:toor was already known-good on 10.0.0.5:22, so it is not retried
    assert all(call[1] != "10.0.0.5" for call in msf.calls)


def test_propagation_respects_scope_at_plan_time(store, eng):
    store.ingest_scan(
        eng["id"],
        {
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 22, "service": "ssh"}]},
                {"address": "10.0.0.9", "services": [{"port": 22, "service": "ssh"}]},
            ],
            "credentials": [
                {
                    "host": "10.0.0.5",
                    "port": 22,
                    "service": "ssh",
                    "user": "root",
                    "password": "toor",
                    "verified": True,
                }
            ],
        },
    )
    msf = FakeMsf()
    PropagationService(msf, store).run(eng["id"])
    assert all(call[1].startswith("10.0.0.") for call in msf.calls)


def test_module_selection_uses_archive(store, eng):
    _prop_store(store, eng)
    msf = FakeMsf()
    PropagationService(msf, store).run(eng["id"])
    modules = {call[0] for call in msf.calls}
    assert "auxiliary/scanner/ssh/ssh_login" in modules
    assert "auxiliary/scanner/mysql/mysql_login" in modules


def test_execute_errors_are_treated_as_failure(store, eng):
    _prop_store(store, eng)

    class BoomMsf:
        def execute(self, *a, **k):
            raise RuntimeError("msf is down")

    res = PropagationService(BoomMsf(), store).run(eng["id"])
    assert res["verified"] == 0
    assert res["failed"] == res["attempted"] == 2


def test_create_session_option_is_dropped_when_rejected(store, eng):
    _prop_store(store, eng)

    class PickyMsf:
        def __init__(self):
            self.seen = []

        def execute(self, kind, module, opts):
            self.seen.append(dict(opts))
            if "CreateSession" in opts:
                raise RuntimeError("unknown option CreateSession")
            return False

    msf = PickyMsf()
    PropagationService(msf, store).run(eng["id"], open_sessions=True)
    # retried without the option rather than blowing up
    assert any("CreateSession" not in o for o in msf.seen)


def test_http_login_gets_default_uri(store, eng):
    store.ingest_scan(
        eng["id"],
        {
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 22, "service": "ssh"}]},
                {"address": "10.0.0.9", "services": [{"port": 80, "service": "http"}]},
            ],
            "credentials": [
                {
                    "host": "10.0.0.5",
                    "port": 22,
                    "service": "ssh",
                    "user": "root",
                    "password": "toor",
                    "verified": True,
                }
            ],
        },
    )

    class SeenMsf:
        def __init__(self):
            self.opts = {}

        def execute(self, kind, module, opts):
            self.opts.update(opts)
            return False

    msf = SeenMsf()
    PropagationService(msf, store).run(eng["id"])
    assert msf.opts.get("URI") == "/"


def test_plan_reports_capped_flag(store, eng):
    _prop_store(store, eng)
    plan = PropagationService(FakeMsf(), store).plan(eng["id"])
    assert plan["max_attempts"] == MAX_ATTEMPTS
    assert plan["capped"] is False


def test_plan_without_credentials_is_empty(store, eng):
    assert PropagationService(FakeMsf(), store).plan(eng["id"])["attempts"] == 0


def test_origin_of_helper():
    assert (
        _origin_of({"hosts": [{"host": "10.0.0.5"}, {"host": "10.0.0.9"}]})
        == "10.0.0.5"
    )
    assert _origin_of({"hosts": []}) is None
    assert _origin_of({}) is None


# ---- router ----------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    """TestClient with the engagement store pointed at a tmp DB and a fake MSF."""
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module
    from routers import engagement as eng_router

    class FakeM:
        @property
        def client(self):
            return self

        def execute(self, *a, **k):
            return a[2].get("RHOSTS") == "10.0.0.9"

    store = EngagementStore(tmp_path / "router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)
    app_state.msf_client = FakeM()

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def _make(client, scope=("10.0.0.0/24",)):
    r = client.post("/api/engagement", json={"name": "acme", "scope": list(scope)})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_router_create_and_list(client):
    eid = _make(client)
    r = client.get("/api/engagement")
    assert r.status_code == 200
    one = r.json()["engagements"][0]
    assert one["id"] == eid
    assert one["summary"]["assets"] == 0


def test_router_create_rejects_bad_scope(client):
    r = client.post("/api/engagement", json={"name": "x", "scope": []})
    assert r.status_code == 400
    assert "scope" in r.json()["detail"]


def test_router_parse_scope(client):
    r = client.post(
        "/api/engagement/parse-scope", json={"text": "10.0.0.0/24, 10.1.1.5"}
    )
    assert r.status_code == 200
    assert r.json()["scope"] == ["10.0.0.0/24", "10.1.1.5"]


def test_router_get_and_404(client):
    eid = _make(client)
    assert client.get(f"/api/engagement/{eid}").status_code == 200
    assert client.get("/api/engagement/nope").status_code == 404


def test_router_delete(client):
    eid = _make(client)
    assert client.delete(f"/api/engagement/{eid}").status_code == 200
    assert client.delete(f"/api/engagement/{eid}").status_code == 404


def _ingest(client, eid):
    return client.post(
        f"/api/engagement/{eid}/ingest",
        json={
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 22, "service": "ssh"}]},
                {"address": "10.0.0.9", "services": [{"port": 22, "service": "ssh"}]},
            ],
            "credentials": [
                {
                    "host": "10.0.0.5",
                    "port": 22,
                    "service": "ssh",
                    "user": "root",
                    "password": "toor",
                    "verified": True,
                }
            ],
        },
    )


def test_router_ingest_and_reads(client):
    eid = _make(client)
    r = _ingest(client, eid)
    assert r.status_code == 200
    assert r.json()["added"]["assets"] == 2

    assets = client.get(f"/api/engagement/{eid}/assets").json()["assets"]
    assert {a["host"] for a in assets} == {"10.0.0.5", "10.0.0.9"}

    creds = client.get(f"/api/engagement/{eid}/credentials").json()
    assert creds["credentials"][0]["user"] == "root"
    assert len(creds["access"]) == 1

    g = client.get(f"/api/engagement/{eid}/graph").json()
    assert g["summary"]["assets"] == 2


def test_router_ingest_unknown_engagement(client):
    assert (
        client.post("/api/engagement/nope/ingest", json={"hosts": []}).status_code
        == 404
    )


def test_router_ingest_rejects_report_without_hosts(client):
    eid = _make(client)
    r = client.post(f"/api/engagement/{eid}/ingest", json={"vulns": []})
    assert r.status_code == 400
    assert "hosts" in r.json()["detail"]


def test_router_ingest_from_job_id(client, monkeypatch):
    from routers import scan as scan_router

    eid = _make(client)
    monkeypatch.setitem(
        scan_router.JOBS,
        "job1",
        {
            "status": "done",
            "report": {"hosts": [{"address": "10.0.0.5", "services": []}]},
        },
    )
    r = client.post(f"/api/engagement/{eid}/ingest", json={"job_id": "job1"})
    assert r.status_code == 200
    assert r.json()["added"]["assets"] == 1


def test_router_ingest_from_missing_or_unready_job(client):
    eid = _make(client)
    assert (
        client.post(
            f"/api/engagement/{eid}/ingest", json={"job_id": "gone"}
        ).status_code
        == 404
    )


def test_router_ingest_unready_job(client, monkeypatch):
    from routers import scan as scan_router

    eid = _make(client)
    monkeypatch.setitem(scan_router.JOBS, "job2", {"status": "running"})
    r = client.post(f"/api/engagement/{eid}/ingest", json={"job_id": "job2"})
    assert r.status_code == 404
    assert "ready" in r.json()["detail"]


def test_router_propagation_plan_then_run(client):
    eid = _make(client)
    _ingest(client, eid)

    plan = client.get(f"/api/engagement/{eid}/propagate/plan").json()
    assert plan["attempts"] == 1  # 10.0.0.9 only; origin service is skipped

    run = client.post(f"/api/engagement/{eid}/propagate", json={}).json()
    assert run["attempted"] == 1
    assert run["verified"] == 1
    assert run["lateral_moves"] == 1
    assert run["reached"][0]["new_host"] == "10.0.0.9"

    g = client.get(f"/api/engagement/{eid}/graph").json()
    assert any(
        e["type"] == "pivot" and e["reaches"] == ["10.0.0.9"] for e in g["edges"]
    )


def test_router_propagation_unknown_engagement(client):
    assert client.post("/api/engagement/nope/propagate", json={}).status_code == 404
    assert client.get("/api/engagement/nope/propagate/plan").status_code == 404


def test_router_propagation_without_msf(client, monkeypatch):
    import app_state

    eid = _make(client)
    monkeypatch.setattr(app_state, "msf_client", None)
    assert client.post(f"/api/engagement/{eid}/propagate", json={}).status_code == 503
    assert client.get(f"/api/engagement/{eid}/propagate/plan").status_code == 503
