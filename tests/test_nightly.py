# Nightly autopilot (#100): cron parsing/next-run, SQLite schedule + run ledger,
# scheduler ticks with an injected runner, and the automation HTTP API.
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services import nightly


# ---------------------------------------------------------------------------
# Cron
# ---------------------------------------------------------------------------
def test_parse_cron_fields_and_names():
    schedule = nightly.parse_cron("*/15 2-4 * * mon-fri")
    assert schedule.minute == frozenset({0, 15, 30, 45})
    assert schedule.hour == frozenset({2, 3, 4})
    assert schedule.weekday == frozenset({1, 2, 3, 4, 5})
    assert schedule.day == frozenset(range(1, 32))
    jan_jul = nightly.parse_cron("0 0 1 jan,jul *")
    assert jan_jul.month == frozenset({1, 7})
    sunday = nightly.parse_cron("0 0 * * 7")
    assert sunday.weekday == frozenset({0})


def test_cron_macros():
    assert nightly.parse_cron("@nightly").expression == "@nightly"
    assert nightly.next_run(
        "@nightly", datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    ) == datetime(2026, 1, 1, 3, 0, tzinfo=UTC)
    assert nightly.next_run(
        "@hourly", datetime(2026, 1, 1, 0, 1, tzinfo=UTC)
    ) == datetime(2026, 1, 1, 1, 0, tzinfo=UTC)
    assert (
        nightly.next_run("@weekly", datetime(2026, 1, 1, 0, 0, tzinfo=UTC)).weekday()
        == 6
    )


def test_cron_rejects_bad_expressions():
    for expression in (
        "",
        "* * * *",
        "* * * * * *",
        "*/0 * * * *",
        "99 * * * *",
        "@sometimes",
    ):
        with pytest.raises(nightly.CronError):
            nightly.parse_cron(expression)
    with pytest.raises(nightly.CronError):
        nightly.next_run("0 0 * * *", tz="Mars/Olympus")


def test_next_run_and_upcoming():
    after = datetime(2026, 1, 1, 0, 0, 30, tzinfo=UTC)
    assert nightly.next_run("* * * * *", after) == datetime(
        2026, 1, 1, 0, 1, tzinfo=UTC
    )
    assert nightly.next_run("0 2 * * *", after) == datetime(
        2026, 1, 1, 2, 0, tzinfo=UTC
    )
    assert nightly.next_run("*/15 * * * *", after) == datetime(
        2026, 1, 1, 0, 15, tzinfo=UTC
    )
    runs = nightly.upcoming("0 * * * *", count=3, after=after)
    assert len(runs) == 3
    assert runs == sorted(runs)


def test_dom_dow_or_semantics_and_timezone():
    after = datetime(2026, 1, 2, 0, 0, tzinfo=UTC)  # Friday
    # day-of-month=1 OR Sunday -> next Sunday 4 Jan
    assert nightly.next_run("0 0 1 * 0", after) == datetime(
        2026, 1, 4, 0, 0, tzinfo=UTC
    )
    # 09:00 New York in January is 14:00 UTC
    assert nightly.next_run(
        "0 9 * * *", datetime(2026, 1, 1, 0, 0, tzinfo=UTC), tz="America/New_York"
    ) == datetime(2026, 1, 1, 14, 0, tzinfo=UTC)


def test_impossible_schedule_is_rejected():
    with pytest.raises(nightly.CronError, match="never matches"):
        nightly.next_run("0 0 31 2 *", datetime(2026, 1, 1, tzinfo=UTC))


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
@pytest.fixture()
def store(tmp_path):
    return nightly.ScheduleStore(tmp_path / "automation.db")


def test_store_crud(store):
    created = store.create("nightly", "0 3 * * *", engagement_id="eng1", deep_web=True)
    assert created["name"] == "nightly"
    assert created["enabled"] is True
    assert created["deep_web"] is True
    assert created["next_run"]
    assert store.get(created["id"])["cron"] == "0 3 * * *"
    assert [s["id"] for s in store.list_all()] == [created["id"]]

    updated = store.update(created["id"], {"cron": "@hourly", "enabled": False})
    assert updated["cron"] == "@hourly"
    assert updated["enabled"] is False
    assert updated["next_run"] is None
    store.update(created["id"], {"enabled": True})
    assert store.get(created["id"])["next_run"]

    with pytest.raises(ValueError):
        store.create("", "* * * * *")
    with pytest.raises(nightly.CronError):
        store.create("bad", "nope")
    with pytest.raises(ValueError):
        store.create("bad-tz", "* * * * *", timezone="Mars/Base")
    with pytest.raises(KeyError):
        store.update("missing", {})
    assert store.delete(created["id"]) is True
    assert store.delete(created["id"]) is False


def test_due_only_returns_enabled_schedules(store):
    first = store.create("a", "* * * * *", engagement_id="e")
    second = store.create("b", "* * * * *", engagement_id="e", enabled=False)
    future = datetime.now(UTC) + timedelta(minutes=2)
    due_ids = {s["id"] for s in store.due(future)}
    assert first["id"] in due_ids
    assert second["id"] not in due_ids


def test_run_ledger(store):
    schedule = store.create("a", "* * * * *", engagement_id="e")
    run = store.start_run(schedule["id"])
    assert run["status"] == "running"
    assert store.get(schedule["id"])["last_status"] == "running"
    finished = store.finish_run(
        run["id"], status="complete", job_id="job1", summary="ok"
    )
    assert finished["status"] == "complete"
    assert store.get(schedule["id"])["last_status"] == "complete"
    assert store.get(schedule["id"])["last_job_id"] == "job1"
    assert store.runs(schedule["id"])[0]["id"] == run["id"]
    assert len(store.runs()) == 1
    with pytest.raises(KeyError):
        store.finish_run("missing", status="error")
    store.delete(schedule["id"])
    assert store.runs(schedule["id"]) == []


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------
def test_scheduler_tick_runs_due_schedule(store):
    schedule = store.create("job", "* * * * *", engagement_id="eng1")
    seen = []

    def runner(sched):
        seen.append(sched["id"])
        return {"ok": True, "job_id": "job-1", "status": "complete", "hosts": 3}

    scheduler = nightly.NightlyScheduler(store=store, runner=runner)
    results = scheduler.tick(datetime.now(UTC) + timedelta(minutes=2))
    assert seen == [schedule["id"]]
    assert results[0]["status"] == "complete"
    run = store.runs(schedule["id"])[0]
    assert run["status"] == "complete"
    assert run["job_id"] == "job-1"
    assert "hosts=3" in run["summary"]
    assert store.get(schedule["id"])["last_status"] == "complete"


def test_scheduler_records_runner_failure(store):
    schedule = store.create("job", "* * * * *", engagement_id="eng1")

    def runner(sched):
        raise RuntimeError("boom")

    scheduler = nightly.NightlyScheduler(store=store, runner=runner)
    result = scheduler.tick(datetime.now(UTC) + timedelta(minutes=2))[0]
    assert result["status"] == "error"
    run = store.runs(schedule["id"])[0]
    assert run["status"] == "error"
    assert "boom" in run["error"]


def test_run_now_and_missing(store):
    schedule = store.create("job", "@hourly", engagement_id="eng1")
    scheduler = nightly.NightlyScheduler(store=store, runner=lambda s: {"ok": True})
    assert scheduler.run_now(schedule["id"])["status"] == "complete"
    with pytest.raises(KeyError):
        scheduler.run_now("nope")


def test_scheduler_env_flags(monkeypatch):
    monkeypatch.setenv("H4K_SCHEDULER", "1")
    assert nightly.scheduler_enabled() is True
    monkeypatch.setenv("H4K_SCHEDULER", "no")
    assert nightly.scheduler_enabled() is False
    monkeypatch.setenv("H4K_SCHEDULER_INTERVAL", "7")
    assert nightly.scheduler_interval() == 7.0


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@pytest.fixture()
def client(monkeypatch, tmp_path):
    import app_state
    import routers.automation as auto_router

    class _CveStub:
        cves: tuple = ()
        path = "stub.json"

        def refresh(self) -> bool:
            return False

    app_state.msf_client = None
    app_state.cve_db = _CveStub()  # type: ignore[assignment]
    app_state.active_engagement_id = None

    scheduler = nightly.NightlyScheduler(
        store=nightly.ScheduleStore(tmp_path / "api-automation.db"),
        runner=lambda s: {
            "ok": True,
            "job_id": "job-api",
            "status": "complete",
            "hosts": 1,
        },
    )
    monkeypatch.setattr(auto_router, "get_scheduler", lambda: scheduler)
    monkeypatch.setattr(auto_router, "_engagement_exists", lambda engagement_id: True)

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    main_module.reset_auth_cache()
    yield TestClient(main_module.app)
    main_module.reset_auth_cache()


def test_api_status_and_validation(client):
    status = client.get("/api/automation/status").json()
    assert status["schedules"] == 0
    assert "store" in status
    valid = client.post("/api/automation/validate", json={"cron": "0 3 * * *"})
    assert valid.status_code == 200
    assert valid.json()["valid"] is True
    assert len(valid.json()["next_runs"]) == 5
    assert (
        client.post("/api/automation/validate", json={"cron": "nope"}).status_code
        == 400
    )


def test_api_schedule_crud_and_runs(client, monkeypatch):
    missing_scope = client.post(
        "/api/automation/schedules", json={"name": "x", "cron": "* * * * *"}
    )
    assert missing_scope.status_code == 400
    created = client.post(
        "/api/automation/schedules",
        json={
            "name": "nightly",
            "cron": "0 3 * * *",
            "engagement_id": "eng1",
            "deep_web": True,
        },
    )
    assert created.status_code == 200
    schedule = created.json()
    assert schedule["deep_web"] is True
    assert schedule["next_run"]

    listing = client.get("/api/automation/schedules").json()["schedules"]
    assert [s["id"] for s in listing] == [schedule["id"]]
    fetched = client.get(f"/api/automation/schedules/{schedule['id']}")
    assert fetched.status_code == 200
    patched = client.patch(
        f"/api/automation/schedules/{schedule['id']}",
        json={"cron": "@hourly", "enabled": False},
    )
    assert patched.status_code == 200
    assert patched.json()["cron"] == "@hourly"
    assert patched.json()["enabled"] is False

    bad_patch = client.patch(
        f"/api/automation/schedules/{schedule['id']}", json={"cron": "nope"}
    )
    assert bad_patch.status_code == 400
    assert client.patch("/api/automation/schedules/missing", json={}).status_code == 404

    run = client.post(
        f"/api/automation/schedules/{schedule['id']}/run", json={"wait": True}
    )
    assert run.status_code == 200
    assert run.json()["status"] == "complete"
    assert run.json()["result"]["job_id"] == "job-api"
    runs = client.get(f"/api/automation/schedules/{schedule['id']}/runs").json()
    assert len(runs["runs"]) == 1
    assert runs["runs"][0]["job_id"] == "job-api"
    assert client.get("/api/automation/runs").json()["runs"]

    deleted = client.delete(f"/api/automation/schedules/{schedule['id']}")
    assert deleted.status_code == 200
    assert (
        client.delete(f"/api/automation/schedules/{schedule['id']}").status_code == 404
    )
    assert client.get(f"/api/automation/schedules/{schedule['id']}").status_code == 404
    assert (
        client.get(f"/api/automation/schedules/{schedule['id']}/runs").status_code
        == 404
    )


def test_api_background_run_and_unknown_scope(client, monkeypatch):
    import routers.automation as auto_router

    monkeypatch.setattr(auto_router, "_engagement_exists", lambda engagement_id: False)
    assert (
        client.post(
            "/api/automation/schedules",
            json={"name": "x", "cron": "* * * * *", "engagement_id": "nope"},
        ).status_code
        == 404
    )
    monkeypatch.setattr(auto_router, "_engagement_exists", lambda engagement_id: True)
    created = client.post(
        "/api/automation/schedules",
        json={"name": "x", "cron": "0 3 * * *", "engagement_id": "eng1"},
    ).json()
    started = client.post(f"/api/automation/schedules/{created['id']}/run", json={})
    assert started.status_code == 200
    assert started.json()["status"] == "started"


def test_api_unknown_schedule_run(client):
    assert (
        client.post("/api/automation/schedules/missing/run", json={}).status_code == 404
    )


def test_run_autopilot_requires_scope(monkeypatch):
    result = nightly.run_autopilot({"id": "s1"})
    assert result["ok"] is False
    assert "engagement_id" in result["error"]


def test_run_autopilot_completes_and_errors(monkeypatch):
    import routers.scan as scan

    monkeypatch.setenv("H4K_NIGHTLY_POLL", "0")
    monkeypatch.setattr(
        scan,
        "autopilot_start",
        lambda req: {"job_id": "job1", "status": "running"},
    )
    monkeypatch.setattr(
        scan,
        "autopilot_status",
        lambda: {"status": "complete", "hosts": {"h": 1}, "message": "done"},
    )
    result = nightly.run_autopilot({"engagement_id": "e1", "deep_web": True})
    assert result["ok"] is True
    assert result["job_id"] == "job1"
    assert result["hosts"] == 1

    def _boom(_req):
        raise RuntimeError("no scope")

    monkeypatch.setattr(scan, "autopilot_start", _boom)
    failed = nightly.run_autopilot({"engagement_id": "e1"})
    assert failed["ok"] is False
    assert "no scope" in failed["error"]

    monkeypatch.setattr(
        scan, "autopilot_start", lambda req: {"job_id": "job2", "status": "running"}
    )
    monkeypatch.setattr(scan, "autopilot_status", lambda: {"status": "running"})
    monkeypatch.setenv("H4K_NIGHTLY_TIMEOUT", "0")
    timed_out = nightly.run_autopilot({"engagement_id": "e1"})
    assert timed_out["ok"] is False
    assert "timed out" in timed_out["error"]


def test_serve_start_stop(tmp_path):
    import asyncio

    store = nightly.ScheduleStore(tmp_path / "async.db")
    scheduler = nightly.NightlyScheduler(store=store, runner=lambda s: {"ok": True})

    async def scenario():
        task = scheduler.start(interval=999)
        await asyncio.sleep(0.05)
        assert scheduler.running is True
        await scheduler.stop()
        assert scheduler.running is False
        assert task.cancelled() or task.done()

    asyncio.run(scenario())


def test_cron_more_invalid_forms():
    for expression in (
        "0,,1 * * * *",
        "*/x * * * *",
        "5-1 * * * *",
        "x * * * *",
        "0 0 * x *",
    ):
        with pytest.raises(nightly.CronError):
            nightly.parse_cron(expression)


def test_next_run_accepts_naive_datetime():
    assert nightly.next_run("* * * * *", datetime(2026, 1, 1, 0, 0)) == datetime(
        2026, 1, 1, 0, 1, tzinfo=UTC
    )
