"""Backlog #10: lockout-aware spray guard (jitter, per-user cap, ledger stop)."""

from __future__ import annotations

import random
from typing import Any

from services.engagement import EngagementStore
from services.propagate import PropagationService
from services.spray_guard import (
    SprayPolicy,
    apply_policy,
    is_lockout_signal,
    jitter_delay,
)


def _eng(store: Any) -> Any:
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    store.ingest_scan(
        eng["id"],
        {
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 22, "service": "ssh"}]},
                {"address": "10.0.0.9", "services": [{"port": 22, "service": "ssh"}]},
                {"address": "10.0.0.11", "services": [{"port": 22, "service": "ssh"}]},
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
    return eng


class FakeMsf:
    def __init__(self, good: Any = (), lockouts: Any = ()) -> None:
        self.good = set(good)
        self.lockouts = set(lockouts)

    def execute(self, kind: str, module: str, opts: dict[str, Any]) -> bool:
        if opts["RHOSTS"] in self.lockouts:
            raise RuntimeError("Account locked out: too many failures")
        return opts["RHOSTS"] in self.good


def test_lockout_markers() -> None:
    assert is_lockout_signal("Account locked out") is True
    assert is_lockout_signal("too many failed logins") is True
    assert is_lockout_signal("login failed") is False
    assert is_lockout_signal(None) is False


def test_jitter_zero_by_default() -> None:
    assert jitter_delay(SprayPolicy()) == 0.0
    assert jitter_delay(SprayPolicy(jitter_max=0.0)) == 0.0
    d = jitter_delay(SprayPolicy(jitter_max=2.0), random.Random(1))
    assert 0.0 <= d <= 2.0


def test_per_user_cap_holds_back(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "cap.db")
    _eng(store)
    pairs = [
        {
            "user": "root",
            "password": "toor",
            "host": h,
            "port": 22,
            "service": "ssh",
            "module": "m",
            "origin_host": "10.0.0.5",
        }
        for h in ("10.0.0.9", "10.0.0.11")
    ]
    out = apply_policy(pairs, [], SprayPolicy(max_per_user=1))
    assert len(out["pairs"]) == 1 and out["held_capped"] == 1


def test_apply_policy_holds_locked() -> None:
    pairs = [
        {
            "user": "root",
            "password": "toor",
            "host": "10.0.0.9",
            "port": 22,
            "service": "ssh",
            "module": "m",
            "origin_host": "10.0.0.5",
        }
    ]
    rows = [{"user": "root", "result": "locked"}]
    out = apply_policy(pairs, rows, SprayPolicy())
    assert out["pairs"] == [] and out["held_locked"] == 1


def test_locked_users_never_retried(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "locked.db")
    eng = _eng(store)
    svc = PropagationService(FakeMsf(lockouts={"10.0.0.9"}), store)
    res = svc.run(eng["id"])
    assert res["locked"] == 1
    by_host = {a["host"]: a["result"] for a in res["attempts"]}
    assert by_host["10.0.0.9"] == "locked"
    assert by_host["10.0.0.11"] == "failed"
    second = svc.run(eng["id"])
    assert second["attempted"] == 0  # locked held, miss ledgered: nothing left
    assert svc.plan(eng["id"])["locked_users"] == ["root"]


def test_run_defaults_unchanged_for_existing_flows(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "compat.db")
    eng = _eng(store)
    res = PropagationService(FakeMsf(good={"10.0.0.9"}), store).run(eng["id"])
    assert res["verified"] == 1 and res["locked"] == 0
    assert res["policy"]["max_per_user"] == 25


def test_plan_reports_policy(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "plan.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)
    app_state.msf_client = FakeMsf()

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eng = _eng(store)
    r = c.get(f"/api/engagement/{eng['id']}/propagate/plan?max_per_user=1")
    assert r.status_code == 200
    body = r.json()
    assert body["policy"]["max_per_user"] == 1
    assert body["attempts"] == 1
