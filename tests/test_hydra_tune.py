"""Backlog #30: Hydra parallel tune + checkpoint resume."""

from __future__ import annotations

from typing import Any

from services.hydra_tune import PROFILES, fragment, job_dir, resolve
from services.sandbox import _hydra_target


def test_profiles() -> None:
    assert PROFILES["standard"]["tasks"] == 16
    assert resolve("quick") == {"profile": "quick", "tasks": 4, "wait": 0}
    assert resolve("bogus")["profile"] == "standard"


def test_clamp_and_override() -> None:
    assert resolve("standard", tasks=999)["tasks"] == 64
    assert resolve("standard", tasks=0)["tasks"] == 1
    assert resolve("standard", wait=99)["wait"] == 30
    assert resolve(None, None, None)["tasks"] == 16


def test_fragment() -> None:
    assert fragment({"tasks": 16, "wait": 0}) == ["-t", "16"]
    assert fragment({"tasks": 8, "wait": 5}) == ["-t", "8", "-W", "5"]


def test_job_dir_scoped(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    d = job_dir("abc123!@#")
    assert d.parent.name == "hydra" and d.name == "abc123"
    assert d.is_dir()


def test_hydra_target_robust() -> None:
    assert (
        _hydra_target(
            ["hydra", "-L", "u", "-P", "p", "-t", "16", "-f", "10.0.0.9", "ssh"]
        )
        == "10.0.0.9"
    )
    assert _hydra_target(["hydra", "-t", "4", "-R", "10.0.0.9", "ssh"]) == "10.0.0.9"
    assert _hydra_target(["hydra", "-t", "4", "-f", "http-get://h:80/"]) == "h"
    assert _hydra_target(["hydra"]) == ""


def test_passattack_tune_and_resume(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import app_state
    import main as main_module
    from routers import scan as scan_router

    assert scan_router._passattack_jobs == {}
    monkeypatch.setattr(app_state, "msf_client", object())

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.post(
        "/api/passattack",
        json={"host": "10.10.10.9", "service": "ssh", "profile": "quick", "tasks": 8},
    )
    assert r.status_code == 200, r.text
    assert r.json()["tune"] == {"profile": "quick", "tasks": 8, "wait": 0}
    job_id = r.json()["job_id"]
    import time

    deadline = time.time() + 30
    while time.time() < deadline:
        st = c.get(f"/api/passattack/{job_id}").json()
        if st["status"] == "done":
            break
        time.sleep(0.5)
    assert st["status"] == "done"
    assert "8 tasks" in " ".join(st.get("log", []))
    r = c.post(f"/api/passattack/{job_id}/resume", json={})
    assert r.status_code == 200 and r.json()["resumed"] is False
    deadline = time.time() + 30
    while time.time() < deadline:
        if c.get(f"/api/passattack/{job_id}").json()["status"] == "done":
            break
        time.sleep(0.5)
    assert c.get(f"/api/passattack/{job_id}").json()["status"] == "done"
    assert c.post("/api/passattack/nope/resume", json={}).status_code == 404
    r = c.post(
        "/api/passattack", json={"host": "10.10.10.9", "service": "ssh", "tasks": 999}
    )
    assert r.json()["tune"]["tasks"] == 64
