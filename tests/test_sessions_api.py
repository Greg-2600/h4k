"""Router-level tests for /api/sessions liveness.

A recorded session is history; only a session msfrpcd still holds is usable.
The API must never present a dead one as live (that dead-end cost a real
engagement an afternoon: "success" with session 8/9/10 that did not exist).
"""

from contextlib import asynccontextmanager

import pytest


class FakeMsf:
    """One live session (id 1); recorded id 99 is long dead."""

    def sessions(self, *a, **k):
        return {"1": {"target_host": "192.168.1.84", "type": "meterpreter"}}

    def current_workspace(self, *a, **k):
        return "default"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsf()

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop

    # a stale recorded session, as left behind by a dead handler
    from routers import scan as scan_router

    conn = scan_router._neighbor_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS exploit_sessions ("
        "  msf_session_id TEXT PRIMARY KEY,"
        "  host           TEXT NOT NULL,"
        "  port           INTEGER,"
        "  module         TEXT,"
        "  opened_at      TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "INSERT OR REPLACE INTO exploit_sessions "
        "(msf_session_id, host, port, module, opened_at) "
        "VALUES (?,?,?,?,?)",
        ("99", "192.168.1.84", 80, "exploit/unix/webapp/zoneminder_lang_exec", "now"),
    )
    conn.commit()
    conn.close()

    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_live_session_is_marked_alive(client):
    body = client.get("/api/sessions").json()
    live = [s for s in body["sessions"] if s["msf_session_id"] == "1"]
    assert live and live[0]["alive"] is True
    assert live[0]["source"] == "msf"


def test_recorded_but_dead_session_is_marked_dead(client):
    body = client.get("/api/sessions").json()
    dead = [s for s in body["sessions"] if s["msf_session_id"] == "99"]
    assert dead and dead[0]["alive"] is False
    assert dead[0]["source"] == "recorded"
