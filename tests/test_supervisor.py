"""Supervisor: backoff budgets, recovery, status shape (offline, no daemon)."""

import socket

from services import supervisor as sup


def _spec(name="svc", alive=True, restarts=None):
    calls = {"n": 0}

    def check():
        return alive[0] if isinstance(alive, list) else alive

    def restart():
        calls["n"] += 1
        (restarts if restarts is not None else []).append(1)
        return True

    return sup.ServiceSpec(name, check, restart), calls


def test_healthy_service_is_left_alone():
    now = [1000.0]
    spec, calls = _spec(alive=True)
    s = sup.Supervisor([spec], clock=lambda: now[0])
    rep = s.tick()
    assert rep["svc"]["up"] is True
    assert calls["n"] == 0
    assert rep["svc"]["restarts_total"] == 0


def test_down_service_is_restarted_once():
    now = [1000.0]
    spec, calls = _spec(alive=False)
    s = sup.Supervisor([spec], clock=lambda: now[0])
    s.tick()
    assert calls["n"] == 1
    assert spec.restarts_total == 1


def test_restart_budget_is_enforced_then_resumes():
    now = [1000.0]
    spec, calls = _spec(alive=False)
    spec.max_restarts = 2
    spec.window_seconds = 100
    s = sup.Supervisor([spec], clock=lambda: now[0])
    s.tick()
    s.tick()
    assert calls["n"] == 2
    s.tick()  # budget exhausted -> degraded, no restart
    assert calls["n"] == 2
    assert spec.degraded is True
    now[0] += 101  # window slides -> restarts resume, still degraded until probe passes
    s.tick()
    assert calls["n"] == 3
    assert spec.degraded is True


def test_recovered_service_clears_degraded():
    now = [1000.0]
    alive = [False]
    spec, calls = _spec(alive=alive)
    spec.max_restarts = 1
    spec.window_seconds = 100
    s = sup.Supervisor([spec], clock=lambda: now[0])
    s.tick()  # restart
    assert calls["n"] == 1
    s.tick()  # budget exhausted -> degraded
    assert spec.degraded is True
    alive[0] = True
    s.tick()
    assert spec.ok is True
    assert spec.degraded is False


def test_status_shape():
    s = sup.Supervisor([], clock=lambda: 0.0)
    st = s.status()
    assert st["enabled"] is False  # no specs supervised
    assert st["services"] == {}


def test_tcp_open_detects_live_and_dead_ports():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        assert sup.tcp_open("127.0.0.1", srv.getsockname()[1]) is True
    finally:
        srv.close()
    assert sup.tcp_open("127.0.0.1", 1, timeout=0.5) is False


def test_relaunch_without_binary_is_false(monkeypatch):
    monkeypatch.setattr(sup.shutil, "which", lambda _: None)
    assert sup.relaunch_msfrpcd("127.0.0.1", 55553, "x") is False


def test_default_specs_empty_in_sandbox(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import services.sandbox as sandbox_mod

    monkeypatch.setattr(sandbox_mod, "enabled", lambda: True)
    assert sup.default_specs() == []
