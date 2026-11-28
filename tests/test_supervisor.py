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


class _FakeFile:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _Proc:
    def __init__(self, returncode):
        self.returncode = returncode


def test_relaunch_msfrpcd_builds_fixed_argv(monkeypatch):
    logfile = _FakeFile()
    recorded = {}
    monkeypatch.setattr(sup.shutil, "which", lambda name: "/usr/bin/msfrpcd")
    monkeypatch.setattr(sup.os, "makedirs", lambda *a, **k: None)
    monkeypatch.setattr("builtins.open", lambda *a, **k: logfile)

    def fake_popen(argv, **kwargs):
        recorded["argv"] = argv
        recorded["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(sup.subprocess, "Popen", fake_popen)
    assert sup.relaunch_msfrpcd("10.1.2.3", 55553, "s3cret") is True
    assert recorded["argv"] == [
        "/usr/bin/msfrpcd",
        "-a",
        "10.1.2.3",
        "-p",
        "55553",
        "-U",
        "msf",
        "-P",
        "s3cret",
        "-S",
        "true",
        "-f",
    ]
    assert recorded["kwargs"]["stdout"] is logfile
    assert recorded["kwargs"]["stderr"] is sup.subprocess.STDOUT
    assert recorded["kwargs"]["start_new_session"] is True


def test_relaunch_msfrpcd_oserror_is_false(monkeypatch):
    monkeypatch.setattr(sup.shutil, "which", lambda name: "/usr/bin/msfrpcd")
    monkeypatch.setattr(sup.os, "makedirs", lambda *a, **k: None)
    monkeypatch.setattr("builtins.open", lambda *a, **k: _FakeFile())

    def boom(*a, **k):
        raise OSError("cannot exec")

    monkeypatch.setattr(sup.subprocess, "Popen", boom)
    assert sup.relaunch_msfrpcd("127.0.0.1", 55553, "x") is False


def test_restart_service_unit_success(monkeypatch):
    seen = {}
    monkeypatch.setattr(sup.shutil, "which", lambda name: "/usr/sbin/service")

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _Proc(0)

    monkeypatch.setattr(sup.subprocess, "run", fake_run)
    assert sup.restart_service_unit("postgresql") is True
    assert seen["argv"] == ["service", "postgresql", "start"]
    assert seen["kwargs"]["check"] is False
    assert seen["kwargs"]["timeout"] == 120


def test_restart_service_unit_nonzero_and_errors(monkeypatch):
    monkeypatch.setattr(sup.shutil, "which", lambda name: "/usr/sbin/service")
    monkeypatch.setattr(sup.subprocess, "run", lambda *a, **k: _Proc(1))
    assert sup.restart_service_unit("tor") is False

    def timed_out(*a, **k):
        raise sup.subprocess.TimeoutExpired(["service", "tor", "start"], 120)

    monkeypatch.setattr(sup.subprocess, "run", timed_out)
    assert sup.restart_service_unit("tor") is False

    def oserror(*a, **k):
        raise OSError("missing")

    monkeypatch.setattr(sup.subprocess, "run", oserror)
    assert sup.restart_service_unit("tor") is False


def test_port_helpers_defaults_overrides_and_bad_values(monkeypatch):
    for key in ("MSF_HOST", "MSF_PORT", "MSF_PASSWORD", "MSF_DB_PORT", "TOR_PORT"):
        monkeypatch.delenv(key, raising=False)
    assert sup._msf_host() == "127.0.0.1"
    assert sup._msf_port() == 55553
    assert sup._msf_password() == "h4k_msf_rocks"
    assert sup._db_port() == 5433
    assert sup._tor_port() == 9050

    monkeypatch.setenv("MSF_HOST", "10.0.0.2")
    monkeypatch.setenv("MSF_PORT", "1234")
    monkeypatch.setenv("MSF_PASSWORD", "pw")
    monkeypatch.setenv("MSF_DB_PORT", "6432")
    monkeypatch.setenv("TOR_PORT", "9150")
    assert sup._msf_host() == "10.0.0.2"
    assert sup._msf_port() == 1234
    assert sup._msf_password() == "pw"
    assert sup._db_port() == 6432
    assert sup._tor_port() == 9150

    monkeypatch.setenv("MSF_PORT", "nope")
    monkeypatch.setenv("MSF_DB_PORT", "nope")
    monkeypatch.setenv("TOR_PORT", "nope")
    assert sup._msf_port() == 55553
    assert sup._db_port() == 5433
    assert sup._tor_port() == 9050


def test_auto_scan_helpers(monkeypatch):
    from services import auto_scan as auto_scan_mod

    monkeypatch.setattr(auto_scan_mod, "status", lambda: {"running": True})
    assert sup._auto_scan_alive() is True
    monkeypatch.setattr(auto_scan_mod, "status", lambda: {"running": False})
    assert sup._auto_scan_alive() is False

    def status_boom():
        raise RuntimeError("no status")

    monkeypatch.setattr(auto_scan_mod, "status", status_boom)
    assert sup._auto_scan_alive() is False

    calls = []
    monkeypatch.setattr(auto_scan_mod, "stop", lambda: calls.append("stop"))
    monkeypatch.setattr(
        auto_scan_mod, "start", lambda force=False: calls.append(("start", force))
    )
    assert sup._auto_scan_restart() is True
    assert calls == ["stop", ("start", True)]

    def start_boom(force=False):
        raise RuntimeError("cannot start")

    monkeypatch.setattr(auto_scan_mod, "start", start_boom)
    assert sup._auto_scan_restart() is False


def test_default_specs_real_container_offline(monkeypatch):
    import services.sandbox as sandbox_mod

    monkeypatch.setattr(sandbox_mod, "enabled", lambda: False)
    monkeypatch.setattr(sup.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(sup, "tcp_open", lambda host, port: False)
    restarts = []
    monkeypatch.setattr(
        sup, "restart_service_unit", lambda unit: restarts.append(unit) or True
    )
    monkeypatch.setattr(
        sup,
        "relaunch_msfrpcd",
        lambda host, port, password: restarts.append((host, port, password)) or True,
    )
    monkeypatch.setattr(sup, "_auto_scan_alive", lambda: True)
    monkeypatch.setattr(sup, "_auto_scan_restart", lambda: True)

    specs = sup.default_specs()
    assert [s.name for s in specs] == ["postgres", "msfrpcd", "tor", "auto_scan"]
    for spec in specs:
        assert spec.check() in (True, False)
    specs[0].restart()
    specs[1].restart()
    specs[2].restart()
    assert restarts == ["postgresql", ("127.0.0.1", 55553, "h4k_msf_rocks"), "tor"]


def test_default_specs_sandbox_probe_error_falls_through(monkeypatch):
    import services.sandbox as sandbox_mod

    def sandbox_boom():
        raise RuntimeError("sandbox probe failed")

    monkeypatch.setattr(sandbox_mod, "enabled", sandbox_boom)
    monkeypatch.setattr(sup.shutil, "which", lambda name: None)
    monkeypatch.setattr(sup, "_auto_scan_alive", lambda: False)
    monkeypatch.setattr(sup, "_auto_scan_restart", lambda: False)
    specs = sup.default_specs()
    assert [s.name for s in specs] == ["postgres", "tor", "auto_scan"]


def test_restart_service_unit_without_service_binary(monkeypatch):
    monkeypatch.setattr(sup.shutil, "which", lambda name: None)
    assert sup.restart_service_unit("postgresql") is False
