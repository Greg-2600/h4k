"""Unit tests for the msfrpcd watchdog helpers (offline, no daemon)."""

import socket
import threading

import main as main_module


def test_port_closed_reports_not_open():
    assert main_module._msf_port_open("127.0.0.1", 1, timeout=0.5) is False


def test_port_open_reports_open():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                break

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        assert main_module._msf_port_open("127.0.0.1", port, timeout=2) is True
    finally:
        stop.set()
        srv.close()


def test_relaunch_without_binary_returns_false(monkeypatch):
    monkeypatch.setattr("services.supervisor.shutil.which", lambda _n: None)
    assert main_module._relaunch_msfrpcd("127.0.0.1", 55553, "x") is False


def test_health_reports_supervised_services(monkeypatch, tmp_path):
    from contextlib import asynccontextmanager

    from fastapi.testclient import TestClient

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import app_state
    import main as main_module

    class FakeMsf:
        pass

    app_state.msf_client = FakeMsf()

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    client = TestClient(main_module.app)
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert "msf" in body and "services" in body
    assert isinstance(body["services"], dict)
