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
    monkeypatch.setattr(main_module.shutil, "which", lambda _n: None)
    assert main_module._relaunch_msfrpcd("127.0.0.1", 55553, "x") is False
