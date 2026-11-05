"""Backlog #34: chisel/sshuttle pivot — one-click tunnel + proxied rescan."""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from services.pivot_tunnel import (
    list_tunnels,
    proxied_scan,
    sandbox_scan,
    sandbox_tunnels,
    socks_connect,
    stop_tunnel,
)


def _echo_server() -> tuple[HTTPServer, int]:
    class Echo(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"echo-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            return

    srv = HTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    return srv, srv.server_address[1]


def _socks5_stub(target_host: str, target_port: int) -> tuple[socket.socket, int]:
    """Minimal SOCKS5 CONNECT stub forwarding to one fixed upstream."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def _serve() -> None:
        for _ in range(2):
            conn, _ = srv.accept()
            conn.settimeout(10)
            conn.recv(3)
            conn.sendall(b"\x05\x00")
            req = conn.recv(10)
            assert req[0] == 5 and req[1] == 1
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            up = socket.create_connection((target_host, target_port), timeout=10)
            up.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            try:
                data = up.recv(4096)
            finally:
                up.close()
            conn.sendall(data)
            conn.close()
        srv.close()

    threading.Thread(target=_serve, daemon=True).start()
    return srv, port


def test_socks_connect_and_proxied_scan() -> None:
    echo, echo_port = _echo_server()
    _, socks_port = _socks5_stub("127.0.0.1", echo_port)
    s = socks_connect("127.0.0.1", socks_port, "10.9.9.9", 80)
    s.close()
    out = proxied_scan("127.0.0.1", socks_port, "10.9.9.9", ports=[80, 81])
    by_port = {r["port"]: r for r in out["results"]}
    assert by_port[80]["open"] is True
    assert "HTTP/1.0 200" in (by_port[80].get("banner") or "")
    assert by_port[81]["open"] is False
    assert out["open_count"] == 1
    echo.shutdown()
    echo.server_close()


def test_registry_roundtrip(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    assert list_tunnels()["count"] == 0
    assert sandbox_tunnels()["count"] == 1
    assert sandbox_scan("10.0.0.5")["open_count"] == 2
    assert stop_tunnel("nope")["stopped"] is False


def test_tunnel_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.post(
        "/api/net/tunnel", json={"kind": "ssh", "ssh_host": "h", "ssh_user": "u"}
    )
    assert r.status_code == 200 and "tunnels" in r.json()
    r = c.get("/api/net/tunnels")
    assert r.status_code == 200 and r.json()["count"] == 1
    r = c.post("/api/net/tunnel", json={"kind": "bogus"})
    assert r.status_code == 200  # sandbox canned; kind validated only off-sandbox
    r = c.post("/api/net/tunnel/scan", json={"target": "10.0.0.5"})
    assert r.status_code == 200 and r.json()["open_count"] == 2
    assert c.post("/api/net/tunnel/scan", json={}).status_code == 400
    r = c.delete("/api/net/tunnels/x")
    assert r.status_code in (200, 404)
