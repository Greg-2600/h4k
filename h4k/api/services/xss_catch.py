"""XSS catch lab — token/cookie catch + replay (Backlog #28, lab-only).

Blind XSS needs somewhere for the payload to phone home. This module
runs a tiny loopback-only HTTP catcher (stdlib, background thread) that
records exfiltrated tokens/cookies/headers, plus a replay helper that
re-sends a captured cookie at a target you own to confirm the session
still works. Loopback-only by construction: the socket binds
127.0.0.1, never 0.0.0.0, and the sandbox serves canned hits without
opening any socket.
"""

from __future__ import annotations

import logging
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

logger = logging.getLogger("h4k.xss_catch")

_lock = threading.Lock()
_hits: list[dict[str, Any]] = []
_server: HTTPServer | None = None
_thread: threading.Thread | None = None
_port: int = 0


def _record(path: str, headers: Any, body: bytes, client: str) -> dict[str, Any]:
    query = dict(
        urllib.parse.parse_qsl(
            urllib.parse.urlsplit(path).query, keep_blank_values=True
        )
    )
    cookie = ""
    try:
        cookie = str(headers.get("Cookie", "") or "")
    except Exception:
        cookie = ""
    token = query.get("token") or query.get("c") or ""
    hit = {
        "path": urllib.parse.urlsplit(path).path or "/",
        "query": query,
        "token": token,
        "cookie": cookie[:2000],
        "client": client,
    }
    with _lock:
        _hits.append(hit)
    return hit


class _Handler(BaseHTTPRequestHandler):
    server_version = "h4k-catch/1.0"

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 65536)) if length > 0 else b""
        _record(self.path, self.headers, body, self.client_address[0])
        data = b"ok"
        self.send_response(204)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *args: Any) -> None:  # keep test output clean
        return


def start(port: int = 0) -> dict[str, Any]:
    """Start the loopback-only catcher (idempotent)."""
    global _server, _thread, _port
    with _lock:
        if _server is not None:
            return {"running": True, "port": _port}
    server = HTTPServer(("127.0.0.1", port), _Handler)
    actual = server.server_address[1]
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True
    )
    thread.start()
    with _lock:
        _server, _thread, _port = server, thread, actual
    logger.info("xss catch lab listening on 127.0.0.1:%d", actual)
    return {"running": True, "port": actual}


def stop() -> dict[str, Any]:
    """Stop the catcher (hits are kept)."""
    global _server, _thread, _port
    with _lock:
        server, _server = _server, None
        _thread = None
        _port = 0
    if server is not None:
        server.shutdown()
        server.server_close()
    return {"running": False}


def hits(clear: bool = False) -> list[dict[str, Any]]:
    """Recorded catches, oldest first."""
    with _lock:
        out = list(_hits)
        if clear:
            _hits.clear()
    return out


def replay(target: str, cookie: str, timeout: float = 15.0) -> dict[str, Any]:
    """Replay a captured cookie at a target you own; compare with baseline.

    Returns status/length with and without the cookie so the operator can
    see whether the session is live. Read-only GETs.
    """
    import urllib.request

    def _get(extra_headers: dict[str, str]) -> dict[str, Any]:
        req = urllib.request.Request(
            target, headers={"User-Agent": "h4k-xss-replay/1.0", **extra_headers}
        )  # nosec B310 - operator-supplied lab target
        try:
            with urllib.request.urlopen(
                req, timeout=timeout
            ) as resp:  # nosec B310 - operator-supplied lab target
                body = resp.read(65536)
                return {"status": getattr(resp, "status", 200), "length": len(body)}
        except Exception as exc:
            return {"status": 0, "length": 0, "error": str(exc)[:200]}

    baseline = _get({})
    authed = _get({"Cookie": cookie}) if cookie else dict(baseline)
    return {
        "target": target,
        "baseline": baseline,
        "authed": authed,
        "session_live": bool(cookie)
        and authed.get("status") not in (0, 401, 403)
        and authed != baseline,
    }


def sandbox_hits() -> list[dict[str, Any]]:
    """Deterministic offline stand-ins (sandbox/e2e only)."""
    return [
        {
            "path": "/hook",
            "query": {
                "token": "sandbox-token"
            },  # nosec B105 - sandbox fixture, never sent
            "token": "sandbox-token",  # nosec B105 - sandbox fixture, never sent
            "cookie": "session=sandbox",  # nosec B105 - sandbox fixture, never sent
            "client": "127.0.0.1",
            "sandbox": True,
        }
    ]
