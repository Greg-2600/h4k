"""Backlog #58: authenticated fuzz profiles — cookie/header presets."""

from __future__ import annotations

from typing import Any

import pytest
from services.fuzz_profiles import (
    delete_profile,
    list_profiles,
    resolve_auth,
    save_profile,
)


def test_save_list_delete(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    assert list_profiles() == {"profiles": [], "count": 0}
    entry = save_profile(
        "lab", {"Authorization": "Bearer s3cret"}, {"session": "abc", "x": "1"}
    )
    assert entry["name"] == "lab"
    listed = list_profiles()
    assert listed["count"] == 1
    only = listed["profiles"][0]
    # Values never leave the server through list/masked views.
    assert only == {
        "name": "lab",
        "headers": ["Authorization"],
        "cookies": ["session", "x"],
        "header_count": 1,
        "cookie_count": 2,
        "updated": only["updated"],
    }
    assert "s3cret" not in str(listed)
    assert delete_profile("lab") is True
    assert delete_profile("lab") is False
    assert list_profiles()["count"] == 0


def test_validation(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    with pytest.raises(ValueError):
        save_profile("", {"A": "b"})
    with pytest.raises(ValueError):
        save_profile("bad name!", {"A": "b"})
    with pytest.raises(ValueError):
        save_profile("empty", {}, {})
    with pytest.raises(ValueError):
        delete_profile("??")


def test_resolve_auth_merging(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    save_profile("lab", {"A": "preset", "B": "preset"}, {"s": "preset"})
    out = resolve_auth("lab", {"B": "explicit", "C": "explicit"}, {"t": "1"})
    assert out == {
        "headers": {"A": "preset", "B": "explicit", "C": "explicit"},
        "cookies": {"s": "preset", "t": "1"},
    }
    assert resolve_auth(None, {"A": "b"}, None) == {
        "headers": {"A": "b"},
        "cookies": {},
    }
    with pytest.raises(ValueError, match="unknown auth profile"):
        resolve_auth("nope", {}, {})


def _client(tmp_path: Any, monkeypatch: Any) -> Any:
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

    return TestClient(main_module.app)


def test_profiles_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    assert c.get("/api/fuzz-profiles").json() == {"profiles": [], "count": 0}

    r = c.post(
        "/api/fuzz-profiles",
        json={
            "name": "lab",
            "headers": {"Authorization": "Bearer s3cret"},
            "cookies": {"session": "abc"},
        },
    )
    assert r.status_code == 200
    assert r.json()["headers"] == ["Authorization"]
    assert "s3cret" not in r.text

    assert (
        c.post(
            "/api/fuzz-profiles", json={"name": "bad name!", "headers": {"A": "b"}}
        ).status_code
        == 400
    )
    assert c.post("/api/fuzz-profiles", json={"name": "empty"}).status_code == 400

    assert c.delete("/api/fuzz-profiles/lab").json() == {"deleted": "lab"}
    assert c.delete("/api/fuzz-profiles/lab").status_code == 404
    assert c.delete("/api/fuzz-profiles/!!!").status_code == 400


def test_stateful_profile_wiring(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    flow = [{"method": "GET", "url": "http://10.10.10.99/x", "fields": ["query:q"]}]
    # Unknown profile is a 404 even in sandbox (fail closed, never fuzz unauthed).
    assert (
        c.post(
            "/api/stateful_fuzz",
            json={
                "login_url": "http://10.10.10.99/login",
                "flow": flow,
                "profile": "nope",
            },
        ).status_code
        == 404
    )
    # A saved preset is accepted and merged.
    assert (
        c.post(
            "/api/fuzz-profiles",
            json={
                "name": "lab",
                "headers": {"X-Lab": "1"},
                "cookies": {"session": "abc"},
            },
        ).status_code
        == 200
    )
    r = c.post(
        "/api/stateful_fuzz",
        json={
            "login_url": "http://10.10.10.99/login",
            "flow": flow,
            "profile": "lab",
        },
    )
    assert r.status_code == 200


def test_stateful_uses_profile(tmp_path: Any, monkeypatch: Any) -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlsplit

    seen: dict[str, Any] = {}

    class _Handler(BaseHTTPRequestHandler):
        def _answer(self, ok: bool, body: bytes = b"ok Logout") -> None:
            seen["auth"] = self.headers.get("Authorization", "")
            seen["cookie"] = self.headers.get("Cookie", "")
            code = 200 if ok else 401
            if self.path == "/login":
                body = b'{"token": "tok"}'
                code = 200
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
            else:
                body = body if ok else b"login required"
                self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self._answer(self.path != "/private" or True)

        def do_GET(self) -> None:
            if urlsplit(self.path).path == "/login":
                self._answer(True)
            else:
                authed = "session=abc" in (self.headers.get("Cookie") or "")
                self._answer(authed)

        def log_message(self, *args: Any) -> None:
            return

    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    ).start()
    try:
        from services.fuzz_profiles import resolve_auth
        from services.stateful_fuzz import fuzz_flow

        base = f"http://127.0.0.1:{srv.server_address[1]}"
        # Preset supplies the session cookie; login body is a dummy.
        auth = resolve_auth(None, {}, {"session": "abc"})
        out = fuzz_flow(
            f"{base}/login",
            login_body={},
            login_headers={},
            steps=[{"method": "GET", "url": f"{base}/private", "fields": []}],
            iterations=4,
            timeout=5.0,
            preset_cookies=auth["cookies"],
        )
        assert out["clean"] is True and out["logins"] == 4
        assert "session=abc" in seen.get("cookie", "")
    finally:
        srv.shutdown()
        srv.server_close()
