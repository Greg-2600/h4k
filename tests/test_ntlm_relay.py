"""Backlog #33: NTLM relay lab (explicit targets, container-only)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from services.ntlm_relay import parse_result, sandbox_run


def test_parse_result() -> None:
    out = parse_result(
        "[*] Authenticating against smb://h as D\\u SUCCEED\n"
        "[+] smb://h PWNED\n"
        "noise\n"
    )
    assert out["pwned_count"] == 1 and out["authenticated_count"] == 1
    assert parse_result("") == {
        "pwned": [],
        "pwned_count": 0,
        "authenticated": [],
        "authenticated_count": 0,
    }


def test_run_relay_argv() -> None:
    from services.ntlm_relay import run_relay

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        out = run_relay(["smb://10.0.0.9"], socks=True, dump=False)
    argv = mock_run.call_args[0][0]
    assert argv[0] == "ntlmrelayx.py"
    assert "-tf" in argv and "-socks" in argv and "--no-dump" in argv
    assert out["success"] is True


def test_run_relay_requires_targets() -> None:
    from services.ntlm_relay import run_relay

    try:
        run_relay([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty targets must raise")


def test_sandbox_run() -> None:
    out = sandbox_run(["smb://10.0.0.9"])
    assert out["authenticated_count"] == 1 and out["sandbox"] is True


def test_relay_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "relay.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eid = c.post(
        "/api/engagement", json={"name": "acme", "scope": ["10.0.0.0/24"]}
    ).json()["id"]
    r = c.post(
        "/api/relay/run", json={"targets": ["smb://10.0.0.5"], "engagement_id": eid}
    )
    assert r.status_code == 200, r.text
    assert r.json()["authenticated_count"] == 1
    assert r.json()["skipped_out_of_scope"] == []
    r = c.post(
        "/api/relay/run", json={"targets": ["smb://8.8.8.8"], "engagement_id": eid}
    )
    assert r.status_code == 400
    assert "out of scope" in r.json()["detail"]
    assert c.post("/api/relay/run", json={"targets": []}).status_code == 400
    assert (
        c.post(
            "/api/relay/run", json={"targets": ["smb://x"], "engagement_id": "nope"}
        ).status_code
        == 404
    )
