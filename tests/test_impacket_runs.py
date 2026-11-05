"""Backlog #32: impacket one-clicks (explicit secretsdump)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from services.impacket_runs import parse_secretsdump, sandbox_dump, secretsdump


def test_parse_secretsdump() -> None:
    out = parse_secretsdump(
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "MACHINE$:1234:aa:bb::: ignored-no\n"
        "junk line\n"
        "svc:1104:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:::\n"
    )
    assert [(h["user"], h["rid"]) for h in out] == [
        ("Administrator", "500"),
        ("svc", "1104"),
    ]
    assert out[0]["nt"] == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_secretsdump_argv() -> None:
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        secretsdump("10.0.0.9", "admin", password="pw", domain="LAB")
    argv = mock_run.call_args[0][0]
    assert argv[0] == "secretsdump.py"
    assert argv[1] == "LAB/admin:pw@10.0.0.9"


def test_sandbox_dump() -> None:
    out = sandbox_dump("10.0.0.9")
    assert out["hash_count"] == 2 and out["sandbox"] is True


def test_secretsdump_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.post(
        "/api/impacket/secretsdump",
        json={"target": "10.0.0.9", "username": "admin", "password": "pw"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["hash_count"] == 2
    assert (
        c.post(
            "/api/impacket/secretsdump",
            json={"target": "10.0.0.9", "username": "admin"},
        ).status_code
        == 400
    )
    assert (
        c.post(
            "/api/impacket/secretsdump",
            json={"target": "", "username": "u", "password": "p"},
        ).status_code
        == 400
    )
