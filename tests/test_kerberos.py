"""Backlog #8: AS-REP + Kerberoast helpers with John handoff."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from services.kerberos import (
    KerberosService,
    crack_hashes,
    extract_hashes,
    sandbox_hashes,
)


def test_extract_hashes() -> None:
    text = (
        "noise $krb5asrep$23$u@D:aaa$bbb more\n"
        "and $krb5tgs$23$*s$D$*ccc$ddd end $krb5asrep$23$u@D:aaa$bbb"
    )
    out = extract_hashes(text)
    assert len(out) == 2
    assert out[0].startswith("$krb5asrep$")
    assert extract_hashes("nothing here") == []


def test_sandbox_hashes() -> None:
    assert sandbox_hashes("asrep")["hashes"][0].startswith("$krb5asrep$")
    assert sandbox_hashes("kerberoast")["hashes"][0].startswith("$krb5tgs$")


def test_asrep_argv() -> None:
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        out = KerberosService().asrep_roast(
            "LAB.LOCAL", dc_ip="10.0.0.1", users=["alice"]
        )
    argv = mock_run.call_args[0][0]
    assert "impacket-GetNPUsers" in argv
    assert "-dc-ip" in argv and "10.0.0.1" in argv
    assert out["hash_count"] == 0


def test_kerberoast_argv() -> None:
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        KerberosService().kerberoast("LAB.LOCAL", "svc", "pw")
    argv = mock_run.call_args[0][0]
    assert "impacket-GetUserSPNs" in argv
    assert "LAB.LOCAL/svc:pw" in argv


def test_crack_hashes_uses_john_format() -> None:
    with patch("services.john.JohnRunner.crack_ctf_hashes") as mock_crack:
        mock_crack.return_value = {"cracked": [], "remaining": ["h"]}
        crack_hashes(["h"], "asrep")
        assert mock_crack.call_args[1]["formats"] == ["krb5asrep"]
        crack_hashes(["h"], "kerberoast")
        assert mock_crack.call_args[1]["formats"] == ["krb5tgs"]


def test_kerberos_router_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
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
    r = c.post("/api/kerberos/asrep", json={"domain": "LAB.LOCAL"})
    assert r.status_code == 200 and r.json()["hash_count"] == 1
    r = c.post("/api/kerberos/kerberoast", json={"domain": "LAB.LOCAL"})
    assert r.status_code == 200 and r.json()["hash_count"] == 1
    r = c.post("/api/kerberos/kerberoast", json={"domain": "", "user": ""})
    assert r.status_code in (200, 400, 422)
    r = c.post("/api/kerberos/asrep", json={"domain": "LAB.LOCAL", "crack": True})
    assert r.status_code == 200 and r.json()["cracked"] == []
