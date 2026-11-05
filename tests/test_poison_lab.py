"""Backlog #9: LLMNR/NBT-NS poison lab (analyze default, gated poison)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from services.poison_lab import (
    PoisonLab,
    extract_hashes,
    is_lab_interface,
)


def test_lab_interface_gate(monkeypatch: Any) -> None:
    monkeypatch.delenv("H4K_POISONLAB_ALLOW", raising=False)
    assert is_lab_interface("lo") is True
    assert is_lab_interface("docker0") is True
    assert is_lab_interface("vethabc123") is True
    assert is_lab_interface("eth0") is False
    assert is_lab_interface("") is False


def test_allow_all_override(monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_POISONLAB_ALLOW", "all")
    assert is_lab_interface("eth0") is True


def test_extract_hashes() -> None:
    log = "NTLMv2-SSP Hash     : alice::LAB:1122:aabb\nnoise\n"
    assert extract_hashes(log) == ["alice::LAB:1122:aabb"]
    assert extract_hashes("nothing") == []


def test_poison_needs_both_confirmations() -> None:
    lab = PoisonLab()
    out = lab.listen("eth0", poison=True, confirm_lab=False)
    assert out["refused"] is True
    out = lab.listen("eth0", poison=True, confirm_lab=True)
    assert out["refused"] is True and "not a lab" in out["error"]


def test_analyze_uses_responder_analyze_flag() -> None:
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        out = PoisonLab().listen("lo", duration=10)
    argv = mock_run.call_args[0][0]
    assert argv[:3] == ["responder", "-I", "lo"] and "-A" in argv
    assert out["mode"] == "analyze"


def test_poison_lab_router(tmp_path: Any, monkeypatch: Any) -> None:
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
    r = c.post("/api/poisonlab/listen", json={"interface": "lo"})
    assert r.status_code == 200
    body = r.json()
    assert body["hash_count"] == 1 and body["mode"] == "analyze"
    # refusal path without sandbox
    monkeypatch.setenv("H4K_SANDBOX", "0")
    r = c.post(
        "/api/poisonlab/listen",
        json={"interface": "eth0", "poison": True, "confirm_lab": True},
    )
    assert r.status_code == 200
    assert r.json()["refused"] is True
