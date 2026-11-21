# Target-noise governor + AI budget: profiles, per-host tokens, backoff,
# guidance, budget enforcement and API/UI contracts. Offline.
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services import ai, ai_budget, noise, wire


class TcpServer:
    def __init__(self):
        import socket
        import threading

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(1024)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass

    def close(self):
        self._stop = True
        with suppress(OSError):
            self.sock.close()


@pytest.fixture(autouse=True)
def _reset_limits(monkeypatch):
    monkeypatch.delenv("H4K_NOISE_PROFILE", raising=False)
    monkeypatch.delenv("H4K_AI_BUDGET_TOKENS", raising=False)
    monkeypatch.delenv("H4K_AI_BUDGET_CALLS", raising=False)
    noise.reset_for_tests()
    ai_budget.reset_for_tests()
    yield
    noise.reset_for_tests()
    ai_budget.reset_for_tests()


def test_profiles_and_guidance():
    assert noise.profile_name() == "off"
    assert noise.status()["rps"] == 0
    status = noise.set_profile("quiet")
    assert status["profile"] == "quiet"
    assert status["rps"] == 2.0
    guide = noise.guidance("nmap")
    assert "-T2" in guide["flags"]
    assert "--max-rate 2" in guide["flags"]
    assert noise.guidance("nuclei")["flags"].startswith("-rate-limit 2")
    assert noise.guidance("unknown")["flags"] == ""
    with pytest.raises(ValueError):
        noise.set_profile("turbo")
    noise.set_profile("off")
    assert noise.guidance("nmap")["profile"] == "off"


def test_acquire_release_and_backoff():
    noise.set_profile("balanced")  # burst 10, max 2 in flight
    first = noise.acquire("10.0.0.5")
    second = noise.acquire("10.0.0.5")
    assert first is not None and second is not None
    assert noise.status()["hosts"][0]["in_flight"] == 2
    with pytest.raises(TimeoutError):
        noise.acquire("10.0.0.5", timeout=0.05)
    noise.release(first)
    noise.release(second)
    assert noise.status()["hosts"][0]["in_flight"] == 0

    permit = noise.acquire("10.0.0.5")
    noise.release(permit, status_code=429)
    host = noise.status()["hosts"][0]
    assert host["blocked"] == 1
    assert host["blocked_for_s"] > 0
    with pytest.raises(TimeoutError):
        noise.acquire("10.0.0.5", timeout=0.05)


def test_wire_is_paced_when_enabled():
    server = TcpServer()
    try:
        assert wire.tcp_exchange("127.0.0.1", server.port, b"GET / HTTP/1.1\r\n\r\n")[
            "ok"
        ]
        assert noise.acquire("127.0.0.1") is None  # off profile returns None
        noise.set_profile("balanced")
        result = wire.tcp_exchange(
            "127.0.0.1", server.port, b"GET / HTTP/1.1\r\n\r\n", timeout=2
        )
        assert result["ok"] is True
        host = noise.status()["hosts"][0]
        assert host["host"] == "127.0.0.1"
        assert host["requests"] >= 1
        assert host["in_flight"] == 0
    finally:
        server.close()


# ---------------------------------------------------------------------------
# AI budget
# ---------------------------------------------------------------------------
def test_budget_check_record_status_and_reset(monkeypatch):
    monkeypatch.setenv("H4K_AI_BUDGET_TOKENS", "20")
    monkeypatch.setenv("H4K_AI_BUDGET_CALLS", "2")
    allowed = ai_budget.check("eng", "x" * 40)
    assert allowed["allowed"] is True
    assert allowed["estimated_input_tokens"] == 10
    ai_budget.record("eng", input_text="x" * 40, output_text="y" * 40)
    assert ai_budget.status("eng")["scopes"]["eng"]["calls"] == 1
    assert ai_budget.status("eng")["scopes"]["eng"]["tokens"] == 20
    denied = ai_budget.check("eng", "z")
    assert denied["allowed"] is False
    assert "token budget" in denied["reason"]

    monkeypatch.setenv("H4K_AI_BUDGET_TOKENS", "0")
    monkeypatch.setenv("H4K_AI_BUDGET_CALLS", "1")
    ai_budget.reset("eng")
    assert ai_budget.check("eng", "x")["allowed"] is True
    ai_budget.record("eng", input_text="x")
    assert ai_budget.check("eng", "x")["allowed"] is False
    assert "call budget" in ai_budget.check("eng", "x")["reason"]
    ai_budget.reset()
    assert ai_budget.status()["scopes"] == {}


class _Resp:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return b'{"message":{"content":"answer"}}'


def test_ai_analyze_respects_budget(monkeypatch):
    monkeypatch.setenv("H4K_AI_BUDGET_TOKENS", "2")
    monkeypatch.setattr(ai, "_probe_ollama", lambda: True)
    monkeypatch.setattr(ai, "_ensure_ollama_model", lambda model: True)
    monkeypatch.setattr(ai.urllib.request, "urlopen", lambda *a, **k: _Resp())
    blocked = ai.ai_analyze("a long prompt that is over the budget", scope="eng")
    assert blocked["ok"] is False
    assert "budget" in blocked["error"]
    assert ai_budget.status("eng")["scopes"].get("eng", {}).get("calls", 0) == 0

    monkeypatch.setenv("H4K_AI_BUDGET_TOKENS", "0")
    ok = ai.ai_analyze("short", scope="eng")
    assert ok["ok"] is True
    assert ai_budget.status("eng")["scopes"]["eng"]["calls"] == 1


def test_full_loop_passes_scope(monkeypatch):
    captured = {}

    def _fake(text, model_override=None, **kwargs):
        captured.update(text=text, model=model_override, **kwargs)
        return {"ok": True, "raw": "ROOT_CAUSE: x", "provider": "openai", "error": None}

    import services.ai_loop as ai_loop

    monkeypatch.setattr(ai_loop, "ai_analyze", _fake)
    ai_loop.ai_full_loop("evidence", model_override="m", scope="eng-1")
    assert captured["scope"] == "eng-1"


# ---------------------------------------------------------------------------
# API / UI
# ---------------------------------------------------------------------------
@pytest.fixture()
def client(monkeypatch):
    import app_state

    class _CveStub:
        cves: tuple = ()
        path = "stub.json"

        def refresh(self) -> bool:
            return False

    app_state.msf_client = None
    app_state.cve_db = _CveStub()  # type: ignore[assignment]

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    main_module.reset_auth_cache()
    yield TestClient(main_module.app)
    main_module.reset_auth_cache()


def test_api_noise_and_budget(client):
    status = client.get("/api/noise/status").json()
    assert status["profile"] == "off"
    assert (
        client.post("/api/noise/profile", json={"profile": "quiet"}).status_code == 200
    )
    assert client.get("/api/noise/status").json()["profile"] == "quiet"
    guide = client.get("/api/noise/guidance?tool=nmap").json()
    assert "-T2" in guide["flags"]
    assert (
        client.post("/api/noise/profile", json={"profile": "turbo"}).status_code == 400
    )
    assert client.post("/api/noise/reset").json()["profile"] == "off"

    budget = client.get("/api/source/ai/budget").json()
    assert "max_tokens" in budget
    ai_budget.record("api", input_text="hello")
    assert client.get("/api/source/ai/budget?scope=api").json()["scopes"]
    assert (
        client.post("/api/source/ai/budget/reset", json={"scope": "api"}).status_code
        == 200
    )
    assert client.get("/api/source/ai/budget?scope=api").json()["scopes"] == {}


def test_ui_contract_ids_exist():
    web = Path(__file__).resolve().parents[1] / "h4k" / "web"
    html = (web / "ops.html").read_text(encoding="utf-8")
    js = (web / "ops.js").read_text(encoding="utf-8")
    for ident in (
        "limits-card",
        "noise-chip",
        "noise-profile",
        "noise-tool",
        "noise-guidance",
        "noise-stats",
        "ai-budget-chip",
        "ai-budget-stats",
        "btn-noise-set",
        "btn-ai-budget-reset",
        "btn-limits-refresh",
    ):
        assert f'id="{ident}"' in html, f"missing #{ident}"
    for ident in (
        "noise-chip",
        "noise-profile",
        "noise-guidance",
        "noise-stats",
        "ai-budget-chip",
        "ai-budget-stats",
        "btn-noise-set",
        "btn-ai-budget-reset",
    ):
        assert ident in js
