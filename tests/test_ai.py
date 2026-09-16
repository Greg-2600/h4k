# Tests for AI provider config + graceful degradation (no live model needed).
import services.ai as ai


def test_default_provider_is_ollama(monkeypatch):
    monkeypatch.delenv("H4K_AI_PROVIDER", raising=False)
    assert ai._provider() == "ollama"


def test_default_model_is_qwen2_5(monkeypatch):
    monkeypatch.delenv("H4K_AI_MODEL", raising=False)
    assert ai._model() == "qwen2.5:latest"


def test_custom_base_url(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://10.0.0.5:11435")
    assert ai._olla_base() == "http://10.0.0.5:11435"
    assert ai._chat_endpoint() == "http://10.0.0.5:11435/api/chat"


def test_ai_gracefully_fails_when_unreachable(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:1")  # nothing listens
    monkeypatch.setenv("H4K_AI_PROVIDER", "ollama")
    res = ai.ai_analyze("test")
    assert res["ok"] is False
    assert "not reachable" in (res.get("error") or "")


def test_openai_requires_key(monkeypatch):
    monkeypatch.delenv("H4K_AI_KEY", raising=False)
    monkeypatch.setenv("H4K_AI_PROVIDER", "openai")
    res = ai.ai_analyze("test")
    assert res["ok"] is False
    assert "H4K_AI_KEY" in (res.get("error") or "")
