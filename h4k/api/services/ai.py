# AI-assisted root-cause analysis + patch-candidate generation.
#
# Defaults to a LOCAL Ollama instance (fast, private, no key) so you can point
# it at a model like qwen2.5. Also supports any OpenAI-compatible endpoint if
# you prefer a cloud/remote LLM. It NEVER auto-weaponizes — it proposes a FIX
# (root-cause + patch candidate + confirm steps) for code the operator owns.
#
# Configuration (all optional):
#   H4K_AI_PROVIDER    ollama (default) | openai | openai_compatible
#   OLLAMA_BASE_URL    e.g. http://127.0.0.1:11434  (host ollama, or a sidecar/
#                      non-standard port later). Default http://127.0.0.1:11434
#   H4K_AI_MODEL       model id. Default qwen2.5:latest for ollama
#   H4K_AI_KEY         only for openai(-compatible)
#
# Falls back cleanly (no crash) if the LLM isn't reachable or no key is set.
import json
import logging
import os
import urllib.request
from typing import Any

logger = logging.getLogger("h4k.ai")

DEFAULT_OLLAMA = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5:latest"

SYS_PROMPT = (
    "You are a senior security engineer analyzing a vulnerability in a school "
    "lab. Given a static-analysis finding or a fuzzer crash, respond with this "
    "exact structure, clearly labelled:\n"
    "ROOT_CAUSE: a 2-3 sentence hypothesis of why the bug exists.\n"
    "PATCH_CANDIDATE: short, concrete, safe code (or a precise textual diff) "
    "showing the direction of the fix — for the operator's own code only.\n"
    "CONFIRM_STEPS: how to validate the diagnosis and the fix on a system they own.\n"
    "Keep it concise. This is for authorized, responsible disclosure on code the "
    "operator owns — never a weapon.\n"
)


def _provider() -> str:
    return (os.environ.get("H4K_AI_PROVIDER") or "ollama").lower()


def _olla_base() -> str:
    return (os.environ.get("OLLAMA_BASE_URL") or DEFAULT_OLLAMA).rstrip("/")


def _chat_endpoint() -> str:
    return _olla_base() + "/api/chat"


def _model() -> str:
    return os.environ.get("H4K_AI_MODEL", DEFAULT_MODEL)


def _probe_ollama() -> bool:
    """Check ollama is reachable and lists models."""
    url = _olla_base() + "/api/tags"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310 fixed URL
            data = json.loads(resp.read().decode())
        return "models" in data
    except Exception:
        return False


def ollama_models() -> list[str]:
    """Return the list of installed Ollama model names (best-effort)."""
    try:
        req = urllib.request.Request(_olla_base() + "/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310 fixed URL
            data = json.loads(resp.read().decode())
        models = data.get("models", [])
        return [str(m.get("name", "")) for m in models if m.get("name")]
    except Exception:
        return []


def _ensure_ollama_model(model: str) -> bool:
    """If the requested model isn't pulled, pull it (best-effort)."""
    try:
        req = urllib.request.Request(_olla_base() + "/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            names = {
                m.get("name", "").split(":")[0]
                for m in json.loads(resp.read().decode()).get("models", [])
            }
            tag = model  # keep full tag; check prefix match below
        if any(tag == n or tag.split(":")[0] == n.split(":")[0] for n in names):
            return True
    except Exception:
        return False
    # Model missing: pull it.
    try:
        req = urllib.request.Request(
            _olla_base() + "/api/pull",
            data=json.dumps({"model": model}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=600) as resp:  # nosec B310
            resp.read()
        return True
    except Exception as exc:
        logger.warning("could not pull ollama model %s: %s", model, exc)
        return False


def ai_analyze(input_text: str, model_override: str | None = None) -> dict[str, Any]:
    """Call the configured LLM; return {ok, raw, provider, error}.

    `model_override` (if provided) overrides the configured model for this call
    (used by the UI model picker); must be a model name Ollama can serve.
    """
    provider = _provider()
    model = model_override or _model()

    if provider == "openai" or provider == "openai_compatible":
        if not os.environ.get("H4K_AI_KEY"):
            return {
                "ok": False,
                "error": "no H4K_AI_KEY set",
                "provider": provider,
                "raw": "",
            }
        return _call_openai(input_text, model)

    # Default: Ollama.
    if not _probe_ollama():
        return {
            "ok": False,
            "error": "ollama not reachable at " + _olla_base(),
            "provider": "ollama",
            "raw": "",
        }
    _ensure_ollama_model(model)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYS_PROMPT},
            {"role": "user", "content": input_text},
        ],
        "stream": False,
        "temperature": 0.2,
    }
    try:
        req = urllib.request.Request(
            _chat_endpoint(),
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=180) as resp:  # nosec B310 fixed URL
            data = json.loads(resp.read().decode())
        content = data.get("message", {}).get("content", "")
        return {"ok": True, "raw": content, "provider": "ollama", "error": None}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "provider": "ollama", "raw": ""}


def _call_openai(input_text: str, model: str) -> dict[str, Any]:
    url = os.environ.get("H4K_AI_URL", "https://api.openai.com/v1/chat/completions")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYS_PROMPT},
            {"role": "user", "content": input_text},
        ],
        "temperature": 0.2,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.environ.get('H4K_AI_KEY')}",
    }
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=120) as resp:  # nosec B310 fixed URL
            data = json.loads(resp.read().decode())
        content = data["choices"][0]["message"]["content"]
        return {"ok": True, "raw": content, "provider": "openai", "error": None}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "provider": "openai", "raw": ""}
