# AI-assisted root-cause analysis + patch-candidate generation.
#
# Wires an LLM (OpenAI-compatible / local Ollama) to take a SAST finding or a
# fuzzer crash and produce a concise root-cause hypothesis and a proposed
# patch. This is the "frontier" piece: model-assisted diagnosis. It NEVER
# auto-weaponizes — it proposes a FIX for code the operator owns.
#
# Falls back cleanly (no crash) if no provider/key is configured, so the rest
# of the tool works offline regardless.
import json
import logging
import os
import urllib.request
from typing import Any

logger = logging.getLogger("h4k.ai")


SYS_PROMPT = (
    "You are a senior security engineer helping analyze a vulnerability for a "
    "school lab. Given a static-analysis finding or fuzzer crash, produce:\n"
    "1) ROOT_CAUSE: a 2-3 sentence hypothesis of the why.\n"
    "2) PATCH_CANDIDATE: short, concrete, safe code showing the direction of "
    "the fix (for the operator's own code only).\n"
    "3) CONFIRM_STEPS: how to validate it on a system they own.\n"
    "Keep it concise and label each section. This is for authorized, responsible "
    "disclosure on code the operator owns — never a weapon.\n"
)


def _provider() -> str:
    return (os.environ.get("H4K_AI_PROVIDER") or "openai").lower()


def _endpoint() -> str:
    if _provider() == "ollama":
        return os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
    return os.environ.get("H4K_AI_URL", "https://api.openai.com/v1/chat/completions")


def _model() -> str:
    return os.environ.get(
        "H4K_AI_MODEL", "gemma2:2b" if _provider() == "ollama" else "gpt-4o-mini"
    )


def ai_analyze(input_text: str) -> dict[str, Any]:
    """Call the configured LLM; return {ok, raw, provider, error}."""
    provider = _provider()
    if not os.environ.get("H4K_AI_KEY") and provider in (
        "openai",
        "anthropic",
        "openai_compatible",
    ):
        return {
            "ok": False,
            "error": "no H4K_AI_KEY set",
            "provider": provider,
            "raw": "",
        }
    # Ollama doesn't need a key
    if provider == "ollama" and not _probe_ollama():
        return {
            "ok": False,
            "error": "ollama not reachable",
            "provider": provider,
            "raw": "",
        }

    payload = {
        "model": _model(),
        "messages": [
            {"role": "system", "content": SYS_PROMPT},
            {"role": "user", "content": input_text},
        ],
        "temperature": 0.2,
    }

    if provider == "ollama":
        url = _endpoint()
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(
                req, timeout=60
            ) as resp:  # nosec B310 - fixed URL
                data = json.loads(resp.read().decode())
            content = data.get("message", {}).get("content", "")
            return {"ok": True, "raw": content, "provider": provider, "error": None}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "provider": provider, "raw": ""}

    # OpenAI-compatible
    url = _endpoint()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.environ.get('H4K_AI_KEY')}",
    }
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=90) as resp:  # nosec B310 - fixed URL
            data = json.loads(resp.read().decode())
        content = data["choices"][0]["message"]["content"]
        return {"ok": True, "raw": content, "provider": provider, "error": None}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "provider": provider, "raw": ""}


def _probe_ollama() -> bool:
    url = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
            resp.read()
        return True
    except Exception:
        return False
