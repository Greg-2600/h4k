# AI-assisted "full loop" for a vulnerability, in one call.
#
# Chain:  input (crash/SAST finding) -> AI root_cause -> AI patch_candidate
#         -> a verification plan (how to re-fuzz/confirm the fix on your build)
#
# This is a diagnostic assist for code you own, not a weapon. Re-fuzzing is
# returned as an actionable plan (the operator runs it on their own build),
# because auto-building arbitrary repos reliably is a separate concern.
import logging
from typing import Any

from services.ai import ai_analyze

logger = logging.getLogger("h4k.aifull")

FULL_LOOP_PROMPT = (
    "Given this vulnerability in software the user owns, produce a concise, "
    "clearly-labelled answer with exactly these sections:\n"
    "ROOT_CAUSE: 2-3 sentences.\n"
    "PATCH_CANDIDATE: concrete, safe code showing the fix direction.\n"
    "VERIFY: how to re-fuzz or re-run to confirm the fix (build with ASan, "
    "feed the same crash input, confirm it no longer crashes).\n"
    "Never weaponize; propose fixes only.\n\n"
    "VULNERABILITY:\n{input}\n"
)


def ai_full_loop(input_text: str) -> dict[str, Any]:
    """Run a single finding/crash through the full AI loop.

    Returns {ok, provider, raw, error, parsed:{root_cause, patch, verify}}.
    """
    analysis = ai_analyze(FULL_LOOP_PROMPT.format(input=input_text))
    if not analysis.get("ok"):
        return {
            "ok": False,
            "provider": analysis.get("provider", ""),
            "raw": "",
            "error": analysis.get("error"),
            "parsed": {},
        }
    raw = analysis.get("raw", "")
    return {
        "ok": True,
        "provider": analysis.get("provider", ""),
        "raw": raw,
        "error": None,
        "parsed": _parse_sections(raw),
    }


def _parse_sections(raw: str) -> dict[str, str]:
    """Best-effort split of the model output into ROOT_CAUSE/PATCH/VERIFY."""
    out: dict[str, str] = {}
    markers = {
        "ROOT_CAUSE": "root_cause",
        "PATCH_CANDIDATE": "patch_candidate",
        "PATCH": "patch_candidate",
        "VERIFY": "verify",
        "CONFIRM_STEPS": "verify",
    }
    import re

    # split on any marker at line start (optionally numbered/bold)
    lines = raw.splitlines()
    current = None
    for ln in lines:
        stripped = ln.strip().lstrip("0123456789.>-#").strip()
        upper = stripped.upper().rstrip(":")
        key = None
        for marker, k in markers.items():
            if upper.startswith(marker):
                key = k
                break
        if key:
            current = key
            continue
        if current:
            out[current] = (out.get(current, "") + " " + ln).strip()
    # cleanup
    for k in list(out):
        out[k] = re.sub(r"\s+", " ", out[k]).strip()
    return out
