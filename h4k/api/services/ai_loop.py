# AI-assisted "full loop" for a vulnerability, in one call.
#
# Chain:  input (crash/SAST finding) -> AI root_cause -> a minimal TRIGGER/PoC
#         that CONFIRMS the vuln on code you own -> AI patch_candidate -> a
#         verification plan (how to re-run to confirm the fix on your build).
#
# This is a diagnostic assist for code you own, not a weapon. Exploit-first:
# we build the smallest trigger that *proves* the bug (the "exploit"), then the
# fix. It is clearly scoped to authorized systems and stops short of anything
# weaponizable — the trigger demonstrates, it doesn't weaponize.
import logging
from typing import Any

from services.ai import ai_analyze

logger = logging.getLogger("h4k.aifull")

FULL_LOOP_PROMPT = (
    "Given this vulnerability in software the user owns and is authorized to "
    "test, produce a concise, clearly-labelled answer with exactly these "
    "sections:\n"
    "ROOT_CAUSE: 2-3 sentences.\n"
    "TRIGGER: a minimal, concrete PoC/trigger that CONFIRMS the vulnerability "
    "on this system (shortest input / smallest repro that demonstrates the "
    "bug). Keep it demonstrative, not weaponized — it proves the flaw exists.\n"
    "PATCH_CANDIDATE: concrete, safe code showing the fix direction.\n"
    "VERIFY: how to re-run the same TRIGGER after patching to confirm it no "
    "longer crashes/misbehaves (build with ASan, feed the same input, confirm "
    "clean).\n"
    "This is a security-research assist for an OWNED target. Never weaponize\n"
    "beyond demonstrating the flaw; propose fixes.\n\n"
    "VULNERABILITY:\n{input}\n"
)


def ai_full_loop(input_text: str, model_override: str | None = None) -> dict[str, Any]:
    """Run a single finding/crash through the full AI loop.

    Returns {ok, provider, raw, error, parsed:{trigger, root_cause, patch, verify}}.
    """
    analysis = ai_analyze(
        FULL_LOOP_PROMPT.format(input=input_text), model_override=model_override
    )
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
    """Best-effort split of the model output into TRIGGER/ROOT_CAUSE/PATCH/VERIFY."""
    out: dict[str, str] = {}
    markers = {
        "ROOT_CAUSE": "root_cause",
        "TRIGGER": "trigger",
        "EXPLOIT": "trigger",
        "POC": "trigger",
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
        raw_line = ln
        stripped = ln.strip().lstrip("0123456789.>-#*_").strip()
        upper = stripped.upper()
        key = None
        for marker, k in markers.items():
            # marker is the section header: either `MARKER: text` on one line
            # or a bare `MARKER` line with content following.
            if upper.startswith(marker):
                rest = stripped[len(marker) :]
                if rest.startswith(":"):
                    rest = rest[1:].strip()
                rest = rest.lstrip("*_ ").strip()
                if rest:
                    key = k
                    out[k] = (out.get(k, "") + " " + rest).strip()
                else:
                    key = k
                break
        if key:
            current = key
            continue
        if current:
            out[current] = (out.get(current, "") + " " + raw_line).strip()
    # cleanup
    for k in list(out):
        out[k] = re.sub(r"\s+", " ", out[k]).strip()
    return out
