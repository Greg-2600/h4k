"""Authenticated fuzz profiles — cookie/header presets (Backlog #58).

Named auth presets stored as one JSON document under
`<data_dir>/fuzz_profiles.json` (operator-owned lab secrets, same
trust as the engagement credential store — values never leave the
server: list/count endpoints expose key *names* only). Fuzz runs name
a profile instead of pasting secrets into every request; per-call
headers/cookies still win over preset entries.

`resolve_auth` merges in precedence order so callers share one rule:
explicit call values override preset values, preset fills the gaps.
Unknown profile names are a hard error (fail closed — never fuzz
unauthenticated by accident because of a typo).
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from paths import data_dir

logger = logging.getLogger("h4k.fuzz_profiles")

FILE = "fuzz_profiles.json"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_MASK = "…"


def _path() -> Path:
    return data_dir() / FILE


def _load() -> dict[str, Any]:
    try:
        doc = json.loads(_path().read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(store: dict[str, Any]) -> None:
    try:
        _path().write_text(json.dumps(store, indent=1), encoding="utf-8")
    except OSError as exc:
        logger.debug("profiles unwritable: %s", exc)


def _check_name(name: str) -> str:
    clean = (name or "").strip()
    if not _NAME_RE.match(clean):
        raise ValueError("profile name must be 1-64 chars: letters, digits, _ or -")
    return clean


def _clean_map(mapping: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(mapping, dict):
        for key, value in mapping.items():
            name = str(key or "").strip()
            if name:
                out[name] = str(value)
    return out


def save_profile(
    name: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create or replace a preset; values stay server-side."""
    clean = _check_name(name)
    heads = _clean_map(headers)
    cooks = _clean_map(cookies)
    if not heads and not cooks:
        raise ValueError("profile needs at least one header or cookie")
    store = _load()
    store[clean] = {
        "name": clean,
        "headers": heads,
        "cookies": cooks,
        "updated": time.time(),
    }
    _save(store)
    return masked(store[clean])


def masked(entry: dict[str, Any]) -> dict[str, Any]:
    """Public view: key names and lengths, never the secrets."""
    return {
        "name": entry.get("name", ""),
        "headers": sorted((entry.get("headers") or {}).keys()),
        "cookies": sorted((entry.get("cookies") or {}).keys()),
        "header_count": len(entry.get("headers") or {}),
        "cookie_count": len(entry.get("cookies") or {}),
        "updated": entry.get("updated", 0.0),
    }


def list_profiles() -> dict[str, Any]:
    """Masked list, newest first."""
    entries = [masked(e) for e in _load().values() if isinstance(e, dict)]
    entries.sort(key=lambda e: e.get("updated", 0.0), reverse=True)
    return {"profiles": entries, "count": len(entries)}


def delete_profile(name: str) -> bool:
    """Remove a preset; False when absent."""
    clean = _check_name(name)
    store = _load()
    if clean not in store:
        return False
    del store[clean]
    _save(store)
    return True


def resolve_auth(
    profile: str | None,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, dict[str, str]]:
    """Merge preset under explicit values (explicit wins, preset fills)."""
    merged_headers = _clean_map(headers)
    merged_cookies = _clean_map(cookies)
    name = (profile or "").strip()
    if name:
        store = _load()
        entry = store.get(name)
        if not isinstance(entry, dict):
            raise ValueError(f"unknown auth profile: {name}")
        preset_headers = _clean_map(entry.get("headers"))
        preset_cookies = _clean_map(entry.get("cookies"))
        merged_headers = {**preset_headers, **merged_headers}
        merged_cookies = {**preset_cookies, **merged_cookies}
    return {"headers": merged_headers, "cookies": merged_cookies}


def sandbox_seed() -> dict[str, Any]:
    """Deterministic demo preset used by docs/tests (never a real secret)."""
    return {
        "name": "demo",
        "headers": {"X-Demo": "1"},
        "cookies": {"session": "demo"},
        "updated": 0.0,
    }
