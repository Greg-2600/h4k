"""Shared corpus — one corpus dir across fuzz runs (Backlog #51).

A persistent, content-addressed seed store under `<data_dir>/corpus`
(survives restarts; `H4K_DATA_DIR`-aware so tests stay hermetic). Each
entry is a raw input file named by its SHA-256 plus a JSON sidecar
(name, source run, tags, timestamps). Adds dedup by hash, per-entry
(1 MiB) and store-wide (500 entries, oldest evicted) caps, and
`..`/separator rejection on lookup keys so a crafted SHA cannot walk
the filesystem.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from paths import data_dir

logger = logging.getLogger("h4k.corpus")

MAX_ENTRY_BYTES = 1_000_000
MAX_ENTRIES = 500


def corpus_dir() -> Path:
    """The shared corpus directory (created on first use)."""
    path = data_dir() / "corpus"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.debug("corpus dir unwritable: %s", exc)
    return path


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _meta_path(sha: str) -> Path:
    return corpus_dir() / f"{sha}.json"


def _check_sha(sha: str) -> str:
    clean = (sha or "").strip().lower()
    if len(clean) != 64 or any(c not in "0123456789abcdef" for c in clean):
        raise ValueError("sha must be a 64-char hex digest")
    return clean


def add_entry(
    data: bytes,
    name: str = "",
    source: str = "",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Store one input; identical bytes dedup to the existing entry."""
    if not data:
        raise ValueError("data required (empty inputs prove nothing)")
    if len(data) > MAX_ENTRY_BYTES:
        raise ValueError(f"entry exceeds {MAX_ENTRY_BYTES} bytes")
    sha = _sha(data)
    blob = corpus_dir() / sha
    meta_path = _meta_path(sha)
    if blob.exists():
        entry = read_entry(sha) or {"sha": sha}
        merged = sorted(set(entry.get("tags", []) or []) | set(tags or []))
        entry["tags"] = merged
        if name and not entry.get("name"):
            entry["name"] = name[:128]
        _write_meta(meta_path, entry)
        entry["deduped"] = True
        return entry
    blob.write_bytes(data)
    entry = {
        "sha": sha,
        "name": (name or f"seed-{sha[:8]}")[:128],
        "size": len(data),
        "source": (source or "")[:128],
        "tags": sorted(set(tags or []))[:16],
        "created": time.time(),
        "deduped": False,
    }
    _write_meta(meta_path, entry)
    _evict_oldest()
    return entry


def _write_meta(path: Path, entry: dict[str, Any]) -> None:
    try:
        path.write_text(json.dumps(entry, indent=1), encoding="utf-8")
    except OSError as exc:
        logger.debug("corpus meta unwritable: %s", exc)


def read_entry(sha: str) -> dict[str, Any] | None:
    """Sidecar metadata, or None when the entry is absent/broken."""
    clean = _check_sha(sha)
    try:
        return json.loads(_meta_path(clean).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def read_bytes(sha: str) -> bytes | None:
    """Raw input bytes, or None when absent."""
    clean = _check_sha(sha)
    try:
        return (corpus_dir() / clean).read_bytes()
    except OSError:
        return None


def list_entries() -> dict[str, Any]:
    """All entries, newest first, with store totals."""
    out: list[dict[str, Any]] = []
    try:
        metas = sorted(corpus_dir().glob("*.json"), key=lambda p: p.stat().st_mtime)
    except OSError:
        metas = []
    for meta in metas:
        try:
            out.append(json.loads(meta.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    out.sort(key=lambda e: e.get("created", 0), reverse=True)
    return {
        "entries": out,
        "count": len(out),
        "bytes": sum(int(e.get("size", 0)) for e in out),
    }


def delete_entry(sha: str) -> bool:
    """Remove an entry and its sidecar; False when absent."""
    clean = _check_sha(sha)
    gone = False
    for path in (corpus_dir() / clean, _meta_path(clean)):
        try:
            path.unlink()
            gone = True
        except OSError:
            continue
    return gone


def _evict_oldest() -> None:
    entries = list_entries()["entries"]
    for entry in entries[MAX_ENTRIES:]:
        try:
            delete_entry(entry["sha"])
        except ValueError:
            continue


def import_bytes_batch(items: list[dict[str, Any]], source: str = "") -> dict[str, Any]:
    """Import many entries at once; per-item errors are reported, not fatal."""
    import base64 as _b64

    added = 0
    deduped = 0
    errors: list[str] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"item[{idx}]: not an object")
            continue
        raw = item.get("data_b64", item.get("data", ""))
        try:
            if isinstance(raw, bytes):
                data = raw
            elif isinstance(raw, str) and item.get("data_b64"):
                data = _b64.b64decode(raw, validate=True)
            else:
                data = str(raw).encode("utf-8")
            out = add_entry(
                data,
                name=str(item.get("name") or ""),
                source=str(item.get("source") or source),
                tags=item.get("tags") if isinstance(item.get("tags"), list) else [],
            )
            if out.get("deduped"):
                deduped += 1
            else:
                added += 1
        except (ValueError, TypeError) as exc:
            errors.append(f"item[{idx}]: {exc}"[:160])
    return {"added": added, "deduped": deduped, "errors": errors}
