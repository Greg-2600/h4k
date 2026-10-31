"""Flag tracking for CTF contests.

A **flag** is the proof of compromise: the string the challenge (or the real
system) hands over when you win. h4k's job is to help you *find* them — by
scanning session-recon output, by grepping files on a captured shell, by
fuzzing a service — and to keep a ledger so you always know what is solved
and what is left.

Flags are stored per-engagement in the same SQLite database as the rest of
the asset graph. The regex list is deliberately broad: CTF flag shapes vary
wildly between platforms (``CTF{...}``, ``FLAG{...}``, ``flag{...}``,
base64 blobs, hex strings, ...), so we surface candidates and let the
operator confirm.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.flags")

# Flag-shaped strings we auto-detect in session-recon output, file dumps and
# fuzzing artifacts. Each entry is (name, regex). The regexes are ordered
# from most specific to least specific so a more specific match wins the
# dedup pass.
_FLAG_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("CTF{...}", re.compile(r"CTF\{[^}\r\n]{3,200}\}")),
    ("FLAG{...}", re.compile(r"FLAG\{[^}\r\n]{3,200}\}")),
    ("flag{...}", re.compile(r"flag\{[^}\r\n]{3,200}\}")),
    ("HTB{...}", re.compile(r"HTB\{[^}\r\n]{3,200}\}")),
    ("THM{...}", re.compile(r"THM\{[^}\r\n]{3,200}\}")),
    ("picoCTF{...}", re.compile(r"picoCTF\{[^}\r\n]{3,200}\}")),
    ("DawgCTF{...}", re.compile(r"DawgCTF\{[^}\r\n]{3,200}\}")),
    ("hex-32", re.compile(r"\b[0-9a-fA-F]{32}\b")),
    ("hex-64", re.compile(r"\b[0-9a-fA-F]{64}\b")),
    ("base64-40+", re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")),
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS flags (
    id          TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    value       TEXT NOT NULL,
    host        TEXT,
    path        TEXT,
    method      TEXT,
    note        TEXT NOT NULL DEFAULT '',
    auto        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    UNIQUE(engagement_id, value)
);
CREATE INDEX IF NOT EXISTS idx_flags_eng ON flags(engagement_id);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _db_path() -> Path:
    from paths import data_dir

    return data_dir() / "flags.db"


class FlagStore:
    """SQLite-backed flag ledger, one row per distinct flag value."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else _db_path()
        self._lock = __import__("threading").RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)
        with __import__("contextlib").suppress(OSError):
            self.path.chmod(0o600)

    def record(
        self,
        engagement_id: str,
        value: str,
        host: str | None = None,
        path: str | None = None,
        method: str | None = None,
        note: str = "",
        auto: bool = False,
    ) -> dict[str, Any]:
        value = (value or "").strip()
        if not value:
            raise ValueError("flag value required")
        fid = uuid.uuid4().hex[:12]
        ts = _now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO flags "
                "(id, engagement_id, value, host, path, method, note, auto, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (fid, engagement_id, value, host, path, method, note, int(auto), ts),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM flags WHERE engagement_id=? AND value=?",
                (engagement_id, value),
            ).fetchone()
        return (
            dict(row)
            if row
            else {
                "id": fid,
                "engagement_id": engagement_id,
                "value": value,
                "host": host,
                "path": path,
                "method": method,
                "note": note,
                "auto": int(auto),
                "created_at": ts,
            }
        )

    def list_flags(self, engagement_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if engagement_id:
                rows = conn.execute(
                    "SELECT * FROM flags WHERE engagement_id=? ORDER BY created_at DESC",
                    (engagement_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM flags ORDER BY created_at DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    def delete(self, flag_id: str) -> bool:
        with self._lock, self._connect() as conn:
            before = conn.execute(
                "SELECT COUNT(*) FROM flags WHERE id=?", (flag_id,)
            ).fetchone()[0]
            conn.execute("DELETE FROM flags WHERE id=?", (flag_id,))
            conn.commit()
        return bool(before)

    def count(self, engagement_id: str | None = None) -> int:
        with self._lock, self._connect() as conn:
            if engagement_id:
                return int(
                    conn.execute(
                        "SELECT COUNT(*) FROM flags WHERE engagement_id=?",
                        (engagement_id,),
                    ).fetchone()[0]
                )
            return int(conn.execute("SELECT COUNT(*) FROM flags").fetchone()[0])

    # ---- detection ---------------------------------------------------------

    @staticmethod
    def detect(text: str) -> list[str]:
        """Return the distinct flag-shaped strings found in `text`.

        More specific patterns (CTF{...}, FLAG{...}, ...) win over the generic
        hex/base64 ones: a candidate that is already covered by a more specific
        match is dropped.
        """
        if not text:
            return []
        found: list[str] = []
        seen: set[str] = set()
        for _name, pattern in _FLAG_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                if value in seen:
                    continue
                # skip a generic hit that is a substring of a more specific one
                if any(value in other for other in seen):
                    continue
                seen.add(value)
                found.append(value)
        return found
