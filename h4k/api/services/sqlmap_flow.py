"""SQLmap tamper flow — dump → ledger (Backlog #29, explicit only).

A tamper-aware scan (`--tamper`) plus a dump whose tables are parsed
into rows, not left as a wall of text. Flag-shaped values become flag
leads; user/password-looking column pairs become *unverified*
credentials (the propagation engine only replays verified ones, so a
dump can never widen access by itself). Every step is explicit:
nothing scans, dumps or records without the operator pressing its
button.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.sqlmap_flow")

# Curated tamper scripts (sqlmap's own names). Offered as a checklist,
# never applied implicitly.
TAMPERS = [
    "space2comment",
    "between",
    "randomcase",
    "charencode",
    "equaltolike",
    "space2plus",
    "unmagicquotes",
    "apostrophemask",
    "appendnullbyte",
    "base64encode",
]

_FLAG_RE = re.compile(r"(?:CTF|FLAG|flag)\{[^}\s]{1,200}\}")


def parse_dump_tables(stdout: str) -> list[dict[str, Any]]:
    """Parse `sqlmap --dump` table blocks into {database, table, rows}.

    sqlmap prints `Database: X` then `Table: Y [N entries]` headers
    followed by `+---+` bordered rows with a header row of column names.
    """
    tables: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    pending_db = ""
    columns: list[str] = []
    for line in (stdout or "").splitlines():
        m = re.match(r"Database:\s*(\S+)\s+Table:\s*(\S+)", line)
        if m:
            pending_db = m.group(1)
            current = {
                "database": m.group(1),
                "table": m.group(2).strip("[]"),
                "columns": [],
                "rows": [],
            }
            tables.append(current)
            columns = []
            continue
        m = re.match(r"Database:\s*(\S+)\s*$", line)
        if m:
            pending_db = m.group(1)
            continue
        m = re.match(r"Table:\s*(\S+)", line)
        if m:
            current = {
                "database": pending_db,
                "table": m.group(1).strip("[]"),
                "columns": [],
                "rows": [],
            }
            tables.append(current)
            columns = []
            continue
        if current is None:
            continue
        stripped = line.strip()
        if not stripped or stripped[0] not in "+|":
            continue
        if stripped[0] == "+":
            continue  # border row
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not columns:
            columns = cells
            current["columns"] = list(columns)
        elif len(cells) == len(columns):
            current["rows"].append(dict(zip(columns, cells, strict=True)))
    return [t for t in tables if t.get("rows")]


def extract_flags(tables: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Flag-shaped values hiding in dumped rows."""
    found: list[dict[str, str]] = []
    for table in tables:
        for row in table.get("rows", []):
            for key, val in row.items():
                for m in _FLAG_RE.findall(str(val)):
                    found.append(
                        {
                            "value": m,
                            "column": str(key),
                            "table": str(table.get("table", "")),
                        }
                    )
    return found


def extract_creds(tables: list[dict[str, Any]]) -> list[dict[str, str]]:
    """User/password-looking column pairs (returned UNVERIFIED)."""
    found: list[dict[str, str]] = []
    for table in tables:
        cols = {str(c).lower(): str(c) for c in table.get("columns", [])}
        user_col = next(
            (
                cols[k]
                for k in cols
                if k in ("user", "username", "login", "name", "email")
            ),
            None,
        )
        pass_col = next(
            (
                cols[k]
                for k in cols
                if k in ("password", "passwd", "pass", "pwd", "secret")
            ),
            None,
        )
        if not user_col or not pass_col:
            continue
        for row in table.get("rows", []):
            user, password = str(row.get(user_col, "") or ""), str(
                row.get(pass_col, "") or ""
            )
            if (
                user
                and password
                and (user, password) not in [(f["user"], f["password"]) for f in found]
            ):
                found.append(
                    {
                        "user": user,
                        "password": password,
                        "table": str(table.get("table", "")),
                    }
                )
    return found


def ledger(
    store: Any, engagement_id: str, host: str, tables: list[dict[str, Any]]
) -> dict[str, Any]:
    """Record dump loot: flags as flags, creds as UNVERIFIED credentials."""
    if not store.get_engagement(engagement_id):
        raise ValueError("unknown engagement")
    from services.flags import FlagStore

    flags = extract_flags(tables)
    creds = extract_creds(tables)
    before = len(FlagStore().list_flags(engagement_id))
    for flag in flags:
        try:
            FlagStore().record(
                engagement_id,
                flag["value"],
                host=host,
                note=f"sqlmap dump:{flag['table']}.{flag['column']}",
            )
        except Exception as exc:
            logger.debug("flag ledger failed: %s", exc)
    recorded_flags = len(FlagStore().list_flags(engagement_id)) - before
    recorded_creds = 0
    for cred in creds:
        try:
            recorded_creds += store.record_credential(
                engagement_id,
                cred["user"],
                cred["password"],
                "dumped",
                origin_host=host,
                verified=False,
            )
        except Exception as exc:
            logger.debug("cred ledger failed: %s", exc)
            break
    return {
        "tables": len(tables),
        "flags": recorded_flags,
        "credentials": recorded_creds,
        "flag_values": [f["value"] for f in flags],
    }


def sandbox_dump() -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    stdout = (
        "Database: labdb\nTable: users [2 entries]\n"
        "+----+-------+----------+\n| id | user  | password |\n+----+-------+----------+\n"
        "| 1  | admin | s3cret!  |\n| 2  | bob   | hunter2  |\n+----+-------+----------+\n"
        "Database: labdb\nTable: flags [1 entry]\n"
        "+----+------------+\n| id | value      |\n+----+------------+\n| 1  | CTF{sq1m4p} |\n+----+------------+\n"
    )
    tables = parse_dump_tables(stdout)
    return {
        "stdout": stdout,
        "stderr": "",
        "rc": 0,
        "success": True,
        "timed_out": False,
        "tables": tables,
        "sandbox": True,
    }


def run_tamper_scan(url: str, tampers: list[str], **kwargs: Any) -> dict[str, Any]:
    """Explicit tamper-aware sqlmap scan (validates tamper names)."""
    from services.sqlmap import SQLMapService

    unknown = [t for t in tampers if t not in TAMPERS]
    if unknown:
        raise ValueError(f"unknown tamper script(s): {', '.join(unknown)}")
    argv = ["sqlmap", "-u", url, "--tamper", ",".join(tampers), "--batch"]
    svc = SQLMapService()
    return svc._run(argv, timeout=int(kwargs.get("timeout", 300)) + 60)
