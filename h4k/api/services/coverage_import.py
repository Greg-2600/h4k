"""Coverage HTML import — llvm-cov badge in UI (Backlog #60).

Offline import of a pasted LLVM coverage export so fuzzing progress
can wear a number. Two inputs, one badge:

- llvm-cov JSON (`llvm-cov export --format=text`): parsed exactly —
  per-file line/region/function/branch summaries plus run totals.
- llvm-cov HTML report: parsed best-effort with a stdlib HTMLParser
  that reads the totals row and per-file rows (`heuristic: true` is
  stamped on the result because table layouts drift between LLVM
  versions — JSON stays the source of truth).

The latest import persists under `<data_dir>/coverage.json`
(`H4K_DATA_DIR`-aware, so tests stay hermetic) and `GET` serves it
back alongside a badge (`lines_pct`, `regions_pct`, grade). Sandbox
returns a canned import.
"""

from __future__ import annotations

import json
import logging
import re
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from paths import data_dir

logger = logging.getLogger("h4k.coverage_import")

FILE = "coverage.json"


def _pct(covered: Any, count: Any) -> float:
    try:
        if not count:
            return 100.0
        return round(100.0 * float(covered) / float(count), 1)
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0


def _summarize(summary: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("lines", "regions", "functions", "branches"):
        node = summary.get(key) or {}
        covered = node.get("covered", 0)
        count = node.get("count", 0)
        out[key] = {"covered": covered, "count": count, "pct": _pct(covered, count)}
    return out


def parse_llvm_json(doc: dict[str, Any]) -> dict[str, Any]:
    """Exact parse of `llvm-cov export --format=text` output."""
    if not isinstance(doc, dict):
        raise ValueError("coverage JSON must be an object")
    data = doc.get("data")
    if not isinstance(data, list) or not data:
        raise ValueError("not an llvm-cov export (missing data[])")
    files: list[dict[str, Any]] = []
    for block in data:
        if not isinstance(block, dict):
            continue
        for entry in block.get("files") or []:
            if not isinstance(entry, dict):
                continue
            files.append(
                {
                    "filename": str(entry.get("filename") or "?")[:256],
                    "summary": _summarize(entry.get("summary") or {}),
                }
            )
    totals_node: dict[str, Any] = {}
    for block in data:
        if isinstance(block, dict) and isinstance(block.get("totals"), dict):
            totals_node = block["totals"]
            break
    totals = _summarize(totals_node)
    return {
        "format": "llvm-json",
        "files": files[:256],
        "file_count": len(files),
        "totals": totals,
        "heuristic": False,
    }


class _TotalsParser(HTMLParser):
    """Best-effort reader for llvm-cov index.html tables."""

    def __init__(self) -> None:
        super().__init__()
        self._row: list[str] = []
        self._cell: list[str] = []
        self._in_cell = False
        self.rows: list[list[str]] = []

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in ("td", "th"):
            self._in_cell = True
            self._cell = []

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th"):
            self._row.append("".join(self._cell).strip())
            self._in_cell = False
        elif tag == "tr":
            if any(c for c in self._row):
                self.rows.append(self._row)
            self._row = []


_NUM_RE = re.compile(r"^[\d,./\s%()\-+]+$")


def parse_llvm_html(text: str) -> dict[str, Any]:
    """Heuristic parse of an llvm-cov HTML index (layouts drift)."""
    parser = _TotalsParser()
    try:
        parser.feed(text or "")
    except Exception as exc:
        raise ValueError(f"unparseable HTML: {exc}") from exc
    numbers: list[tuple[str, list[str]]] = []
    for row in parser.rows:
        label = (row[0] or "").strip()
        cells = [c.strip() for c in row[1:] if c.strip()]
        if label and cells and all(_NUM_RE.match(c) for c in cells):
            numbers.append((label, cells))
    if not numbers:
        raise ValueError("no llvm-cov totals/file rows found in HTML")
    totals_cells: list[str] = []
    file_rows: list[tuple[str, list[str]]] = []
    for label, cells in numbers:
        if label.lower() == "totals":
            totals_cells = cells
        else:
            file_rows.append((label, cells))
    pcts = [
        float(m.group(1))
        for c in totals_cells
        for m in [re.search(r"([\d.]+)\s*%", c)]
        if m
    ]
    lines_pct = pcts[0] if pcts else 0.0
    regions_pct = pcts[1] if len(pcts) > 1 else 0.0
    files = [
        {"filename": label[:256], "cells": cells[:12]}
        for label, cells in file_rows[:256]
    ]
    return {
        "format": "llvm-html",
        "files": files,
        "file_count": len(files),
        "totals": {
            "lines": {"pct": lines_pct},
            "regions": {"pct": regions_pct},
        },
        "heuristic": True,
    }


def parse_export(text: str, fmt: str = "auto") -> dict[str, Any]:
    """Parse pasted JSON (or YAML-free JSON-with-comments-tolerated) or HTML."""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("coverage export required (paste llvm-cov output)")
    if len(raw) > 5_000_000:
        raise ValueError("export exceeds 5 MiB")
    want = (fmt or "auto").strip().lower()
    if want not in ("auto", "json", "html"):
        raise ValueError("format must be auto, json or html")
    if want in ("auto", "json") and raw.lstrip().startswith(("{", "[")):
        try:
            return parse_llvm_json(json.loads(raw))
        except ValueError:
            if want == "json":
                raise
    if want in ("auto", "html") or raw.lstrip().startswith("<"):
        return parse_llvm_html(raw)
    raise ValueError("not llvm-cov JSON or HTML (paste the export output)")


def _path() -> Path:
    return data_dir() / FILE


def store_import(parsed: dict[str, Any], source: str) -> dict[str, Any]:
    """Persist the latest import; the badge is derived on read."""
    record = {
        "imported_at": time.time(),
        "source": source,
        "format": parsed.get("format"),
        "heuristic": bool(parsed.get("heuristic")),
        "file_count": parsed.get("file_count", 0),
        "totals": parsed.get("totals", {}),
        "files": (parsed.get("files") or [])[:50],
    }
    try:
        _path().write_text(json.dumps(record, indent=1), encoding="utf-8")
    except OSError as exc:
        logger.debug("coverage store unwritable: %s", exc)
    return with_badge(record)


def load_import() -> dict[str, Any] | None:
    """Latest stored import with badge, or None when empty/corrupt."""
    try:
        doc = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    return with_badge(doc)


def _grade(lines_pct: float) -> str:
    if lines_pct >= 90:
        return "excellent"
    if lines_pct >= 70:
        return "good"
    if lines_pct >= 40:
        return "thin"
    return "bare"


def with_badge(record: dict[str, Any]) -> dict[str, Any]:
    """Attach the badge (line/region %, grade) to a stored record."""
    totals = record.get("totals") or {}
    lines = (totals.get("lines") or {}).get("pct", 0.0)
    regions = (totals.get("regions") or {}).get("pct", 0.0)
    try:
        lines_f, regions_f = float(lines), float(regions)
    except (TypeError, ValueError):
        lines_f, regions_f = 0.0, 0.0
    return {
        **record,
        "badge": {
            "lines_pct": lines_f,
            "regions_pct": regions_f,
            "grade": _grade(lines_f),
            "label": f"{lines_f:.1f}% lines",
        },
    }


def sandbox_result() -> dict[str, Any]:
    """Canned stored import (nothing parsed)."""
    return with_badge(
        {
            "imported_at": 0.0,
            "source": "sandbox",
            "format": "llvm-json",
            "heuristic": False,
            "file_count": 2,
            "totals": {
                "lines": {"covered": 87, "count": 100, "pct": 87.0},
                "regions": {"covered": 41, "count": 50, "pct": 82.0},
                "functions": {"covered": 9, "count": 10, "pct": 90.0},
                "branches": {"covered": 30, "count": 40, "pct": 75.0},
            },
            "files": [
                {
                    "filename": "vuln.c",
                    "summary": {"lines": {"covered": 60, "count": 70, "pct": 85.7}},
                },
                {
                    "filename": "main.c",
                    "summary": {"lines": {"covered": 27, "count": 30, "pct": 90.0}},
                },
            ],
            "sandbox": True,
        }
    )
