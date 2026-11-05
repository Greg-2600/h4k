"""Coverage badge card through the real UI (sandbox canned)."""

from __future__ import annotations

import json
from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

EXPORT = {
    "data": [
        {
            "files": [
                {
                    "filename": "vuln.c",
                    "summary": {
                        "lines": {"covered": 60, "count": 70},
                        "regions": {"covered": 30, "count": 35},
                        "functions": {"covered": 5, "count": 5},
                        "branches": {"covered": 10, "count": 20},
                    },
                }
            ],
            "totals": {
                "lines": {"covered": 87, "count": 100},
                "regions": {"covered": 41, "count": 50},
                "functions": {"covered": 9, "count": 10},
                "branches": {"covered": 30, "count": 40},
            },
        }
    ],
}


def test_coverage_import_badge(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "cov-export", json.dumps(EXPORT))
    click(page, "btn-cov-import")
    wait_visible(page, "cov-output", timeout=60)
    wait_text(page, "cov-output", "file(s)", timeout=60)
    wait_text(page, "cov-badge", "87.0%", timeout=60)
