"""BloodHound ingest through the real UI (textarea JSON)."""

from __future__ import annotations

import json
from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def _doc() -> dict[str, Any]:
    return {
        "users": [{"ObjectIdentifier": "S-U", "Properties": {"name": "alice"}}],
        "groups": [
            {
                "ObjectIdentifier": "S-DA",
                "Properties": {"name": "Domain Admins"},
                "Members": [{"ObjectIdentifier": "S-U"}],
            }
        ],
    }


def test_bloodhound_ingest_and_paths(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    fill(page, "bh-json", json.dumps(_doc()))
    click(page, "btn-bh-ingest")
    wait_visible(page, "bh-summary", timeout=60)
    wait_text(page, "bh-summary", "2 nodes", timeout=60)
    click(page, "btn-bh-paths")
    wait_visible(page, "bh-path", timeout=60)
