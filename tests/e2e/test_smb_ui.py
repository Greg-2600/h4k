"""SMB share enumeration through the real UI (sandbox mode)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_smb_enum_renders_shares(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "smb-target", "10.10.10.42")
    click(page, "btn-smb-enum")
    wait_visible(page, "smb-shares", timeout=60)
    wait_text(page, "smb-shares", "3 share(s)", timeout=60)
    wait_text(page, "smb-status", "3 share(s)", timeout=60)
