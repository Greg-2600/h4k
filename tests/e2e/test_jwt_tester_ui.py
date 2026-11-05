"""JWT tester card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def _token() -> str:
    head = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode())
        .decode()
        .rstrip("=")
    )
    body = (
        base64.urlsafe_b64encode(
            json.dumps({"sub": "u", "exp": int(time.time()) + 60}).encode()
        )
        .decode()
        .rstrip("=")
    )
    return f"{head}.{body}."


def test_jwt_test_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "jwt-token", _token())
    fill(page, "jwt-url", "http://10.10.10.77/api")
    fill(page, "jwt-marker", "Logout")
    click(page, "btn-jwt-test")
    wait_visible(page, "jwt-probes", timeout=60)
    wait_text(page, "jwt-probes", "finding(s)", timeout=60)
    wait_text(page, "jwt-probes", "in ledger", timeout=60)
