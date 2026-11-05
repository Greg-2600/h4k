"""OpenAPI spec fuzz card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

import json
from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/items": {
            "post": {
                "operationId": "createItem",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"name": {"type": "string"}},
                            }
                        }
                    }
                },
            }
        }
    },
}


def test_openapi_fuzz_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "oapi-base", "http://10.10.10.77:8080")
    fill(page, "oapi-iters", "8")
    fill(page, "oapi-spec", json.dumps(SPEC))
    click(page, "btn-oapi-start")
    wait_visible(page, "oapi-output", timeout=60)
    wait_text(page, "oapi-output", "candidate(s)", timeout=120)
    wait_text(page, "oapi-output", "in ledger", timeout=60)
