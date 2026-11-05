"""SARIF interchange card through the real UI (sandbox canned)."""

from __future__ import annotations

import json
from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

SEMGREP = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep OSS",
                    "rules": [
                        {
                            "id": "r1",
                            "name": "exec-call",
                            "shortDescription": {"text": "exec"},
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {"tags": ["security", "CWE-95"]},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "r1",
                    "level": "warning",
                    "message": {"text": "exec() call"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app.py"},
                                "region": {"startLine": 7},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}

H4K = [
    {
        "rule_id": "sast-secret-http",
        "name": "Hardcoded credential",
        "severity": "high",
        "cwe": "CWE-798",
        "file": "app.py",
        "line": 3,
        "code": "k = 'x'",
        "description": "hardcoded",
    }
]


def test_sarif_import_card(page: Any, seeded: dict[str, Any]) -> None:
    # Sandbox answers the canned round-trip regardless of the paste,
    # so assert on canned content (live parsing is covered by unit tests).
    go_to(page, "score")
    fill(page, "sarif-paste", json.dumps(SEMGREP))
    click(page, "btn-sarif-import")
    wait_visible(page, "sarif-output", timeout=60)
    wait_text(page, "sarif-output", "1 finding(s)", timeout=60)
    wait_text(page, "sarif-output", "Hardcoded credential", timeout=60)


def test_sarif_export_download(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "score")
    fill(page, "sarif-paste", json.dumps(H4K))
    click(page, "btn-sarif-export")
    wait_visible(page, "sarif-output", timeout=60)
    wait_text(page, "sarif-output", "1 result(s)", timeout=60)
