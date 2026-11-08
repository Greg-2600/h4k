"""Multi-lang SAST card through the real UI (sandbox canned)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text

BUNDLE = """=== main.go ===
package main
import "os/exec"
func h(q string) {
  exec.Command(q)
}
"""


def test_multilang_card(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "ml-bundle", BUNDLE)
    click(page, "btn-ml-scan")
    wait_text(page, "ml-findings", "ml-go-cmd-injection", timeout=60)
    wait_text(page, "ml-status", "finding", timeout=60)
