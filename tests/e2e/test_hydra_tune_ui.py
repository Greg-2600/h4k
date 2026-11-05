"""Tune + resume through the real UI (sandbox canned hydra)."""

from __future__ import annotations

from typing import Any

from selenium.webdriver.common.by import By

from .helpers import click, fill, go_to, wait_text


def test_passattack_tune_and_resume(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "discover")
    click(page, "btn-neighbors")
    wait_text(page, "scan-status", "done", timeout=120)
    go_to(page, "recon")
    click(page, "btn-fingerprint")
    wait_text(page, "hosts-tbody", "10.10.10", timeout=180)
    go_to(page, "exploit")
    fill(page, "pa-tasks", "8")
    rows = page.find_elements(By.CSS_SELECTOR, "[data-cred]")
    assert rows, "expected fingerprinted cred targets"
    rows[0].click()
    wait_text(page, "pa-tune-status", "8 tasks", timeout=60)
    click(page, "btn-pa-resume")
    wait_text(page, "activity-log", "resumed", timeout=120)
