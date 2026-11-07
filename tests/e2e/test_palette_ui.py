"""Command palette end-to-end: Ctrl-K open, filter, Enter dispatches."""

from __future__ import annotations

from typing import Any

from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from .helpers import fill, go_to, wait_text, wait_visible


def _open_palette(page: Any) -> None:
    page.find_element(By.TAG_NAME, "body").send_keys(Keys.CONTROL, "k")
    wait_visible(page, "cmd-palette", timeout=20)


def test_palette_runs_kev_check(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "kev-cves", "CVE-2021-43798")
    _open_palette(page)
    fill(page, "cmd-input", "kev")
    page.find_element(By.CSS_SELECTOR, '[data-testid="cmd-input"]').send_keys(
        Keys.ENTER
    )
    wait_text(page, "kev-result", "CVE-2021-43798", timeout=60)


def test_palette_runs_tls_inventory(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "tls-inv-targets", "127.0.0.1:443")
    _open_palette(page)
    fill(page, "cmd-input", "tls-inv")
    page.find_element(By.CSS_SELECTOR, '[data-testid="cmd-input"]').send_keys(
        Keys.ENTER
    )
    wait_visible(page, "tls-inv-entry", timeout=60)
