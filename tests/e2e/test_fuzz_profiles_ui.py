"""Auth preset manager through the real UI (sandbox; filesystem-backed)."""

from __future__ import annotations

from typing import Any

from selenium.common.exceptions import StaleElementReferenceException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

from .helpers import click, fill, go_to, wait_text, wait_visible


def _output_text(page: Any) -> str:
    return page.find_element(By.CSS_SELECTOR, '[data-testid="prof-output"]').text


def _click_delete(page: Any) -> bool:
    # The rows re-render on every list refresh, so a row found a moment
    # ago may already be detached — re-find until the click lands.
    page.find_element(By.CSS_SELECTOR, '[data-profdel="uitest"]').click()
    return True


def test_preset_save_list_delete(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "prof-name", "uitest")
    fill(page, "prof-headers", '{"Authorization": "Bearer s3cret"}')
    fill(page, "prof-cookies", "session=abc")
    click(page, "btn-prof-save")
    wait_text(page, "prof-status", "saved uitest", timeout=60)
    click(page, "btn-prof-list")
    wait_visible(page, "prof-output", timeout=60)
    wait_text(page, "prof-output", "uitest", timeout=60)
    wait_text(page, "prof-output", "Authorization", timeout=60)
    # Values must never render into the page.
    assert "s3cret" not in page.page_source
    # Attach the preset to a stateful run, then delete it via the row button.
    fill(page, "st-profile", "uitest")
    click(page, "btn-prof-list")
    wait_text(page, "prof-output", "uitest", timeout=60)
    WebDriverWait(page, 30, ignored_exceptions=(StaleElementReferenceException,)).until(
        _click_delete
    )
    for _ in range(60):
        import time

        time.sleep(1)
        if "uitest" not in _output_text(page):
            break
    assert "uitest" not in _output_text(page)
