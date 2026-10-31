"""Shared helpers for the Selenium suite."""

from __future__ import annotations

import contextlib
import time

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


def wait(page, timeout=20):
    return WebDriverWait(page, timeout)


def find(page, testid):
    return page.find_element(By.CSS_SELECTOR, f'[data-testid="{testid}"]')


def wait_for(page, testid, timeout=20):
    """Wait until an element with the given testid is present and visible."""
    return wait(page, timeout).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, f'[data-testid="{testid}"]'))
    )


def wait_visible(page, testid, timeout=20):
    return wait(page, timeout).until(
        EC.visibility_of_element_located((By.CSS_SELECTOR, f'[data-testid="{testid}"]'))
    )


def wait_text(page, testid, needle, timeout=20, retry=None):
    """Wait until the element's text contains `needle`.

    Uses `textContent` (not Selenium's `.text`) so entries that live in a
    hidden pane -- e.g. the activity log while the Report page is open --
    are still visible to the assertion.

    `retry` is an optional callable invoked on every poll: it is how a test
    nudges the UI to re-render (re-opening a tab) instead of only waiting for
    a request that may have been issued too early.
    """

    def _check(driver):
        if retry is not None:
            with contextlib.suppress(Exception):
                retry(driver)
        found = driver.execute_script(
            "const el = document.querySelector('[data-testid=' + arguments[0] + ']');"
            " return el ? el.textContent : null;",
            testid,
        )
        if found is None:
            return False
        return found if needle in found else False

    return wait(page, timeout).until(_check)


def all_of(page, testid):
    return page.find_elements(By.CSS_SELECTOR, f'[data-testid="{testid}"]')


def rows_of(page, testid):
    """Rows of a table body identified by testid."""
    return page.find_elements(By.CSS_SELECTOR, f'[data-testid="{testid}"] tr')


def go_to(page, tab):
    """Click a top-level workspace button (map | operate | access | loot)."""
    WebDriverWait(page, 30).until(
        lambda d: len(d.find_elements(By.CSS_SELECTOR, f'.ws-btn[data-tab="{tab}"]'))
        > 0
    )
    btn = page.find_element(By.CSS_SELECTOR, f'.ws-btn[data-tab="{tab}"]')
    WebDriverWait(page, 30).until(
        EC.visibility_of_element_located(
            (By.CSS_SELECTOR, f'.ws-btn[data-tab="{tab}"]')
        )
    )
    btn.click()
    time.sleep(0.2)


def click(page, testid):
    el = page.find_element(By.CSS_SELECTOR, f'[data-testid="{testid}"]')
    WebDriverWait(page, 30).until(
        EC.visibility_of_element_located((By.CSS_SELECTOR, f'[data-testid="{testid}"]'))
    )
    el.click()
    return el


def fill(page, testid, value):
    el = page.find_element(By.CSS_SELECTOR, f'[data-testid="{testid}"]')
    WebDriverWait(page, 30).until(
        EC.visibility_of_element_located((By.CSS_SELECTOR, f'[data-testid="{testid}"]'))
    )
    el.clear()
    el.send_keys(str(value))
    return el
