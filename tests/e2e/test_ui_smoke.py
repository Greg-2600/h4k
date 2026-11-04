"""Smoke tests: the console boots, navigates, and shows the scope."""

from __future__ import annotations

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

from .helpers import find, go_to, wait_text, wait_visible


def test_app_boots(page, api):
    assert "h4k" in page.title.lower()
    # every workspace button is present
    for tab in ("discover", "recon", "exploit", "pivot", "persist", "score"):
        assert page.find_element(
            By.CSS_SELECTOR, f'.ws-btn[data-tab="{tab}"]'
        ).is_displayed()
    # the activity drawer starts shut; open it before asserting on the log
    page.find_element(By.ID, "activity-toggle").click()
    assert wait_visible(page, "activity-log")


def test_health_endpoint_is_ok(api):
    status, payload = api.get("/api/health")
    assert status == 200
    assert payload["status"] == "ok"


def test_msf_pill_matches_health_contract(page, api):
    # regression: the pill read h.msf === 'up' but /api/health returns
    # {msf: {reachable: bool}} — so it showed "down" while msf was fine
    status, payload = api.get("/api/health")
    assert status == 200
    assert wait_text(
        page,
        "msf-status",
        "msf up" if payload["msf"]["reachable"] else "msf down",
        timeout=30,
    )


def test_scope_selector_lists_engagement(page, seeded):
    # the header scope picker is populated from /api/engagement
    sel = wait_visible(page, "scope-select")
    # the option list is filled asynchronously
    WebDriverWait(page, 20).until(
        lambda d: seeded["id"]
        in [o.get_attribute("value") for o in sel.find_elements(By.TAG_NAME, "option")]
    )


def test_navigation_switches_pages(page):
    go_to(page, "score")
    assert page.find_element(By.CSS_SELECTOR, "#tab-score").is_displayed()
    go_to(page, "exploit")
    assert page.find_element(By.CSS_SELECTOR, "#tab-exploit").is_displayed()
    go_to(page, "discover")
    assert page.find_element(By.CSS_SELECTOR, "#tab-discover").is_displayed()


def test_score_page_contains_new_panels(page):
    go_to(page, "score")
    assert find(page, "compute-paths").is_displayed()
    assert find(page, "load-attck").is_displayed()
    assert find(page, "crown-host").is_displayed()


def test_report_preview_renders(page, seeded):
    """Regression: opening the Report area used to throw a ReferenceError."""
    go_to(page, "score")
    wait_text(
        page,
        "report-preview",
        "h4k session report",
        timeout=40,
        retry=lambda d: d.find_element(
            By.CSS_SELECTOR, '.ws-btn[data-tab="score"]'
        ).click(),
    )


def test_capability_badge_reports_readiness(page, seeded):
    """The status bar badge tells the operator what this instance can do."""
    from .helpers import wait_for, wait_text

    badge = wait_for(page, "cap-status")
    assert badge.is_displayed()
    # it must resolve to a definite state, not stay on "?"
    wait_text(page, "cap-status", "caps:", timeout=40)
    text = badge.text
    assert "?" not in text
    assert "unavailable" not in text
