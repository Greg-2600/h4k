"""Autopilot (Walk) end-to-end in sandbox mode.

Sandbox mode makes the walk deterministic: three lab hosts, one known
credential, and no network traffic. The UI, the API, the parsers and the
scoring are all real.
"""

from __future__ import annotations

from selenium.webdriver.support.ui import WebDriverWait

from .helpers import all_of, click, go_to, rows_of, wait_text, wait_visible


def _run_walk(page, timeout=180):
    """Start the autopilot and wait until the console shows a finished run."""
    go_to(page, "exploit")
    click(page, "ap-start")
    wait_text(page, "ap-status", "done", timeout=timeout)
    # the host table is filled from the same poll that flips the chip
    WebDriverWait(page, 30).until(lambda d: len(rows_of(d, "ap-tbody")) >= 3)
    return rows_of(page, "ap-tbody")


def test_autopilot_walk_completes_and_shows_hosts(page, seeded):
    rows = _run_walk(page)
    assert len(rows) >= 3, f"expected the 3 sandbox hosts, got {len(rows)}"
    body = " ".join(r.text for r in rows)
    assert "10.10.10." in body


def test_autopilot_log_records_the_walk(page, seeded):
    _run_walk(page)
    log_text = all_of(page, "ap-log")[0].text
    assert "autopilot start" in log_text
    assert "autopilot complete" in log_text


def test_autopilot_summary_counts_hosts(page, seeded):
    _run_walk(page)
    wait_visible(page, "ap-summary")
    assert "3 hosts" in all_of(page, "ap-chip-hosts")[0].text


def test_autopilot_finds_the_sandbox_credential(page, seeded):
    _run_walk(page)
    log_text = all_of(page, "ap-log")[0].text
    assert "login admin:lab-admin" in log_text
