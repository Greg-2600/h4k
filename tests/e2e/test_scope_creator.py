"""Scope creation through the Discover form — no API calls needed by hand."""

from __future__ import annotations

from .helpers import click, fill, wait_text, wait_visible


def test_scope_create_form_and_scan_guard(page, api):
    api.post("/api/session/scope", {"engagement_id": None})
    try:
        page.refresh()
        # with no scope the creator form is visible and Scan is guarded
        wait_visible(page, "scope-create", timeout=60)
        fill(page, "target-input", "127.0.0.1")
        click(page, "btn-scan")
        wait_text(page, "activity-log", "no scope", timeout=30)
        # create a scope through the form; the form hides once engaged
        fill(page, "scope-name", "e2e-lab")
        fill(page, "scope-cidrs", "127.0.0.0/8")
        click(page, "btn-scope-create")
        wait_text(page, "scope-summary", "e2e-lab", timeout=30)
    finally:
        api.post("/api/session/scope", {"engagement_id": None})
