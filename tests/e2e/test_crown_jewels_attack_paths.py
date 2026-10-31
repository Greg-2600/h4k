"""Crown jewels + attack paths, driven through the real UI."""

from __future__ import annotations

from .helpers import all_of, click, fill, go_to, wait_text, wait_visible


def _open_paths(page):
    go_to(page, "score")
    click(page, "compute-paths")
    wait_visible(page, "crown-list")


def test_seeded_crown_jewel_is_listed(page, seeded):
    _open_paths(page)
    wait_text(page, "crown-list", "Domain controller")


def test_attack_paths_are_rendered(page, seeded):
    _open_paths(page)
    # the seeded estate has a pivot path to the DC
    wait_visible(page, "path-item")
    paths = all_of(page, "path-item")
    assert len(paths) >= 1
    node_text = all_of(page, "path-nodes")[0].text
    assert "10.10.10.42" in node_text, node_text
    score = all_of(page, "path-score")[0].text
    assert score.strip().isdigit()


def test_paths_summary_reports_counts(page, seeded):
    _open_paths(page)
    wait_text(page, "paths-summary", "path(s)")


def test_add_crown_jewel_through_the_form(page, seeded):
    _open_paths(page)
    fill(page, "crown-host", "10.10.10.9")
    fill(page, "crown-label", "Jump host")
    fill(page, "crown-value", "60")
    click(page, "add-crown")
    wait_text(page, "crown-list", "Jump host")


def test_add_crown_jewel_rejects_out_of_scope_host(page, seeded):
    _open_paths(page)
    fill(page, "crown-host", "8.8.8.8")
    fill(page, "crown-label", "Not allowed")
    click(page, "add-crown")
    # the API refuses (400) and the UI reports it in the activity log
    wait_text(page, "activity-log", "Add crown jewel failed", timeout=60)


def test_delete_crown_jewel(page, seeded):
    _open_paths(page)
    wait_text(page, "crown-list", "Domain controller")
    click(page, "del-crown")
    # the seeded crown jewel is gone; the list falls back to the empty state
    wait_text(page, "crown-list", "No crown jewels declared yet")


def test_attack_paths_persist_across_reload(page, seeded, api_server):
    _open_paths(page)
    wait_visible(page, "path-item")
    page.get(api_server)
    go_to(page, "score")
    click(page, "compute-paths")
    wait_visible(page, "path-item")


def test_flag_paths_reach_captured_flag(page, seeded, api):
    go_to(page, "score")
    status, payload = api.post(
        f"/api/engagement/{seeded['id']}/flags",
        {"value": "CTF{e2e}", "host": "10.10.10.42"},
    )
    assert status == 200, payload
    click(page, "compute-flag-paths")
    wait_visible(page, "path-item")
    wait_text(page, "paths-summary", "flag path(s)")
    wait_text(page, "attack-paths", "CTF{e2e}")
