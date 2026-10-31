"""ATT&CK mapping + detection guidance in the Report page."""

from __future__ import annotations

from .helpers import all_of, click, go_to, wait_text, wait_visible


def test_attck_panel_lists_techniques(page, seeded):
    go_to(page, "score")
    click(page, "load-attck")
    wait_visible(page, "attck-technique")
    techs = all_of(page, "attck-technique")
    assert len(techs) >= 1
    ids = [t.text for t in all_of(page, "attck-tech-id")]
    assert any(i.startswith("T") for i in ids), ids


def test_attck_panel_shows_detection_guidance(page, seeded):
    go_to(page, "score")
    click(page, "load-attck")
    wait_visible(page, "attck-detection")
    text = all_of(page, "attck-detection")[0].text
    assert "sources:" in text.lower() or "sources:" in text
    assert "events:" in text


def test_attck_panel_empty_state_without_findings(page, api, api_server):
    # no active scope -> the panel explains what to do instead of breaking
    api.post("/api/session/scope", {"engagement_id": None})
    page.get(api_server)
    go_to(page, "score")
    click(page, "load-attck")
    wait_text(page, "attck-body", "No active engagement scope")
