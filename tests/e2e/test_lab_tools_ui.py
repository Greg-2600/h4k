"""Lab-tools UI: the web-assessment and Fire TV cards render and drive
their endpoints (sandboxed API: no process is ever spawned)."""

from __future__ import annotations

from .helpers import click, fill, find, go_to, wait_text


def test_web_assessment_card_runs_nikto(page):
    go_to(page, "recon")
    assert find(page, "web-target").is_displayed()
    assert find(page, "btn-nikto").is_displayed()
    assert find(page, "btn-gobuster").is_displayed()
    fill(page, "web-target", "http://127.0.0.1:8080")
    click(page, "btn-nikto")
    # sandbox refuses to spawn nikto; the refusal itself must render
    wait_text(page, "web-body", "sandbox")


def test_web_assessment_card_runs_gobuster(page):
    go_to(page, "recon")
    fill(page, "web-target", "http://127.0.0.1:8080")
    fill(page, "webgob-ext", "php")
    click(page, "btn-gobuster")
    wait_text(page, "web-body", "sandbox")


def test_firetv_card_recon_and_state(page):
    go_to(page, "pivot")
    for testid in (
        "ftv-target",
        "ftv-code",
        "btn-ftv-recon",
        "btn-ftv-pair",
        "btn-ftv-state",
        "btn-ftv-apps",
        "btn-ftv-shot",
    ):
        assert find(page, testid).is_displayed(), testid
    fill(page, "ftv-target", "127.0.0.1")
    click(page, "btn-ftv-recon")
    # read-only recon against localhost: closed ports, unknown adb state
    wait_text(page, "ftv-body", "adb state")
    click(page, "btn-ftv-state")
    wait_text(page, "ftv-body", "unknown")
