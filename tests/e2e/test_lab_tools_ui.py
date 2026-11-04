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


def test_container_surfaces_card_detects(page):
    go_to(page, "exploit")
    for testid in (
        "cf-surface",
        "cf-target",
        "cf-iters",
        "btn-cf-detect",
        "btn-cf-start",
    ):
        assert find(page, testid).is_displayed(), testid
    fill(page, "cf-target", "127.0.0.1")
    click(page, "btn-cf-detect")
    wait_text(page, "cf-output", "docker sock")


def test_discover_stepper_and_next_go(page):
    go_to(page, "discover")
    for testid in (
        "workflow-steps",
        "step-scope",
        "step-scan",
        "step-fingerprint",
        "step-win",
    ):
        assert find(page, testid).is_displayed(), testid
    # no scope in a fresh session: step 1 shows its number, not a check
    assert "1" in find(page, "step-scope").text
    # the next strip exposes a run control for the top recommendation
    assert find(page, "next-go").is_displayed()


def test_ops_rail_shows_session_and_activity(page):
    go_to(page, "pivot")
    assert find(page, "rail-session").is_displayed()
    assert find(page, "rail-log").is_displayed()
    # the boot log line is mirrored into the rail
    wait_text(page, "rail-log", "kill-chain", timeout=30)


def test_recon_table_renders_fingerprinted_services(page, seeded):
    """Regression: loadHosts read res.hosts while /api/neighbors returns
    {neighbors} — the Services table stayed empty forever."""
    go_to(page, "discover")
    click(page, "btn-neighbors")
    wait_text(page, "scan-status", "done", timeout=120)
    go_to(page, "recon")
    click(page, "btn-fingerprint")
    wait_text(page, "hosts-tbody", "10.10.10", timeout=180)
