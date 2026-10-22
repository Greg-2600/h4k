# The web UI has no framework and no build step, so the only thing standing
# between a deleted element and a silently dead interface is this contract:
# app.js binds every handler at load time, so one id it touches but index.html
# does not define aborts the whole script. The console stops scrolling, the job
# poller never starts, and nothing throws a visible error. That regression
# shipped once (the consolidated-report panel was dropped from the HTML), so it
# is pinned here instead of being rediscovered by hand.
import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "h4k" / "web"
INDEX = WEB / "index.html"
APP = WEB / "app.js"
CSS = WEB / "style.css"


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _js() -> str:
    return APP.read_text(encoding="utf-8")


def _css() -> str:
    return CSS.read_text(encoding="utf-8")


def test_every_js_id_lookup_exists_in_the_html():
    html_ids = set(re.findall(r'id="([^"]+)"', _html()))
    wanted = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', _js()))
    wanted |= set(re.findall(r'getElementById\("([A-Za-z0-9_-]+)"\)', _js()))
    missing = sorted(wanted - html_ids)
    assert not missing, f"app.js references undefined ids: {missing}"


def test_no_duplicate_element_ids():
    ids = re.findall(r'id="([^"]+)"', _html())
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate ids in index.html: {dupes}"


def test_html_tags_are_balanced():
    """A truncated or over-closed pane swallows everything after it."""
    void = {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
    stack: list[tuple[str, int]] = []
    for m in re.finditer(r"<(/?)([a-zA-Z0-9]+)([^>]*)>", _html()):
        closing, tag, rest = m.group(1), m.group(2).lower(), m.group(3)
        if tag in void or rest.rstrip().endswith("/"):
            continue
        line = _html()[: m.start()].count("\n") + 1
        if not closing:
            stack.append((tag, line))
            continue
        assert stack, f"stray </{tag}> on line {line}"
        top, opened = stack.pop()
        assert (
            top == tag
        ), f"</{tag}> on line {line} closes <{top}> opened line {opened}"
    assert not stack, f"unclosed tags: {[(name, ln) for name, ln in stack]}"


def test_the_five_phases_are_present():
    """The nav buttons are the whole navigation; a missing phase is a dead end."""
    html = _html()
    for name in ("recon", "analyze", "prepare", "execute", "pwned"):
        assert f'id="phase-{name}"' in html, f"phase {name} missing"
        assert f'data-phase="{name}"' in html, f"nav entry for {name} missing"
    nav = set(re.findall(r'class="nav-btn[^"]*"[^>]*data-phase="([^"]+)"', html))
    secs = set(re.findall(r'class="phase"[^>]*data-phase="([^"]+)"', html))
    assert nav == secs, f"nav/phase mismatch: {nav ^ secs}"


def test_only_one_phase_starts_visible():
    """Only the recon phase should be visible at load; the others are hidden."""
    html = _html()
    open_phases = re.findall(
        r'<div class="phase"[^>]*id="phase-(\w+)"(?![^>]*hidden)', html
    )
    assert open_phases == ["recon"], f"expected only recon visible, got {open_phases}"


def test_phase_order_matches_the_nav_order():
    """app.js's state.currentPhase must agree with the markup order: the nav
    order is the workflow order (recon -> analyze -> prepare -> execute -> pwned)."""
    dom_order = re.findall(r'<div class="phase"[^>]*id="phase-(\w+)"', _html())
    nav_order = re.findall(r'class="nav-btn[^"]*"[^>]*data-phase="(\w+)"', _html())
    assert dom_order == nav_order, f"nav {nav_order} != markup {dom_order}"


def test_stat_tiles_keep_their_class_list():
    """Assigning `.className` on a stat number silently drops `.stat-n`, so the
    headline renders as body text and stops matching the stat selectors."""
    js = _js()
    for m in re.finditer(r'\$\("(fsum-[a-z]+)"\)\.className', js):
        raise AssertionError(
            f"{m.group(1)} is assigned className wholesale, dropping its base class"
        )


def test_findings_panels_exist():
    """The analyze phase hosts vuln details; the prepare phase hosts config."""
    html = _html()
    assert 'id="vuln-list"' in html, "vuln-list missing"
    assert 'id="vuln-detail"' in html, "vuln-detail missing"
    assert 'id="config-summary"' in html, "config-summary missing"


def test_msf_status_footer_present():
    """msf-status shows MSF connection state in the footer via .status-dot class."""
    html = _html()
    assert 'id="msf-status"' in html, "msf-status element missing"
    assert re.search(r'class="status-dot', html), "status-dot element missing"


def test_new_ui_classes_are_styled():
    """A class the stylesheet never heard of renders as unstyled markup."""
    css = _css()
    unstyled = sorted(
        c
        for c in {c for m in re.findall(r'class="([^"]+)"', _html()) for c in m.split()}
        if not re.search(r"\." + re.escape(c) + r"(?![\w-])", css)
    )
    assert not unstyled, f"classes with no CSS rule: {unstyled}"


def test_target_input_uses_canonical_id():
    """One #target only: two inputs means the operator can shoot the wrong box."""
    html = _html()
    assert html.count('id="target"') == 1, "expected exactly one #target"
    js = _js()
    assert '$("target").value = ""' not in js, "scan clears the target field"
