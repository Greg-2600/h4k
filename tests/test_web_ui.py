# The web UI has no framework and no build step, so the only thing standing
# between a deleted element and a silently dead interface is this contract:
# app.js binds handlers at load time, so one id it touches but index.html
# does not define aborts the whole script.
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


# `id="..."` must not match the tail of `data-testid="..."`, so the attribute
# name is anchored with a negative lookbehind.
_ID_RE = r'(?<![\w-])id="([^"]+)"'
_TESTID_RE = r'data-testid="([^"]+)"'


def test_every_js_id_lookup_exists_in_the_html():
    html_ids = set(re.findall(_ID_RE, _html()))
    wanted = set(re.findall(r"""\$\(['"]([A-Za-z0-9_-]+)['"]\)""", _js()))
    wanted |= set(re.findall(r'getElementById\(["\']([A-Za-z0-9_-]+)["\']\)', _js()))
    missing = sorted(wanted - html_ids)
    assert not missing, f"app.js references undefined ids: {missing}"


def test_no_duplicate_element_ids():
    ids = re.findall(_ID_RE, _html())
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate ids in index.html: {dupes}"


def test_no_duplicate_test_ids():
    """The Selenium suite targets elements by data-testid — they must be unique."""
    ids = re.findall(_TESTID_RE, _html())
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate data-testid in index.html: {dupes}"


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


def test_the_workspace_nav_is_present():
    """Six kill-chain phases, operator order: Discover → Recon → Exploit → Pivot → Persist → Score."""
    html = _html()
    names = ("discover", "recon", "exploit", "pivot", "persist", "score")
    for name in names:
        assert f'data-tab="{name}"' in html, f"workspace {name} missing"
    nav = set(re.findall(r'class="ws-btn[^"]*"[^>]*data-tab="([^"]+)"', html))
    secs = set(re.findall(r'class="ws-panel[^"]*"[^>]*data-tab="([^"]+)"', html))
    assert nav == secs == set(names), f"nav/panel mismatch: {nav ^ secs}"
    dom_order = re.findall(r'<section class="ws-panel[^"]*"[^>]*id="tab-(\w+)"', html)
    nav_order = re.findall(r'class="ws-btn[^"]*"[^>]*data-tab="(\w+)"', html)
    assert dom_order == nav_order == list(names)


def test_only_discover_starts_visible():
    html = _html()
    tabs = re.findall(r'<section class="ws-panel([^"]*)"[^>]*id="tab-(\w+)"', html)
    visible = [tid for cls, tid in tabs if "active" in cls.split()]
    assert visible == ["discover"], f"expected only discover visible, got {visible}"


def test_operator_chrome_exists():
    """Status bar + next action + drawers: the persistent operator chrome."""
    html = _html()
    for needle in (
        'id="scope-select"',
        'id="msf-status"',
        'id="cap-status"',
        'id="autoscan-status"',
        'id="flag-counter"',
        'id="host-counter"',
        'id="next-move-bar"',
        'id="next-move-list"',
        'id="btn-refresh-next"',
        'id="activity-drawer"',
        'id="activity-log"',
        'id="cmd-palette"',
        'id="cmd-input"',
        'id="flag-toast"',
    ):
        assert needle in html, f"{needle} missing"
    for cls in ("statusbar", "nextmove", "workspaces", "ws-btn", "ws-panel"):
        assert f".{cls}" in _css(), f"class .{cls} has no CSS rule"


def test_workspace_panels_exist():
    """Every workspace owns its controls; no hidden-compat leftovers."""
    html = _html()
    for cid in (
        # discover
        "target",
        "mode-select",
        "depth-select",
        "btn-scan",
        "btn-neighbors",
        "scan-status",
        "scope-summary",
        "btn-live-map-toggle",
        # recon
        "hosts-tbody",
        "hosts-empty",
        "hosts-count",
        "vulns-tbody",
        "vulns-empty",
        "vulns-count",
        "btn-fingerprint",
        "btn-full-scan",
        "cve-status",
        "btn-cve-refresh",
        # exploit
        "attack-queue",
        "attack-empty",
        "attack-queue-count",
        "btn-ap-start",
        "btn-ap-stop",
        "ap-status",
        "ap-log",
        "ap-tbody",
        "ap-summary",
        "cred-targets-tbody",
        "cred-targets-empty",
        "cred-targets-count",
        "btn-cred-targets-refresh",
        "btn-launch-passattack",
        "fz-host",
        "fz-port",
        "fz-iters",
        "fz-timeout",
        "btn-fz-start",
        "btn-fz-stop",
        "fz-output",
        "fz-live",
        # pivot
        "creds-ledger",
        "creds-empty",
        "creds-ledger-count",
        "prop-body",
        "prop-results",
        "btn-propagate-plan",
        "btn-propagate-run",
        "shells-list",
        "shells-empty",
        "shells-count",
        "ex-console",
        "ex-console-target",
        "ex-console-output",
        "ex-cmd",
        "btn-ex-cmd",
        "shell-close",
        "lateral-cidr",
        "btn-lateral-map",
        "lateral-body",
        "db-target",
        "btn-db-run",
        "db-body",
        "btn-escape-run",
        "escape-body",
        "btn-trylocalroot-run",
        "trylocalroot-body",
        # persist
        "persist-checks",
        "persist-sessions",
        "btn-reenter",
        "btn-go-score",
        # score
        "flags-grid",
        "flags-empty",
        "flags-count",
        "flag-value",
        "flag-host",
        "flag-note",
        "btn-flag-add",
        "btn-flag-detect",
        "crown-list",
        "cj-host",
        "cj-label",
        "cj-value",
        "btn-add-crown",
        "btn-attack-paths",
        "attack-paths-body",
        "attack-paths-summary",
        "attck-body",
        "btn-attck",
        "report-preview",
        "btn-session-report",
    ):
        assert f'id="{cid}"' in html, f"{cid} missing"


def test_no_gamification_leftovers():
    """First-principles rule: operator console, not a game. No XP/glitch/sound."""
    html, js = _html(), _js()
    for needle in (
        "xp-bar",
        "player-level",
        "player-xp",
        "ach-popup",
        "glitch-overlay",
        "sound-toggle",
        "xp-popup",
    ):
        assert needle not in html, f"gamification leftover in HTML: {needle}"
        assert needle not in js, f"gamification leftover in JS: {needle}"
    assert "logXp" not in js, "XP function still present"
    assert "playSound" not in js, "sound function still present"


def test_no_inline_styles():
    """Layout lives in style.css; inline styles are unthemeable one-offs."""
    assert 'style="' not in _html(), "inline styles in index.html"


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
    assert _html().count('id="target"') == 1, "expected exactly one #target"


def test_tables_scroll_inside_their_card():
    """Half-screen rule: wide tables must scroll inside `.tbl-wrap`, never
    push the whole page sideways. Every table needs the wrapper."""
    html = _html()
    tables = re.findall(r'<table class="tbl">', html)
    wraps = re.findall(r'class="tbl-wrap"', html)
    assert tables, "no tables found"
    assert len(wraps) == len(tables), f"{len(tables)} tables but {len(wraps)} wrappers"
    assert ".tbl-wrap" in _css(), "class .tbl-wrap has no CSS rule"


def test_responsive_breakpoints_exist():
    """Half-screen rule: the status bar must shed chrome as width shrinks."""
    css = _css()
    for needle in (
        "@media (max-width: 1100px)",
        "@media (max-width: 900px)",
        "@media (max-width: 640px)",
    ):
        assert needle in css, f"missing breakpoint {needle}"
