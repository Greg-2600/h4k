# Keyboard-first + screen-reader contract (#83).
#
# The UI has no framework, so accessibility is a set of invariants in the HTML
# and CSS: a skip link, live regions, labelled controls, one current nav item,
# listbox/combobox semantics for the palette, and captions/scopes on every table.
# These checks are cheap and catch the regressions a visual review misses.
import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "h4k" / "web"
HTML = (WEB / "ops.html").read_text(encoding="utf-8")
JS = (WEB / "ops.js").read_text(encoding="utf-8")
CSS = (WEB / "ops.css").read_text(encoding="utf-8")


def test_skip_link_and_focusable_main():
    assert 'class="skip-link" href="#main-content"' in HTML
    main = re.search(r'<main[^>]*id="main-content"[^>]*>', HTML)
    assert main and 'tabindex="-1"' in main.group(0)


def test_live_regions_exist_and_are_sr_only():
    for role in ("status", "alert"):
        match = re.search(rf'<div[^>]*id="sr-{role}"[^>]*aria-live="[^"]+"[^>]*>', HTML)
        assert match, f"missing sr-{role} live region"
        assert f'role="{role}"' in match.group(0)
    assert "$(assertive ? 'sr-alert' : 'sr-status')" in JS
    assert ".sr-only" in CSS


def test_navigation_is_labelled_and_marks_the_current_view():
    nav = re.search(r'<nav class="nav"[^>]*aria-label="[^"]+"', HTML)
    assert nav
    buttons = re.findall(r'<button class="nav-btn[^"]*"[^>]*>', HTML)
    assert len(buttons) == 9
    for button in buttons:
        assert 'aria-controls="phase-' in button
        assert "aria-keyshortcuts=" in button
    current = [b for b in buttons if 'aria-current="page"' in b]
    assert len(current) == 1
    # every aria-controls target exists
    for target in re.findall(r'aria-controls="(phase-[^"]+)"', HTML):
        assert f'id="{target}"' in HTML
    # phases and nav order match
    nav_order = re.findall(r'class="nav-btn[^"]*"[^>]*data-phase="(\w+)"', HTML)
    dom_order = re.findall(
        r'<div class="(?:phase|console)[^"]*"[^>]*id="phase-(\w+)"', HTML
    )
    assert nav_order == dom_order


def test_every_form_control_has_a_label():
    for match in re.finditer(r"<(input|select|textarea)\b([^>]*)>", HTML):
        tag, attrs = match.group(1), match.group(2)
        ident = re.search(r'id="([^"]+)"', attrs)
        if not ident:
            continue
        control_id = ident.group(1)
        if tag == "input" and 'type="hidden"' in attrs:
            continue
        explicit = f'for="{control_id}"' in HTML
        aria = "aria-label" in attrs or "aria-labelledby" in attrs
        # implicit label: <label ...><input id=...> text</label>
        before = HTML[: match.start()]
        implicit = False
        open_label = before.rfind("<label")
        close_label = before.rfind("</label>")
        if open_label > close_label:
            implicit = True
        assert explicit or aria or implicit, f"unlabelled control: {control_id}"


def test_tables_have_captions_and_scoped_headers():
    tables = re.findall(r"<table\b[^>]*>(.*?)</table>", HTML, re.S)
    assert tables
    for table in tables:
        assert "<caption" in table
    for th in re.findall(r"<th\b[^>]*>", HTML):
        assert 'scope="col"' in th


def test_dialog_and_command_palette_semantics():
    assert re.search(r'<dialog[^>]*id="shortcuts-dialog"[^>]*aria-labelledby=', HTML)
    assert 'id="btn-shortcuts-close"' in HTML
    palette = re.search(
        r'id="cmd-palette"[^>]*role="dialog"[^>]*aria-modal="true"', HTML
    )
    assert palette
    input_tag = re.search(r'<input[^>]*id="cmd-input"[^>]*>', HTML)
    assert input_tag
    for attr in (
        'role="combobox"',
        'aria-expanded="true"',
        'aria-controls="cmd-results"',
        "aria-autocomplete",
    ):
        assert attr in input_tag.group(0)
    assert 'id="cmd-results"' in HTML and 'role="listbox"' in HTML
    options = re.findall(r'class="cmd-item[^"]*"[^>]*role="option"', HTML)
    assert len(options) >= 5


def test_keyboard_shortcuts_are_documented_and_implemented():
    for key in ("1", "9", "Ctrl", "Esc", "?"):
        assert key in HTML
    for snippet in (
        "PHASES",
        "PHASE_KEYS",
        "openShortcuts",
        "toggleCmdPalette",
        "ArrowDown",
        "aria-activedescendant",
    ):
        assert snippet in JS
    assert '[data-reduce-motion="true"]' in CSS
    assert "prefers-reduced-motion" in CSS


def test_focus_is_visible():
    assert ":focus-visible" in CSS
    assert "outline:" in CSS


def test_progressbars_and_result_regions_are_named():
    bars = re.findall(r'<div class="progress-bar"[^>]*>', HTML)
    assert bars
    for bar in bars:
        assert 'role="progressbar"' in bar
        assert "aria-label=" in bar
    for pre in re.findall(r"<pre[^>]*result-pre[^>]*>", HTML):
        assert 'role="region"' in pre
        assert "aria-label=" in pre
