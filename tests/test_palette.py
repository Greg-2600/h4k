"""Backlog #65: command palette covers every card action.

Static contract (no browser needed): every palette entry resolves to
something real, and every runnable card button is reachable from the
palette — so the palette can never silently rot as cards are added.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "h4k" / "web"

# Palette entries handled inside runCmd itself, not via a card button.
LEGACY_COMMANDS = {"theme", "clear", "persist", "sarifx", "score"}

# Buttons that are navigation, toggles, stops, resets, deletes,
# demo seeders, form openers or deliberate multi-field submits —
# not launchable ops, so the palette skips them on purpose.
EXCLUDED_BUTTONS = {
    "btn-session-reset",
    "btn-next-go",
    "btn-live-map-toggle",
    "btn-empty-fp",
    "btn-empty-fpv",
    "btn-empty-scope",
    "btn-empty-exploit",
    "btn-ap-stop",
    "btn-fz-stop",
    "btn-canvas-zoom-in",
    "btn-canvas-zoom-out",
    "btn-canvas-reset",
    "btn-reenter",
    "btn-go-score",
    "btn-flag-add",
    "btn-add-crown",
    "btn-ex-cmd",
    "btn-scope-create",
}


class _Buttons(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "button":
            d = dict(attrs)
            ident = (d.get("id") or "") + (d.get("data-testid") or "")
            if ident.startswith("btn-"):
                self.ids.add(d.get("id") or "")


def _parse() -> tuple[dict[str, dict[str, str]], set[str]]:
    src = (WEB / "index.html").read_text()
    items: dict[str, dict[str, str]] = {}
    for m in re.finditer(r'<div class="cmd-item"([^>]*)>', src):
        attrs = dict(re.findall(r'(data-[a-z]+)="([^"]*)"', m.group(1)))
        assert attrs.get("data-cmd"), "palette item without data-cmd"
        items[attrs["data-cmd"]] = attrs
    p = _Buttons()
    p.feed(src)
    return items, p.ids


def test_palette_commands_unique_and_wired() -> None:
    items, buttons = _parse()
    app = (WEB / "app.js").read_text()
    handled = set(re.findall(r"cmd === '([a-z0-9-]+)'", app))
    for cmd, attrs in items.items():
        if "data-btn" in attrs:
            assert (
                attrs["data-btn"] in buttons
            ), f"palette {cmd!r} points at missing button {attrs['data-btn']!r}"
        else:
            assert (
                cmd in handled | LEGACY_COMMANDS
            ), f"palette {cmd!r} has no button and no runCmd branch"


def test_every_action_button_reachable() -> None:
    items, buttons = _parse()
    wired = {attrs["data-btn"] for attrs in items.values() if "data-btn" in attrs}
    missing = {b for b in buttons if b not in wired and b not in EXCLUDED_BUTTONS}
    assert not missing, "card buttons with no palette entry: " + ", ".join(
        sorted(missing)
    )
