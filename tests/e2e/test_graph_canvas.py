"""Attack-graph canvas: render, click node, zoom state changes."""

from __future__ import annotations

from typing import Any

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver

from .helpers import click, find, go_to, wait_text, wait_visible


def _viewbox(page: WebDriver) -> Any:
    el = find(page, "graph-canvas")
    return page.execute_script("return arguments[0].getAttribute('viewBox');", el)


def test_canvas_renders_nodes(page: WebDriver, seeded: dict[str, Any]) -> None:
    go_to(page, "score")
    click(page, "load-canvas")
    wait_visible(page, "graph-canvas", timeout=60)
    wait_text(page, "canvas-legend", "nodes", timeout=60)


def test_canvas_zoom_and_reset(page: WebDriver, seeded: dict[str, Any]) -> None:
    go_to(page, "score")
    click(page, "load-canvas")
    wait_visible(page, "graph-canvas", timeout=60)
    before = _viewbox(page)
    assert before == "0 0 800 600"
    click(page, "canvas-zoom-in")
    after = _viewbox(page)
    assert before != after
    click(page, "canvas-reset")
    assert _viewbox(page) == "0 0 800 600"
    # clicking a node fills the detail pane (JS click: SVG <g> centres
    # are not always Selenium-clickable headless)
    node = page.find_element(By.CSS_SELECTOR, "[data-canvas-node]")
    page.execute_script("arguments[0].scrollIntoView({block: 'center'});", node)
    page.execute_script(
        "arguments[0].dispatchEvent(new MouseEvent('click', {bubbles: true}));",
        node,
    )
    wait_text(page, "canvas-detail", "type=", timeout=60)
