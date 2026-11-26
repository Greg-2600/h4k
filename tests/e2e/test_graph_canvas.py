"""Attack-graph canvas: render, click node, zoom state changes."""

from __future__ import annotations

import contextlib
from typing import Any

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.support.ui import WebDriverWait

from .helpers import click, find, go_to, wait_text

_NODE_SELECTOR = "#graph-canvas [data-canvas-node]"


def _viewbox(page: WebDriver) -> Any:
    el = find(page, "graph-canvas")
    return page.execute_script("return arguments[0].getAttribute('viewBox');", el)


def _canvas_nodes(page: WebDriver) -> list[Any]:
    return page.find_elements(By.CSS_SELECTOR, _NODE_SELECTOR)


def _render_canvas(page: WebDriver) -> list[Any]:
    """Open Score and wait for the SVG to contain real node groups.

    The `<svg>` element is present from page load, so waiting for it says
    nothing about whether the render request finished. Wait for the node
    groups instead. If the initial click raced the tab switch, nudge it
    again on each poll rather than sitting on a stale empty canvas.
    """
    go_to(page, "score")
    click(page, "load-canvas")

    def _rendered(driver: WebDriver) -> Any:
        nodes = _canvas_nodes(driver)
        if nodes:
            return nodes
        with contextlib.suppress(Exception):
            driver.find_element(By.CSS_SELECTOR, '[data-testid="load-canvas"]').click()
        return False

    return WebDriverWait(page, 60).until(_rendered)


def test_canvas_renders_nodes(page: WebDriver, seeded: dict[str, Any]) -> None:
    nodes = _render_canvas(page)
    assert len(nodes) >= 1
    wait_text(page, "canvas-legend", "nodes", timeout=60)


def test_canvas_zoom_and_reset(page: WebDriver, seeded: dict[str, Any]) -> None:
    _render_canvas(page)
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
