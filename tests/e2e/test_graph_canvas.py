"""Attack-graph canvas: render, click node, zoom state changes."""

from __future__ import annotations

from selenium.webdriver.common.by import By

from .helpers import click, find, go_to, wait_text, wait_visible


def test_canvas_renders_nodes(page, seeded):
    go_to(page, "score")
    click(page, "load-canvas")
    wait_visible(page, "graph-canvas", timeout=60)
    wait_text(page, "canvas-legend", "nodes", timeout=60)


def test_canvas_zoom_and_reset(page, seeded):
    go_to(page, "score")
    click(page, "load-canvas")
    wait_visible(page, "graph-canvas", timeout=60)
    before = find(page, "graph-canvas").get_attribute("viewBox")
    click(page, "canvas-zoom-in")
    after = find(page, "graph-canvas").get_attribute("viewBox")
    assert before != after
    click(page, "canvas-reset")
    assert find(page, "graph-canvas").get_attribute("viewBox") == "0 0 800 600"
    # clicking a node fills the detail pane
    node = page.find_element(By.CSS_SELECTOR, "[data-canvas-node]")
    node.click()
    wait_text(page, "canvas-detail", "type=", timeout=60)
