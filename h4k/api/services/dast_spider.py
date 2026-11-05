"""Lightweight DAST spider + auth crawl (Backlog #3).

ZAP's spider needs the ZAP daemon. This module is the dependency-free
complement: a depth-bounded, same-origin BFS crawl over a web surface you
own, with optional auth (bearer/api-key header or session cookie) so it can
map the *authed* attack surface. Scope-checked: only URLs on the target's
own host:port are followed; everything else is reported as external and
never fetched.
"""

from __future__ import annotations

import contextlib
import logging
from collections import deque
from html.parser import HTMLParser
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("h4k.dast_spider")

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PAGES = 50
MAX_DEPTH_CAP = 5
MAX_PAGES_CAP = 500


class _LinkFormParser(HTMLParser):
    """Collect same-document links and forms."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self.title_parts: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        at = {k: (v or "") for k, v in attrs}
        if tag == "a" and at.get("href"):
            self.links.append(at["href"])
        elif tag == "form":
            self._current_form = {
                "action": at.get("action", ""),
                "method": (at.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {"name": at.get("name", ""), "type": at.get("type", "text")}
            )
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data.strip())


def _origin(url: str) -> str:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{host}:{port}"


def _normalize(base: str, href: str) -> str:
    return urljoin(base, href.split("#")[0].strip())


def crawl(
    target: str,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_pages: int = DEFAULT_MAX_PAGES,
    auth_header: str | None = None,
    auth_cookie: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """BFS crawl of one origin. Never fetches off-origin URLs."""
    max_depth = max(0, min(int(max_depth), MAX_DEPTH_CAP))
    max_pages = max(1, min(int(max_pages), MAX_PAGES_CAP))
    if "://" not in target:
        target = f"http://{target}"
    origin = _origin(target)
    headers: dict[str, str] = {"User-Agent": "h4k-spider/1.0 (authorized scan)"}
    if auth_header:
        headers["Authorization"] = auth_header
    if auth_cookie:
        headers["Cookie"] = auth_cookie

    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    external: list[str] = []
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(target, 0)])
    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        req = urlrequest.Request(
            url, headers=headers
        )  # nosec B310 - target URL is the authorized scan target
        try:
            resp = urlrequest.urlopen(
                req, timeout=timeout
            )  # nosec B310 - target URL is the authorized scan target
        except HTTPError as exc:
            pages.append(
                {"url": url, "status": exc.code, "title": "", "links_found": 0}
            )
            continue
        except (URLError, OSError, ValueError) as exc:
            logger.debug("spider fetch failed for %s: %s", url, exc)
            pages.append(
                {
                    "url": url,
                    "status": 0,
                    "title": "",
                    "links_found": 0,
                    "error": str(exc)[:200],
                }
            )
            continue
        try:
            status = getattr(resp, "status", 200) or 200
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read(512_000).decode("utf-8", errors="replace")
        finally:
            with contextlib.suppress(Exception):
                resp.close()
        if "html" not in ctype and body and not ctype.startswith("text/"):
            pages.append({"url": url, "status": status, "title": "", "links_found": 0})
            continue
        parser = _LinkFormParser()
        with contextlib.suppress(Exception):
            parser.feed(body)
        title = " ".join(parser.title_parts)[:200]
        page_forms = []
        for f in parser.forms:
            action = _normalize(url, f["action"] or url)
            page_forms.append(
                {
                    "page": url,
                    "action": action,
                    "method": f["method"],
                    "inputs": f["inputs"],
                }
            )
        forms.extend(page_forms)
        page_links = 0
        if depth < max_depth:
            for href in parser.links:
                norm = _normalize(url, href)
                if not norm.startswith(("http://", "https://")):
                    continue
                if _origin(norm) != origin:
                    if norm not in external:
                        external.append(norm)
                    continue
                page_links += 1
                if norm not in seen:
                    queue.append((norm, depth + 1))
        pages.append(
            {
                "url": url,
                "status": status,
                "title": title,
                "links_found": page_links,
                "forms_found": len(page_forms),
            }
        )
    return {
        "target": target,
        "origin": origin,
        "pages": pages,
        "forms": forms,
        "page_count": len(pages),
        "form_count": len(forms),
        "external": sorted(external)[:200],
        "external_count": len(external),
        "auth_used": bool(auth_header or auth_cookie),
    }


def sandbox_crawl(target: str) -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    base = target if "://" in target else f"http://{target}"
    pages = [
        {
            "url": base,
            "status": 200,
            "title": "sandbox home",
            "links_found": 2,
            "forms_found": 1,
        },
        {
            "url": f"{base}/login",
            "status": 200,
            "title": "login",
            "links_found": 0,
            "forms_found": 1,
        },
        {
            "url": f"{base}/dashboard",
            "status": 200,
            "title": "dashboard",
            "links_found": 0,
            "forms_found": 0,
        },
    ]
    forms = [
        {
            "page": base,
            "action": f"{base}/search",
            "method": "GET",
            "inputs": [{"name": "q", "type": "text"}],
        },
        {
            "page": f"{base}/login",
            "action": f"{base}/login",
            "method": "POST",
            "inputs": [
                {"name": "user", "type": "text"},
                {"name": "pass", "type": "password"},
            ],
        },
    ]
    return {
        "target": base,
        "origin": _origin(base),
        "pages": pages,
        "forms": forms,
        "page_count": 3,
        "form_count": 2,
        "external": [f"{base.rstrip('/')}/external"],
        "external_count": 1,
        "auth_used": False,
        "sandbox": True,
    }
