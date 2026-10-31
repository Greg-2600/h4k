# OpenAPI / Swagger completeness: the served schema must describe every
# registered API route, and every capability in the inventory must map to
# at least one endpoint. Adding a tool without an endpoint (or an endpoint
# without a schema) fails here by design.
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

# capability -> representative endpoint(s) proving it is API-reachable
CAPABILITY_ENDPOINTS: dict[str, list[str]] = {
    "nmap": ["/api/scan", "/api/nmap/nse"],
    "arp-scan": ["/api/neighbors", "/api/net/arp"],
    "hydra": ["/api/deepattack"],
    "nikto": ["/api/nikto"],
    "gobuster": ["/api/gobuster"],
    "sqlmap": ["/api/sqlmap"],
    "semgrep": ["/api/source/scan"],
    "osv-scanner": ["/api/source/sca"],
    "trivy": ["/api/source/sca/sbom"],
    "john": ["/api/john"],
    "msfconsole": ["/api/attack"],
    "docker": ["/api/privesc/try-docker-group", "/api/container_escape"],
    "adb": ["/api/firetv/recon", "/api/firetv/shell"],
}


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import main as main_module

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module._rate_store = None
    return main_module.app


def test_swagger_ui_and_spec_served(monkeypatch, app):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    client = TestClient(app)
    r = client.get("/docs")
    assert r.status_code == 200 and "swagger" in r.text.lower()
    r = client.get("/openapi.json")
    assert r.status_code == 200 and r.json()["info"]["title"]


def _declared_paths() -> set[str]:
    """Every schema-visible API path from the router tables themselves.

    (The app object holds lazy _IncludedRouter refs in this FastAPI
    version, so we read the source routers — the same tables the app
    serves from.)
    """
    from fastapi.routing import APIRoute
    from routers import engagement, net, scan, source, update

    found: set[str] = set()

    def _walk(routes) -> None:
        for route in routes:
            if isinstance(route, APIRoute):
                if route.path.startswith("/api") and route.include_in_schema:
                    found.add(route.path)
            elif hasattr(route, "routes"):
                _walk(route.routes)

    for router in (
        scan.router,
        source.router,
        update.router,
        net.router,
        engagement.router,
    ):
        _walk(router.routes)
    return found


def test_every_route_in_openapi_schema(app):
    spec = app.openapi()
    declared = _declared_paths()
    assert declared, "no API routes registered"
    missing = [p for p in sorted(declared) if p not in spec["paths"]]
    assert not missing, f"routes missing from OpenAPI schema: {missing}"


def test_every_capability_has_an_endpoint(app):
    from services.capabilities import TOOLS

    spec = app.openapi()
    paths = spec["paths"]
    unmapped = [t for t in TOOLS if t not in CAPABILITY_ENDPOINTS]
    assert not unmapped, f"capabilities without an endpoint mapping: {unmapped}"
    missing = [
        p
        for tool, endpoints in CAPABILITY_ENDPOINTS.items()
        for p in endpoints
        if p not in paths
    ]
    assert not missing, f"mapped endpoints missing from OpenAPI schema: {missing}"
