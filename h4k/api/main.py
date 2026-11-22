# h4k FastAPI application: serves the web UI and the JSON API.
# Binds to 0.0.0.0:3137 (set via uvicorn in entrypoint.sh).
import asyncio
import hashlib
import logging
import os
import sys
import time
import uuid as _uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

# Allow flat imports (from schemas import ...) since this file lives in api/.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from collections.abc import AsyncIterator, Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from routers import (
    ad as ad_router,
    approvals as approvals_router,
    auth as auth_router,
    automation as automation_router,
    bloodhound as bloodhound_router,
    engagement as engagement_router,
    findings as findings_router,
    lab as lab_router,
    net as net_router,
    noise as noise_router,
    sandbox as sandbox_router,
    scan as scan_router,
    source as source_router,
    telemetry as telemetry_router,
    update as update_router,
)
from services import auth as auth_service

# ---------------------------------------------------------------------------
# Logging: everything goes to stdout (container logs) with timestamps and the
# emitting logger name. Without this the root logger stays at WARNING and every
# logger.info across the services is silently swallowed. H4K_LOG_LEVEL tunes it.
# ---------------------------------------------------------------------------
LOG_LEVEL = os.environ.get("H4K_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)-7s %(name)s:%(lineno)d - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    stream=sys.stdout,
    force=True,
)
for _noisy in ("urllib3", "httpx"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("h4k")

# ---------------------------------------------------------------------------
# Rate limiting middleware (in-memory, per-IP sliding window)
# ---------------------------------------------------------------------------
# Single-operator lab console: the UI polls several endpoints concurrently
# (discovery status, fingerprint progress, cred targets, session badge), so the
# default budget must absorb a whole scanning burst — not just idle browsing.
_RATE_LIMIT = int(os.environ.get("H4K_RATE_LIMIT", "600"))  # req/min per IP
_WINDOW = 60.0  # seconds


class _RateLimitStore:
    __slots__ = ("_hits", "_windows")

    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, limit: int = _RATE_LIMIT) -> bool:
        now = time.monotonic()
        window_start = now - _WINDOW
        # expire old entries
        self._hits[key] = [t for t in self._hits[key] if t > window_start]
        if len(self._hits[key]) >= limit:
            return False
        self._hits[key].append(now)
        return True


_rate_store: _RateLimitStore | None = None
_auth_limiter: auth_service.RateLimiter | None = None
_AUTH_CONFIG: auth_service.AuthConfig | None = None
_AUTH_ENV: tuple[str, ...] = ()

_AUTH_ENV_KEYS = (
    "H4K_AUTH_ENABLED",
    "H4K_API_KEYS",
    "H4K_API_KEYS_FILE",
    "H4K_API_KEY",
    "H4K_SESSION_SECRET",
    "H4K_SESSION_TTL",
    "H4K_RATE_LIMIT_ANON",
    "H4K_RATE_LIMIT_AUTHED",
    "H4K_RATE_LIMIT_OPERATOR",
    "H4K_RATE_LIMIT_WINDOW",
    "H4K_OIDC_ISSUER",
    "H4K_OIDC_CLIENT_ID",
    "H4K_OIDC_CLIENT_SECRET",
    "H4K_OIDC_SCOPES",
    "H4K_OIDC_REDIRECT_URI",
    "H4K_OIDC_ROLE_CLAIM",
    "H4K_OIDC_ADMIN_ROLE",
    "H4K_OIDC_OPERATOR_ROLE",
    "H4K_OIDC_VERIFY_TLS",
)


def _auth_config() -> auth_service.AuthConfig:
    """Load auth config once per distinct environment (tests flip env vars)."""
    global _AUTH_CONFIG, _AUTH_ENV
    fingerprint = tuple(os.environ.get(key, "") for key in _AUTH_ENV_KEYS)
    if _AUTH_CONFIG is None or fingerprint != _AUTH_ENV:
        _AUTH_CONFIG = auth_service.load_config()
        _AUTH_ENV = fingerprint
    return _AUTH_CONFIG


def reset_auth_cache() -> None:
    """Drop cached auth config (tests/env reloads)."""
    global _AUTH_CONFIG, _auth_limiter, _rate_store
    _AUTH_CONFIG = None
    _auth_limiter = None
    _rate_store = None


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "127.0.0.1")
    )


def _rate_limited(config: auth_service.AuthConfig, request: Request) -> Response | None:
    """Apply the right budget for the caller. Returns a 429 or None."""
    global _rate_store, _auth_limiter
    path = request.url.path
    if path.startswith("/static") or path in ("/docs", "/redoc", "/openapi.json"):
        return None
    ip = _client_ip(request)
    ip_key = hashlib.sha256(ip.encode()).hexdigest()[:16]

    if not config.enabled:
        # Backwards-compatible single-operator behaviour: one IP budget.
        if _rate_store is None:
            _rate_store = _RateLimitStore()
        if not _rate_store.is_allowed(ip_key):
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded: {_RATE_LIMIT} req/min. Retry after 60s."
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(_RATE_LIMIT),
                },
            )
        return None

    principal = getattr(request.state, "principal", None)
    if _auth_limiter is None:
        _auth_limiter = auth_service.RateLimiter(config.rate_window)
    bucket = (
        f"{principal.method}:{principal.subject}"
        if principal and principal.method != "anonymous"
        else f"ip:{ip_key}"
    )
    decision = _auth_limiter.check(bucket, config.limit_for(principal))
    if not decision.allowed:
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=429,
            content={
                "detail": (
                    f"Rate limit exceeded: {decision.limit} requests per "
                    f"{int(decision.window)}s."
                ),
                "rate_limit": decision.limit,
                "retry_after": decision.reset_seconds,
            },
            headers={
                "Retry-After": str(decision.reset_seconds),
                **decision.headers(),
            },
        )
    request.state.rate_decision = decision
    return None


async def _rate_limit_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Authenticate, authorize, then rate-limit every request.

    With H4K_AUTH_ENABLED unset this is exactly the old per-IP limiter. With
    auth enabled, a valid API key or OIDC session is required for protected
    routes, the role is checked against the route class, and the budget follows
    the principal rather than the network address.
    """
    config = _auth_config()
    if config.enabled:
        try:
            principal = auth_service.principal_from_request(request, config)
            auth_service.enforce(principal, request.method, request.url.path)
        except auth_service.AuthError as exc:
            from fastapi.responses import JSONResponse

            headers = {"WWW-Authenticate": exc.challenge or "Bearer"}
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=headers,
            )
        request.state.principal = principal
    else:
        request.state.principal = auth_service.Principal(
            subject="anonymous", role="admin", method="disabled"
        )

    limited = _rate_limited(config, request)
    if limited is not None:
        return limited

    response = await call_next(request)
    decision = getattr(request.state, "rate_decision", None)
    if decision is not None:
        for name, value in decision.headers().items():
            response.headers[name] = value
    else:
        limit = (
            _RATE_LIMIT
            if not config.enabled
            else config.limit_for(request.state.principal)
        )
        response.headers["X-RateLimit-Limit"] = str(limit)
    return response


WEB_DIR = Path(__file__).resolve().parent.parent / "web"
ROOT_DIR = Path(__file__).resolve().parent.parent


def _msf_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    from services import supervisor as supervisor_mod

    return supervisor_mod.tcp_open(host, port, timeout=timeout)


def _relaunch_msfrpcd(host: str, port: int, password: str) -> bool:
    from services import supervisor as supervisor_mod

    return supervisor_mod.relaunch_msfrpcd(host, port, password)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    host = os.environ.get("MSF_HOST", "127.0.0.1")
    port = int(os.environ.get("MSF_PORT", "55553"))
    password = os.environ.get("MSF_PASSWORD", "h4k_msf_rocks")
    # Write the shared client into app_state so routers can import it.
    import app_state
    from services.cve_lookup import CveDb
    from services.msfrpc import MsfClient
    from services.sandbox import FakeMsfClient, enabled as sandbox_enabled

    if sandbox_enabled():
        # Sandbox mode: deterministic stand-ins, zero network, zero daemon.
        app_state.msf_client = FakeMsfClient(host, port, password)
        log.warning("sandbox mode ON - Metasploit calls are stubbed (H4K_SANDBOX=1)")
    else:
        app_state.msf_client = MsfClient(host, port, password)
        log.info("msf client ready (lazy connect to %s:%s)", host, port)
    # Load the local CVE database.
    app_state.cve_db = CveDb()
    log.info(
        "CVE db loaded: %d entries from %s",
        len(app_state.cve_db.cves),
        app_state.cve_db.path,
    )
    # Optional refresh if network is available (keeps bundled snapshot otherwise).
    if os.environ.get("H4K_REFRESH_CVE", "1") == "1":
        app_state.cve_db.refresh()
    # Start the passive auto-scan (best-effort): as soon as the API comes
    # up it begins building a network/service map of the local subnet, with
    # CVE correlation. No credentials, no exploitation -- recon only.
    import services.auto_scan as auto_scan_module

    auto_scan_module.start()

    # Start the periodic software-component updater (best-effort).
    _task = None
    if os.environ.get("H4K_AUTO_UPDATE", "1") == "1":
        _interval = int(os.environ.get("H4K_UPDATE_INTERVAL", "21600"))

        async def _periodic_updater() -> None:
            from services import updater

            while True:
                try:
                    if updater.should_run():
                        await asyncio.to_thread(updater.run_update)
                except Exception as exc:  # pragma: no cover - defensive
                    logging.getLogger("h4k").warning("updater cycle failed: %s", exc)
                await asyncio.sleep(_interval)

        _task = asyncio.create_task(_periodic_updater())

    # Weekly CVE-database refresh job: keeps the offline matcher current with
    # the curated upstream dataset. Independent of the tool updater's cadence
    # (which is hours) because CVE deltas move weekly, not hourly.
    _cve_task = None
    if os.environ.get("H4K_CVE_WEEKLY", "1") == "1":
        _cve_interval = int(os.environ.get("H4K_CVE_REFRESH_INTERVAL", str(7 * 86400)))

        async def _weekly_cve_refresh() -> None:
            await asyncio.sleep(_cve_interval)
            while True:
                try:
                    cve = app_state.cve_db
                    if cve is not None:
                        ok = await asyncio.to_thread(cve.refresh)
                        if ok:
                            logging.getLogger("h4k").info(
                                "weekly CVE refresh complete (%d CVEs)", len(cve.cves)
                            )
                except Exception as exc:  # pragma: no cover - defensive
                    logging.getLogger("h4k").warning(
                        "weekly CVE refresh failed: %s", exc
                    )
                await asyncio.sleep(_cve_interval)

        _cve_task = asyncio.create_task(_weekly_cve_refresh())

    # Supervisor: the entrypoint starts every daemon once at boot with no
    # supervisor afterwards. Probe postgres/msfrpcd/tor/auto-scan on a
    # cadence and restart what's down within budget (container-local only).
    _sup_task = None
    if not sandbox_enabled():
        from services import supervisor as supervisor_mod

        _sup_interval = int(
            os.environ.get(
                "H4K_SUPERVISOR_INTERVAL",
                os.environ.get("H4K_MSF_WATCHDOG_INTERVAL", "60"),
            )
        )

        async def _supervisor_loop() -> None:
            while True:
                try:
                    await asyncio.to_thread(supervisor_mod.supervisor.tick)
                except Exception as exc:  # pragma: no cover - defensive
                    logging.getLogger("h4k").warning("supervisor failed: %s", exc)
                await asyncio.sleep(_sup_interval)

        _sup_task = asyncio.create_task(_supervisor_loop())
    try:
        yield
    finally:
        auto_scan_module.stop()
        if _task is not None:
            _task.cancel()
        if _cve_task is not None:
            _cve_task.cancel()
        if _sup_task is not None:
            _sup_task.cancel()


app = FastAPI(
    title="h4k",
    description="""**h4k** — offensive-security analysis platform.

## Capabilities

| Category | Operations |
|---|---|
| **Recon** | Host scan, service fingerprint, UDP sweep, version detection |
| **Vuln** | CVE matching, version-aware exploit lookup, vuln leads |
| **Attack** | MSF RPC exploit execution, opt-in toolkits (hydra/nikto/sqlmap) |
| **Creds** | Default-credential matching, verified-credential propagation |
| **Source** | SAST (Semgrep + heuristics), SCA (SBOM + osv), PoC scaffold |
| **Fuzz** | Coverage-guided HTTP mutation, libFuzzer crash triage |
| **AI** | Ollama LLM root-cause + patch analysis |
| **Engagement** | Scope-enforced asset graph with credential ledger |

## Authorization

All aggressive operations (`do_attack`, `try_default_creds`, toolkit endpoints) are **opt-in and off by default**.
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "scan",
            "description": "Host reconnaissance and vulnerability scanning",
        },
        {
            "name": "source",
            "description": "Source-code SAST, SCA, exploit scaffolding, and GitHub CVE search",
        },
        {"name": "attack", "description": "Opt-in Metasploit exploit execution"},
        {
            "name": "toolkit",
            "description": "Non-Metasploit offensive tools (hydra/nikto/sqlmap/NSE/...)",
        },
        {
            "name": "engagement",
            "description": "Scoped engagement store with credential propagation",
        },
        {
            "name": "fuzz",
            "description": "Coverage-guided HTTP fuzzing and crash triage",
        },
        {"name": "update", "description": "Tool/CVE/rule auto-update"},
        {"name": "net", "description": "Neighbor discovery and security assessment"},
    ],
)

# Authentication first, then rate limiting.
app.middleware("http")(_rate_limit_middleware)

# ---------------------------------------------------------------------------
# Structured error responses: never leak a traceback to the client.
# ---------------------------------------------------------------------------


@app.exception_handler(Exception)
async def _unhandled_exception(request: Request, exc: Exception) -> Response:
    error_id = _uuid.uuid4().hex[:12]
    log.exception("unhandled error %s on %s: %s", error_id, request.url.path, exc)
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=500,
        content={
            "detail": "internal server error",
            "error_id": error_id,
            "path": request.url.path,
        },
    )


app.include_router(scan_router.router, tags=["scan"])
app.include_router(source_router.router, tags=["source"])
app.include_router(update_router.router, tags=["update"])
app.include_router(net_router.router, tags=["net"])
app.include_router(engagement_router.router, tags=["engagement"])
app.include_router(auth_router.router, tags=["auth"])
app.include_router(approvals_router.router, tags=["approvals"])
app.include_router(sandbox_router.router, tags=["sandbox"])
app.include_router(lab_router.router, tags=["lab"])
app.include_router(ad_router.router, tags=["ad"])
app.include_router(bloodhound_router.router, tags=["bloodhound"])
app.include_router(telemetry_router.router, tags=["telemetry"])
app.include_router(findings_router.router, tags=["findings"])
app.include_router(automation_router.router, tags=["automation"])
app.include_router(noise_router.router, tags=["noise"])

# Serve the plain HTML/JS frontend.
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/ops", include_in_schema=False)
async def ops_page(request: Request) -> Response:
    """Legacy console URL.

    The console is embedded in the dashboard's Operations workspace; a direct
    visit redirects there. ``?embed=1`` serves the fragment the iframe uses.
    """
    if request.query_params.get("embed") == "1":
        return FileResponse(WEB_DIR / "ops.html")
    return RedirectResponse(url="/?tab=ops", status_code=307)


@app.get("/api", include_in_schema=False)
async def api_landing() -> HTMLResponse:
    """API landing page with links to Swagger UI and ReDoc."""
    return HTMLResponse("""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>h4k // API</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#f5f7fa; --card:#fff; --border:#e2e5ea; --accent:#3b82f6; --text:#1a1e28; --dim:#5a6370; }
    [data-theme="dark"] { --bg:#0a0e14; --card:#111620; --border:#1e2a3a; --accent:#60a5fa; --text:#e0e6f0; --dim:#8a95a5; }
    * { box-sizing:border-box; }
    body { margin:0; font-family:'Outfit',sans-serif; background:var(--bg); color:var(--text); min-height:100vh; display:flex; flex-direction:column; }
    .hero { padding:60px 40px; text-align:center; border-bottom:1px solid var(--border); }
    .hero h1 { font-size:42px; font-weight:700; margin:0 0 8px; color:var(--accent); }
    .hero p { margin:0; font-size:16px; color:var(--dim); }
    .container { max-width:900px; margin:0 auto; padding:40px 20px; }
    .tag-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:16px; margin-bottom:40px; }
    .tag-card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; transition:all 0.15s; cursor:pointer; text-decoration:none; color:var(--text); }
    .tag-card:hover { border-color:var(--accent); transform:translateY(-2px); box-shadow:0 4px 20px rgba(0,0,0,0.08); }
    .tag-card h3 { margin:0 0 6px; font-size:16px; font-weight:600; color:var(--accent); }
    .tag-card p { margin:0; font-size:13px; color:var(--dim); }
    .tag-card .count { display:inline-block; padding:2px 8px; background:var(--bg); border-radius:10px; font-size:11px; font-family:'Space Mono',monospace; margin-top:8px; }
    .docs-links { display:flex; gap:16px; justify-content:center; margin-top:30px; }
    .docs-links a { padding:12px 28px; border-radius:8px; font-weight:600; text-decoration:none; transition:all 0.15s; }
    .docs-links a.primary { background:var(--accent); color:#fff; }
    .docs-links a.secondary { background:var(--card); color:var(--text); border:1px solid var(--border); }
    .docs-links a:hover { transform:translateY(-1px); }
    .version { text-align:center; color:var(--dim); font-size:12px; margin-top:40px; font-family:'Space Mono',monospace; }
  </style>
</head>
<body>
  <div class="hero">
    <h1>h4k // API</h1>
    <p>Offensive-security analysis platform — all capabilities accessible via REST</p>
  </div>
  <div class="container">
    <div class="tag-grid">
      <a class="tag-card" href="/docs#tag/scan">
        <h3>🔍 Scan</h3>
        <p>Host reconnaissance, service fingerprint, UDP sweep, version detection</p>
        <span class="count">9 endpoints</span>
      </a>
      <a class="tag-card" href="/docs#tag/source">
        <h3>📋 Source</h3>
        <p>SAST, SCA, SBOM, exploit scaffold, GitHub CVE search, AI analysis</p>
        <span class="count">16 endpoints</span>
      </a>
      <a class="tag-card" href="/docs#tag/attack">
        <h3>⚔️ Attack</h3>
        <p>Opt-in MSF exploit execution, module discovery, session management</p>
        <span class="count">4 endpoints</span>
      </a>
      <a class="tag-card" href="/docs#tag/toolkit">
        <h3>🛠️ Toolkit</h3>
        <p>hydra, nikto, sqlmap, NSE, deep attack orchestration</p>
        <span class="count">8 endpoints</span>
      </a>
      <a class="tag-card" href="/docs#tag/engagement">
        <h3>📁 Engagement</h3>
        <p>Scope-enforced asset graph, credential ledger, propagation</p>
        <span class="count">6 endpoints</span>
      </a>
      <a class="tag-card" href="/docs#tag/fuzz">
        <h3>💥 Fuzz</h3>
        <p>Coverage-guided HTTP mutation, crash triage, minimize</p>
        <span class="count">3 endpoints</span>
      </a>
      <a class="tag-card" href="/docs#tag/net">
        <h3>🌐 Net</h3>
        <p>ARP neighbors, security assessment, traceroute</p>
        <span class="count">2 endpoints</span>
      </a>
      <a class="tag-card" href="/docs#tag/update">
        <h3>⬆️ Update</h3>
        <p>CVE, tool, and rule auto-refresh status and triggers</p>
        <span class="count">3 endpoints</span>
      </a>
    </div>
    <div class="docs-links">
      <a class="primary" href="/docs">Swagger UI</a>
      <a class="secondary" href="/redoc">ReDoc</a>
    </div>
    <p class="version">h4k v1.0.0 · MSF RPC · SAST · SCA · Fuzzing · AI</p>
  </div>
</body>
</html>""")


@app.get("/readme", response_class=HTMLResponse, include_in_schema=False)
async def readme() -> str:
    """Render the README as a PHRACK-ezine-style terminal page."""
    md = (ROOT_DIR / "README.md").read_text(encoding="utf-8")
    return _wrap_phrack(md)


def _wrap_phrack(md: str) -> str:
    import html

    body = html.escape(md)
    # wrap triple-backtick fenced blocks
    lines = body.split("\n")
    out: list[str] = []
    in_code = False
    for ln in lines:
        if ln.startswith("```"):
            out.append('<span class="code-fence">' if not in_code else "</span>")
            in_code = not in_code
        elif in_code:
            out.append('<span class="code">' + ln + "</span>")
        else:
            out.append(ln)
    body = "\n".join(out)
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>h4k README · ezine view</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {{ --bg:#0a0a0d; --fg:#c8c8cc; --dim:#5c5c68; --accent:#79a8ff; --green:#a3d977; --amber:#e5c07b; --line:#2a2a33; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg);
  font-family:"IBM Plex Mono",ui-monospace,Menlo,monospace; font-size:13px; line-height:1.5; }}
.masthead {{ display:flex; justify-content:space-between; align-items:center;
  padding:12px 20px; border-bottom:1px solid var(--line);
  background:#0d0d12; }}
.masthead .phrack {{ color:var(--amber); font-weight:600; letter-spacing:2px; }}
.masthead .issue {{ color:var(--dim); }}
.screen {{ max-width:920px; margin:0 auto; padding:20px; white-space:pre-wrap; word-break:break-word; }}
.code {{ color:var(--green); display:block; }}
.code-fence {{ display:block; color:var(--dim); }}
.pill {{ color:var(--accent); }}
.legal {{ max-width:920px; margin:0 auto; padding:10px 20px 40px;
  color:var(--dim); border-top:1px solid var(--line); font-size:12px; white-space:pre-wrap; }}
</style></head>
<body>
<div class="masthead"><span class="phrack">PHRACK&nbsp;49</span>
<span class="issue">h4k · intrusion-suite · window into the wires</span></div>
<div class="screen" id="screen">{body}</div>
<div class="legal">authorized-scope only · targets you own or hold written approval to test.</div>
</body></html>"""
