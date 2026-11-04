# h4k FastAPI application: serves the web UI and the JSON API.
# Binds to 0.0.0.0:3137 (set via uvicorn in entrypoint.sh).
import asyncio
import hashlib
import logging
import os
import shutil
import socket
import subprocess
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
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from routers import (
    engagement as engagement_router,
    net as net_router,
    scan as scan_router,
    source as source_router,
    update as update_router,
)

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
# API-key authentication (optional, env-gated)
# ---------------------------------------------------------------------------
# When H4K_API_KEY is set, every API request must carry X-API-Key: <key>.
# When it is unset, authentication is off (solo-operator / test default).


async def _auth_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    from services.auth import api_key as _api_key, is_exempt as _is_exempt

    key = _api_key()
    if key is None:
        # auth disabled -- nothing to check
        return await call_next(request)

    path = request.url.path
    if _is_exempt(path):
        return await call_next(request)

    supplied = request.headers.get("x-api-key")
    if supplied != key:
        # constant-time comparison to avoid timing leaks
        from hmac import compare_digest

        if not (supplied is not None and compare_digest(supplied, key)):
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=401,
                content={"detail": "missing or invalid API key (X-API-Key header)"},
                headers={"WWW-Authenticate": "ApiKey"},
            )
    return await call_next(request)


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


async def _rate_limit_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    global _rate_store
    if _rate_store is None:
        _rate_store = _RateLimitStore()

    # Skip rate limiting for static assets and Swagger docs
    path = request.url.path
    if path.startswith("/static") or path in ("/docs", "/redoc", "/openapi.json"):
        return await call_next(request)

    # Use X-Forwarded-For if behind a proxy, else client IP
    forwarded = request.headers.get("x-forwarded-for", "")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "127.0.0.1")
    )
    ip_key = hashlib.sha256(ip.encode()).hexdigest()[:16]

    if not _rate_store.is_allowed(ip_key):
        # raise HTTPException from raw-ASGI context is NOT rendered by FastAPI's
        # exception handlers — clients would get a bare 500 — so return the
        # 429 response directly
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=429,
            content={
                "detail": f"Rate limit exceeded: {_RATE_LIMIT} req/min. Retry after 60s."
            },
            headers={"Retry-After": "60", "X-RateLimit-Limit": str(_RATE_LIMIT)},
        )

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(_RATE_LIMIT)
    return response


WEB_DIR = Path(__file__).resolve().parent.parent / "web"
ROOT_DIR = Path(__file__).resolve().parent.parent


def _msf_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _relaunch_msfrpcd(host: str, port: int, password: str) -> bool:
    exe = shutil.which("msfrpcd")
    if not exe:
        return False
    try:
        os.makedirs("/var/log/h4k", exist_ok=True)
        # fd intentionally inherited by the daemon process (stays open in child)
        logfile = open("/var/log/h4k/msfrpcd-watchdog.log", "ab")  # noqa: SIM115
        subprocess.Popen(  # nosec B603 - fixed argv, no shell
            [
                exe,
                "-a",
                host,
                "-p",
                str(port),
                "-U",
                "msf",
                "-P",
                password,
                "-S",
                "true",
                "-f",
            ],
            stdout=logfile,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        return True
    except OSError as exc:
        logging.getLogger("h4k").warning("msfrpcd relaunch failed: %s", exc)
        return False


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

    # msfrpcd watchdog: the entrypoint starts the daemon once at boot with
    # no supervisor afterwards. If it dies later the UI shows "msf down"
    # until someone restarts the container. Re-launch it here when the
    # port goes quiet (best-effort, container-local only).
    _msf_task = None
    if not sandbox_enabled() and shutil.which("msfrpcd"):
        _msf_interval = int(os.environ.get("H4K_MSF_WATCHDOG_INTERVAL", "60"))

        async def _msf_watchdog() -> None:
            while True:
                try:
                    if not await asyncio.to_thread(_msf_port_open, host, port):
                        logging.getLogger("h4k").warning(
                            "msfrpcd %s:%s unreachable - relaunching", host, port
                        )
                        await asyncio.to_thread(_relaunch_msfrpcd, host, port, password)
                except Exception as exc:  # pragma: no cover - defensive
                    logging.getLogger("h4k").warning("msf watchdog failed: %s", exc)
                await asyncio.sleep(_msf_interval)

        _msf_task = asyncio.create_task(_msf_watchdog())
    try:
        yield
    finally:
        auto_scan_module.stop()
        if _task is not None:
            _task.cancel()
        if _cve_task is not None:
            _cve_task.cancel()
        if _msf_task is not None:
            _msf_task.cancel()


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
app.middleware("http")(_auth_middleware)
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

# Serve the plain HTML/JS frontend.
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


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
