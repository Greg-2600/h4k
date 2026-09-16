# h4k FastAPI application: serves the web UI and the JSON API.
# Binds to 0.0.0.0:3137 (set via uvicorn in entrypoint.sh).
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Allow flat imports (from schemas import ...) since this file lives in api/.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from routers import scan as scan_router

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
ROOT_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    host = os.environ.get("MSF_HOST", "127.0.0.1")
    port = int(os.environ.get("MSF_PORT", "55553"))
    password = os.environ.get("MSF_PASSWORD", "h4k_msf_rocks")
    # Write the shared client into app_state so routers can import it.
    import app_state
    from services.cve_lookup import CveDb
    from services.msfrpc import MsfClient

    app_state.msf_client = MsfClient(host, port, password)
    # Load the local CVE database.
    app_state.cve_db = CveDb()
    # Optional refresh if network is available (keeps bundled snapshot otherwise).
    if os.environ.get("H4K_REFRESH_CVE", "1") == "1":
        app_state.cve_db.refresh()
    yield


app = FastAPI(title="h4k", lifespan=lifespan)

app.include_router(scan_router.router)

# Serve the plain HTML/JS frontend.
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


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
