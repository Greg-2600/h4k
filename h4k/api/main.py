# h4k FastAPI application: serves the web UI and the JSON API.
# Binds to 0.0.0.0:3137 (set via uvicorn in entrypoint.sh).
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Allow flat imports (from schemas import ...) since this file lives in api/.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import schemas
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    host = os.environ.get("MSF_HOST", "127.0.0.1")
    port = int(os.environ.get("MSF_PORT", "55553"))
    password = os.environ.get("MSF_PASSWORD", "h4k_msf_rocks")
    # Write the shared client into app_state so routers can import it.
    import app_state
    from services.msfrpc import MsfClient
    app_state.msf_client = MsfClient(host, port, password)
    yield


app = FastAPI(title="h4k", lifespan=lifespan)

from routers import scan as scan_router
app.include_router(scan_router.router)

# Serve the plain HTML/JS frontend.
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index():
    from fastapi.responses import FileResponse
    return FileResponse(WEB_DIR / "index.html")
