# Provide the flat-import package root (h4k/api) on sys.path for tests.
import os
import sys
from pathlib import Path

# tests/conftest.py -> repo root
REPO = Path(__file__).resolve().parent.parent
API_PKG = REPO / "h4k" / "api"
CVE_DATA = REPO / "h4k" / "data" / "cves.json"

# Put the package root first so `from schemas import ...` etc. resolve.
sys.path.insert(0, str(API_PKG))

# Tests run offline: don't attempt a network CVE refresh.
os.environ.setdefault("H4K_REFRESH_CVE", "0")
