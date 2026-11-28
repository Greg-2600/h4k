"""Backlog #23: KEV/EPSS enrichment (real snapshot, refreshable)."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from services import kev


def test_enrich_known_cve() -> None:
    out = kev.enrich("cve-2021-44228")
    assert out["kev"] is True
    assert out["due_date"] == "2021-12-24"
    assert float(out["epss"]["score"]) > 0.9


def test_enrich_unknown_cve() -> None:
    out = kev.enrich("CVE-9999-0001")
    assert out == {
        "cve": "CVE-9999-0001",
        "kev": False,
        "epss": None,
        "catalog_date": kev.catalog_date(),
    }


def test_enrich_many_dedups() -> None:
    out = kev.enrich_many(["CVE-2021-44228", "cve-2021-44228", "CVE-9999-1", ""])
    assert out["count"] == 2 and out["kev_count"] == 1


def test_load_bundle_missing_file_returns_empty_default(
    monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setattr(kev, "BUNDLE", tmp_path / "does-not-exist.json")
    assert kev._load_bundle() == {"catalog_date": "", "cves": {}, "source": ""}


def test_load_bundle_reads_json(monkeypatch: Any, tmp_path: Path) -> None:
    payload = {"catalog_date": "2026-01-01", "cves": {}, "source": "test"}
    path = tmp_path / "kev.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(kev, "BUNDLE", path)
    assert kev._load_bundle() == payload


def test_refresh_success_swaps_table(monkeypatch: Any) -> None:
    header = (
        "cveID,vendorProject,product,dueDate,"
        "knownRansomwareCampaignUse,shortDescription"
    )
    rows = [header]
    for i in range(101):
        rows.append(
            f"CVE-2020-{1000 + i:04d},Vendor {i},Product {i},"
            f"2020-01-01,Known,description {i}"
        )
    rows.append("not-a-cve,V,P,D,K,N")
    csv_bytes = ("\n".join(rows) + "\n").encode()
    epss_payload = json.dumps(
        {
            "data": [
                {"cve": "cve-2020-1000", "epss": "0.5", "percentile": "0.9"},
                {"cve": "CVE-9999-9999", "epss": "0.1", "percentile": "0.2"},
            ]
        }
    ).encode()

    calls: list[str] = []

    def fake_urlopen(req: Any, timeout: int = 0) -> Any:
        url = req.full_url
        calls.append(url)
        if url.startswith(kev.EPSS_API_URL):
            return io.BytesIO(epss_payload)
        return io.BytesIO(csv_bytes)

    monkeypatch.setattr(kev.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(kev, "_table", kev._table)
    before = len(kev._table.get("cves", {}))

    out = kev.refresh(timeout=5)

    today = datetime.now(UTC).date().isoformat()
    assert out == {"before": before, "after": 101, "catalog_date": today}
    assert calls[0] == kev.KEV_CSV_URL
    assert len(calls) == 3  # KEV catalog + two EPSS chunks (100 + 1)
    assert all(u.startswith(kev.EPSS_API_URL) for u in calls[1:])

    known = kev.enrich("CVE-2020-1000")
    assert known["kev"] is True
    assert known["vendor"] == "Vendor 0"
    assert known["due_date"] == "2020-01-01"
    assert known["epss"] == {"score": "0.5", "percentile": "0.9", "date": today}
    assert kev._table["cves"]["CVE-2020-1000"]["notes"] == "description 0"
    assert kev.catalog_date() == today

    assert kev.enrich("CVE-2020-1099")["kev"] is True
    assert kev.enrich("CVE-9999-9999")["kev"] is False
    assert kev.enrich("NOT-A-CVE")["kev"] is False


def test_refresh_keeps_table_on_failure(monkeypatch: Any) -> None:
    import urllib.request

    def boom(*a: Any, **k: Any) -> Any:
        raise OSError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    before = len(kev._table.get("cves", {}))
    out = kev.refresh()
    assert out["after"] == before and "error" in out


def test_kev_router() -> None:
    from contextlib import asynccontextmanager

    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.get("/api/kev/check?cve=CVE-2017-0144")
    assert r.status_code == 200 and r.json()["kev"] is True
    assert c.get("/api/kev/check").status_code == 400
    r = c.post("/api/kev/enrich", json={"cves": ["CVE-2021-44228", "nope"]})
    assert r.status_code == 200 and r.json()["kev_count"] == 1
    assert c.post("/api/kev/enrich", json={"cves": "x"}).status_code == 400
