"""Backlog #51: corpus sync — shared corpus dir across runs."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest
from services.corpus import (
    MAX_ENTRY_BYTES,
    add_entry,
    corpus_dir,
    delete_entry,
    import_bytes_batch,
    list_entries,
    read_bytes,
    read_entry,
)


def test_add_list_get_delete(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    assert list_entries() == {"entries": [], "count": 0, "bytes": 0}
    entry = add_entry(b"AAAA", name="seed-a", source="run-1", tags=["http"])
    sha = hashlib.sha256(b"AAAA").hexdigest()
    assert entry["sha"] == sha and entry["deduped"] is False
    assert read_bytes(sha) == b"AAAA"
    assert read_entry(sha)["name"] == "seed-a"
    # Dedup merges tags instead of storing twice.
    again = add_entry(b"AAAA", tags=["fuzz"])
    assert again["deduped"] is True
    assert sorted(read_entry(sha)["tags"]) == ["fuzz", "http"]
    assert list_entries()["count"] == 1
    assert read_bytes("f" * 64) is None
    assert read_entry("f" * 64) is None
    assert delete_entry(sha) is True
    assert delete_entry(sha) is False
    assert list_entries()["count"] == 0


def test_validation(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    with pytest.raises(ValueError):
        add_entry(b"")
    with pytest.raises(ValueError):
        add_entry(b"x" * (MAX_ENTRY_BYTES + 1))
    with pytest.raises(ValueError):
        read_bytes("../evil")
    with pytest.raises(ValueError):
        delete_entry("zz")
    assert corpus_dir().is_dir()


def test_import_batch(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    out = import_bytes_batch(
        [
            {"data": "hello", "name": "t"},
            {"data_b64": base64.b64encode(b"raw-bytes").decode(), "tags": ["bin"]},
            {"data": "hello"},
            "nope",
            {},
        ],
        source="run-9",
    )
    assert out["added"] == 2 and out["deduped"] == 1
    assert len(out["errors"]) == 2
    assert list_entries()["count"] == 2


def _client(tmp_path: Any, monkeypatch: Any) -> Any:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_corpus_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    assert c.get("/api/corpus").json() == {"entries": [], "count": 0, "bytes": 0}

    r = c.post("/api/corpus", json={"data": "AAAA", "name": "a"})
    assert r.status_code == 200
    sha = r.json()["sha"]
    assert r.json()["deduped"] is False
    assert c.post("/api/corpus", json={"data": "AAAA"}).json()["deduped"] is True
    assert c.get("/api/corpus").json()["count"] == 1

    r = c.get(f"/api/corpus/{sha}")
    assert r.status_code == 200 and r.content == b"AAAA"
    assert c.get(f"/api/corpus/{'f' * 64}").status_code == 404
    assert c.get("/api/corpus/nothex").status_code == 400

    assert c.post("/api/corpus", json={}).status_code == 400
    assert c.post("/api/corpus", json={"data_b64": "!!!"}).status_code == 400

    r = c.post(
        "/api/corpus/import",
        json={"items": [{"data": "one"}, {"data_b64": "!!!"}], "source": "run-2"},
    )
    assert r.status_code == 200
    assert r.json()["added"] == 1 and len(r.json()["errors"]) == 1
    assert c.post("/api/corpus/import", json={"items": []}).status_code == 400

    assert c.delete(f"/api/corpus/{sha}").json() == {"deleted": sha}
    assert c.delete(f"/api/corpus/{sha}").status_code == 404
    assert c.delete("/api/corpus/nothex").status_code == 400
    assert c.get("/api/corpus").json()["count"] == 1
