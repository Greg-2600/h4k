"""Backlog #64: reachability filter — import-graph prunes dead code."""

from __future__ import annotations

from typing import Any

from services.reachability import analyze, sandbox_result

PY = {
    "main.py": "import util\nprint(util.run())\n",
    "util.py": "import json\ndef run():\n    return json.dumps(1)\n",
    "legacy.py": "import os\ndef old():\n    return os.getcwd()\n",
    "guard.py": "if __name__ == '__main__':\n    print('x')\n",
}

JS = {
    "index.js": "const u = require('./util');\nmodule.exports = u;\n",
    "util.js": "module.exports = 1;\n",
    "dead.js": "module.exports = 2;\n",
}

PHP = {
    "index.php": "<?php require 'lib.php';\necho hi();\n",
    "lib.php": "<?php function hi() { return 1; }\n",
    "stale.php": "<?php function old() { return 0; }\n",
}


def _files(mapping: dict[str, str]) -> list[dict[str, str]]:
    return [{"path": p, "content": c} for p, c in mapping.items()]


def test_python_chain() -> None:
    out = analyze(_files(PY))
    assert out["files"] == 4
    assert out["entry_guessed"] is True
    assert set(out["entries"]) >= {"main.py", "guard.py"}
    assert set(out["reachable"]) == {"main.py", "util.py", "guard.py"}
    assert out["unreachable"] == ["legacy.py"]
    assert out["unresolved"] == [
        {"file": "util.py", "import": "json"},
        {"file": "legacy.py", "import": "os"},
    ]
    assert out["pruned_ratio"] == 0.25


def test_explicit_entries_and_unknown() -> None:
    out = analyze(_files(PY), entries=["main.py", "nope.py"])
    assert out["entries"] == ["main.py"] and out["entry_guessed"] is False
    assert out["unknown_entries"] == ["nope.py"]
    assert out["unreachable"] == ["guard.py", "legacy.py"]


def test_js_and_php() -> None:
    out = analyze(_files(JS))
    assert out["unreachable"] == ["dead.js"]
    out = analyze(_files(PHP))
    assert out["unreachable"] == ["stale.php"]


def test_empty_rejected() -> None:
    import pytest

    with pytest.raises(ValueError):
        analyze([])


def test_sandbox_shape() -> None:
    res = sandbox_result()
    assert res["unreachable"] == ["legacy.py"]
    assert res["pruned_ratio"] == 0.33


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


BUNDLE = "".join(f"=== {p} ===\n{c}" for p, c in PY.items())


def test_reachability_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/source/reachability", json={"bundle": BUNDLE})
    assert r.status_code == 200
    body = r.json()
    assert body["unreachable"] == ["legacy.py"]
    assert body["unreachable_count"] == 1

    assert c.post("/api/source/reachability", json={}).status_code == 400
    assert c.post("/api/source/reachability", json={"bundle": "  "}).status_code == 400
