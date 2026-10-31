"""Regression: the password attack must not litter the working directory.

`hydra -o -` writes to a file literally named "-" -- the classic gotcha.
We parse hydra's stdout instead.
"""

from routers import scan as scan_router


def test_pass_attack_argv_has_no_output_file(monkeypatch):
    seen = {}

    class _Runner:
        def run_tool(self, tool, argv, timeout=300):
            seen["tool"] = tool
            seen["argv"] = list(argv)
            return {
                "tool": "hydra",
                "status": "ok",
                "stdout": "[22][ssh] host: 10.0.0.5   login: root   password: toor\n",
                "stderr": "",
                "rc": 0,
                "elapsed": 1.0,
                "timed_out": False,
            }

    monkeypatch.setattr("services.toolkit.ToolkitRunner", lambda *a, **k: _Runner())
    job = {
        "id": "t",
        "host": "10.0.0.5",
        "service": "ssh",
        "port": 22,
        "status": "running",
        "progress": 0.0,
        "message": "",
        "found": [],
        "attempts": 0,
        "log": [],
        "error": None,
        "created": "",
    }
    scan_router._run_pass_attack(job, "10.0.0.5", "ssh", 22, None, None)
    assert seen["tool"] == "hydra"
    assert "-o" not in seen["argv"]
    assert "-" not in seen["argv"]
    # the hit is still parsed out of stdout
    assert job["found"]
    assert job["found"][0]["user"] == "root"
    assert job["found"][0]["password"] == "toor"
