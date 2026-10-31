# Fire TV toolkit: ADB wrapper, recon, mDNS discovery and all endpoints.
# Every subprocess, socket and HTTP call is faked; nothing touches a TV.
from contextlib import asynccontextmanager

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    import main as main_module

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module._rate_store = None
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


class _Proc:
    def __init__(self, stdout="", stderr="", rc=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = rc


# --------------------------------------------------------------------------
# target normalisation
# --------------------------------------------------------------------------


def test_target_addr_shapes():
    from services.firetv import _target_addr

    assert _target_addr("192.168.1.100") == "192.168.1.100:5555"
    assert _target_addr("192.168.1.100:5555") == "192.168.1.100:5555"
    assert _target_addr("  tv.lan:4321 ") == "tv.lan:4321"
    for bad in ("", "   ", "-rf", "--help"):
        try:
            _target_addr(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted {bad!r}")


# --------------------------------------------------------------------------
# plumbing
# --------------------------------------------------------------------------


def test_run_branches(monkeypatch):
    import subprocess as _sp

    from services import firetv as ft

    svc = ft.FireTVService()
    monkeypatch.setattr(ft.subprocess, "run", lambda *a, **k: _Proc("ok", "", 0))
    assert svc._run(["adb"])["success"] is True

    def _timeout(*a, **k):
        raise _sp.TimeoutExpired(cmd="x", timeout=1, output=b"part", stderr=None)

    monkeypatch.setattr(ft.subprocess, "run", _timeout)
    out = svc._run(["adb"])
    assert out["timed_out"] is True and out["stdout"] == "part"

    def _missing(*a, **k):
        raise FileNotFoundError("nope")

    monkeypatch.setattr(ft.subprocess, "run", _missing)
    assert svc._run(["adb"])["rc"] == -1

    def _boom(*a, **k):
        raise RuntimeError("weird")

    monkeypatch.setattr(ft.subprocess, "run", _boom)
    assert svc._run(["adb"])["rc"] == -1


def test_adb_missing_short_circuits(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    monkeypatch.setattr(ft.shutil, "which", lambda _n: None)
    assert svc._adb("h:5555", "shell")["stderr"] == "adb not installed"
    assert svc.check() == {"installed": False, "version": None}
    assert svc.screenshot("h")["error"] == "adb not installed"


def test_check_reports_version(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    monkeypatch.setattr(ft.shutil, "which", lambda _n: "/usr/bin/adb")
    monkeypatch.setattr(
        ft.subprocess,
        "run",
        lambda *a, **k: _Proc("Android Debug Bridge 1.0.41\n", "", 0),
    )
    out = svc.check()
    assert out["installed"] is True and "1.0.41" in out["version"]
    monkeypatch.setattr(ft.subprocess, "run", lambda *a, **k: _Proc("", "", 0))
    assert svc.check()["version"] == "unknown"


# --------------------------------------------------------------------------
# connection + state
# --------------------------------------------------------------------------


def test_connect_branches(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    assert svc.connect("")["success"] is False
    monkeypatch.setattr(
        ft.FireTVService,
        "_run",
        lambda self, argv, timeout=60: {
            "stdout": "connected to x",
            "stderr": "",
            "success": True,
            "rc": 0,
        },
    )
    out = svc.connect("192.168.1.100")
    assert out["success"] is True and out["needs_on_screen_approval"] is False
    monkeypatch.setattr(
        ft.FireTVService,
        "_run",
        lambda self, argv, timeout=60: {
            "stdout": "failed to connect",
            "stderr": "",
            "success": False,
            "rc": 1,
        },
    )
    out = svc.connect("192.168.1.100")
    assert out["success"] is False and out["needs_on_screen_approval"] is True
    monkeypatch.setattr(
        ft.FireTVService,
        "_run",
        lambda self, argv, timeout=60: {
            "stdout": "already connected; unauthorized",
            "stderr": "",
            "success": True,
            "rc": 0,
        },
    )
    out = svc.connect("192.168.1.100")
    # "connected" is present but so is failure/unauthorized handling
    assert out["unauthorized"] is True


def test_disconnect_and_invalid(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    assert svc.disconnect("")["success"] is False
    monkeypatch.setattr(
        ft.FireTVService,
        "_run",
        lambda self, argv, timeout=60: {
            "stdout": "",
            "stderr": "",
            "success": True,
            "rc": 0,
        },
    )
    assert svc.disconnect("192.168.1.100")["success"] is True


def test_state_branches(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    assert svc.state("")["success"] is False
    # via `adb devices`
    monkeypatch.setattr(
        ft.FireTVService,
        "_run",
        lambda self, argv, timeout=60: {
            "stdout": "List of devices\n192.168.1.100:5555\tdevice\n",
            "stderr": "",
            "success": True,
            "rc": 0,
        },
    )
    assert svc.state("192.168.1.100")["state"] == "device"
    # via get-state fallback
    calls = {"n": 0}

    def _fake(self, argv, timeout=60):
        calls["n"] += 1
        if "devices" in argv:
            return {
                "stdout": "List of devices\n",
                "stderr": "",
                "success": True,
                "rc": 0,
            }
        word = ["device", "unauthorized", "offline"][min(calls["n"] // 2, 2)]
        return _Proc("", word, 0)

    monkeypatch.setattr(ft.FireTVService, "_run", _fake)
    # monkeypatch the inner _adb textual probe instead: simpler to stub _adb
    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: {"stdout": "device", "stderr": ""},
    )
    assert svc.state("192.168.1.100")["state"] == "device"
    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: {"stdout": "", "stderr": "unauthorized"},
    )
    assert svc.state("192.168.1.100")["state"] == "unauthorized"
    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: {"stdout": "offline", "stderr": ""},
    )
    assert svc.state("192.168.1.100")["state"] == "offline"
    # "error: device '<addr>' not found" must NOT read as authorised
    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: {
            "stdout": "",
            "stderr": "error: device '192.168.1.100:5555' not found",
        },
    )
    assert svc.state("192.168.1.100")["state"] == "unknown"


# --------------------------------------------------------------------------
# read-only interrogation
# --------------------------------------------------------------------------


def test_apps_parses_packages_and_focus(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    assert svc.apps("")["success"] is False

    def _fake(self, addr, *args, **kwargs):
        if "dumpsys" in args:
            return {
                "stdout": "  mCurrentFocus=Window{abc com.amazon.tv.launcher}\n",
                "stderr": "",
            }
        return {
            "stdout": "package:/data/app/x.apk=com.example.x\npackage:com.nopath\n",
            "stderr": "",
            "success": True,
        }

    monkeypatch.setattr(ft.FireTVService, "_adb", _fake)
    out = svc.apps("192.168.1.100")
    assert out["count"] == 2
    assert out["packages"][0] == {"package": "com.example.x", "apk": "/data/app/x.apk"}
    assert "mCurrentFocus" in (out["current_focus"] or "")


def test_screenshot_branches(monkeypatch, tmp_path):
    from services import firetv as ft

    svc = ft.FireTVService()
    assert svc.screenshot("")["success"] is False
    monkeypatch.setattr(ft.shutil, "which", lambda _n: "/usr/bin/adb")

    def _timeout(*a, **k):
        raise ft.subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(ft.subprocess, "run", _timeout)
    assert svc.screenshot("h", out_dir=str(tmp_path))["error"] == "screencap timed out"

    class _Bin:
        returncode = 1
        stdout = b""
        stderr = b"error: no devices"

    monkeypatch.setattr(ft.subprocess, "run", lambda *a, **k: _Bin())
    assert svc.screenshot("h", out_dir=str(tmp_path))["success"] is False

    class _Png:
        returncode = 0
        stdout = b"\x89PNG" + b"\x00" * 200
        stderr = b""

    monkeypatch.setattr(ft.subprocess, "run", lambda *a, **k: _Png())
    out = svc.screenshot("h", out_dir=str(tmp_path))
    assert out["success"] is True and out["bytes"] > 100


def test_logcat_bounds_and_truncation(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    assert svc.logcat("")["success"] is False
    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: {
            "stdout": "x" * 30000,
            "stderr": "",
            "success": True,
        },
    )
    out = svc.logcat("h", lines=5)
    assert out["truncated"] is True and len(out["lines"]) <= 5
    # lines clamped to >= 1 even when asked for 0
    out = svc.logcat("h", lines=0)
    assert out["success"] is True


def test_pull_branches(monkeypatch, tmp_path):
    import os

    from services import firetv as ft

    svc = ft.FireTVService()
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    assert svc.pull("", "/x")["success"] is False
    assert svc.pull("h", "")["success"] is False
    assert svc.pull("h", "-rf")["success"] is False

    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: {"stdout": "pulled", "stderr": "", "success": True},
    )
    # dest does not exist -> success False even though adb claimed success
    out = svc.pull("h", "/data/x.apk", local="nope.apk")
    assert out["success"] is False and out["file"] is None
    # pre-create the artifact -> success
    (tmp_path / "firetv").mkdir(exist_ok=True)
    (tmp_path / "firetv" / "x.apk").write_bytes(b"pk")
    out = svc.pull("h", "/data/x.apk", local="x.apk")
    assert out["success"] is True and out["file"].endswith("x.apk")
    os.remove(tmp_path / "firetv" / "x.apk")


# --------------------------------------------------------------------------
# mutating (sandbox-gated)
# --------------------------------------------------------------------------


def test_shell_gated_and_runs(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    monkeypatch.setenv("H4K_SANDBOX", "1")
    assert svc.shell("h", "id")["error"] == "disabled in sandbox mode"
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    assert svc.shell("", "id")["success"] is False
    assert svc.shell("h", "   ")["error"] == "empty command"
    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: {
            "stdout": "uid=2000(shell)",
            "stderr": "",
            "success": True,
            "rc": 0,
        },
    )
    out = svc.shell("h", "id -u")
    assert out["success"] is True and "uid=2000" in out["stdout"]


def test_keyevent_allowlist(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    monkeypatch.setenv("H4K_SANDBOX", "1")
    assert svc.keyevent("h", "HOME")["error"] == "disabled in sandbox mode"
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    assert svc.keyevent("", "HOME")["success"] is False
    assert svc.keyevent("h", "RM -RF")["success"] is False
    assert svc.keyevent("h", "999")["success"] is False
    seen = {}
    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: (seen.__setitem__("args", a), {"success": True})[1],
    )
    assert svc.keyevent("h", "home")["success"] is True
    assert seen["args"][-1] == "HOME"
    assert svc.keyevent("h", "23")["success"] is True


def test_install_branches(monkeypatch, tmp_path):
    from services import firetv as ft

    svc = ft.FireTVService()
    monkeypatch.setenv("H4K_SANDBOX", "1")
    assert svc.install("h", "x.apk")["error"] == "disabled in sandbox mode"
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    assert svc.install("", "x.apk")["success"] is False
    assert svc.install("h", str(tmp_path / "missing.apk"))["success"] is False
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"pk")
    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: {
            "stdout": "Success",
            "stderr": "",
            "success": True,
        },
    )
    assert svc.install("h", str(apk))["success"] is True
    monkeypatch.setattr(
        ft.FireTVService,
        "_adb",
        lambda self, addr, *a, **k: {
            "stdout": "Failure [X]",
            "stderr": "",
            "success": False,
        },
    )
    assert svc.install("h", str(apk))["success"] is False


# --------------------------------------------------------------------------
# recon + mdns
# --------------------------------------------------------------------------


def test_recon_branches(monkeypatch):
    from services import firetv as ft

    svc = ft.FireTVService()
    assert svc.recon("")["success"] is False
    assert svc.recon("-evil")["success"] is False

    def _refused(host_port, timeout=3):
        raise OSError("closed")

    monkeypatch.setattr(ft.socket, "create_connection", _refused)
    out = svc.recon("192.168.1.100")
    assert out["success"] is True and out["adb_state"] in ("unknown", "offline")
    assert out["looks_like_fire_tv"] is False

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _open(host_port, timeout=3):
        if host_port[1] in (5555, 8008):
            return _Conn()
        raise OSError("closed")

    monkeypatch.setattr(ft.socket, "create_connection", _open)

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"model_name": "AFTHA004", "manufacturer": "Amazon"}'

    monkeypatch.setattr(ft.urllib.request, "urlopen", lambda url, timeout=8: _Resp())
    monkeypatch.setattr(
        ft.FireTVService, "state", lambda self, host: {"state": "unauthorized"}
    )
    out = svc.recon("192.168.1.100")
    assert out["looks_like_fire_tv"] is True
    assert out["eureka"]["model_name"] == "AFTHA004"

    def _boom(url, timeout=8):
        raise OSError("no http")

    monkeypatch.setattr(ft.urllib.request, "urlopen", _boom)
    out = svc.recon("192.168.1.100")
    assert "error" in out["eureka"] and out["looks_like_fire_tv"] is True


def test_mdns_discover_branches(monkeypatch):
    from services import firetv as ft

    # socket creation is fine; bind fails (another responder on 5353)
    class _BindFail:
        def setsockopt(self, *a):
            pass

        def bind(self, *a):
            raise OSError("in use")

        def close(self):
            pass

    monkeypatch.setattr(ft.socket, "socket", lambda *a, **k: _BindFail())
    out = ft.mdns_discover(timeout=0.1)
    assert out["success"] is False and "devices" in out

    # multicast join fails
    class _McFail:
        def setsockopt(self, *a):
            if a[1] == ft.socket.IP_ADD_MEMBERSHIP:
                raise OSError("no multicast")

        def bind(self, *a):
            pass

        def close(self):
            pass

    monkeypatch.setattr(ft.socket, "socket", lambda *a, **k: _McFail())
    assert ft.mdns_discover(timeout=0.1)["success"] is False

    # happy path with one announcement + a sendto hiccup tolerated
    blob = b"blah n=Hallie's\x20TV | model=AFTHA004 | model=AFTHA004 end"

    class _Sock:
        def __init__(self):
            self.sent = 0

        def setsockopt(self, *a):
            pass

        def bind(self, *a):
            pass

        def settimeout(self, *a):
            pass

        def sendto(self, *a):
            self.sent += 1
            if self.sent == 2:
                raise OSError("drop me")

        def recvfrom(self, *a):
            if self.sent >= 1:
                self.sent = -99
                return blob, ("192.168.1.100", 5353)
            raise TimeoutError()

        def close(self):
            pass

    monkeypatch.setattr(ft.socket, "socket", lambda *a, **k: _Sock())
    out = ft.mdns_discover(timeout=0.1, queries=["_airplay._tcp.local"])
    assert out["success"] is True
    dev = out["devices"][0]
    assert dev["ip"] == "192.168.1.100"
    assert dev["models"] == ["AFTHA004"]


def test_module_helpers_and_as_text():
    from services import firetv as ft

    assert ft._as_text(None) == ""
    assert ft._as_text(b"ab") == "ab"
    assert ft._as_text("s") == "s"
    # module-level wrappers exist and delegate
    assert callable(ft.firetv_recon) and callable(ft.firetv_connect)


# --------------------------------------------------------------------------
# endpoints
# --------------------------------------------------------------------------


def test_firetv_endpoints(client, monkeypatch):
    import services.firetv as ft

    monkeypatch.setattr(
        ft.FireTVService, "recon", lambda self, t: {"success": True, "target": t}
    )
    r = client.post("/api/firetv/recon", json={"target": "192.168.1.100"})
    assert r.status_code == 200 and r.json()["action"] == "recon"
    r = client.post("/api/firetv/recon", json={"target": "  "})
    assert r.status_code == 400

    monkeypatch.setattr(
        ft, "mdns_discover", lambda *a, **k: {"success": True, "devices": []}
    )
    r = client.post("/api/firetv/mdns")
    assert r.status_code == 200 and r.json()["action"] == "mdns"
    monkeypatch.setattr(
        ft,
        "mdns_discover",
        lambda *a, **k: {"success": False, "error": "nope", "devices": []},
    )
    r = client.post("/api/firetv/mdns")
    assert r.json()["error"] == "nope"

    canned = {"success": True, "stdout": "hi"}
    monkeypatch.setattr(ft.FireTVService, "connect", lambda self, t, p=5555: canned)
    assert (
        client.post("/api/firetv/connect", json={"target": "h"}).json()["success"]
        is True
    )
    monkeypatch.setattr(ft.FireTVService, "disconnect", lambda self, t, p=5555: canned)
    assert (
        client.post("/api/firetv/disconnect", json={"target": "h"}).status_code == 200
    )
    monkeypatch.setattr(ft.FireTVService, "state", lambda self, t, p=5555: canned)
    assert (
        client.post("/api/firetv/state", json={"target": "h"}).json()["success"] is True
    )

    monkeypatch.setattr(
        ft.FireTVService,
        "shell",
        lambda self, t, c, p=5555: {"success": True, "stdout": "uid=0"},
    )
    r = client.post("/api/firetv/shell", json={"target": "h", "command": "id"})
    assert r.json()["output"] == "uid=0"
    assert client.post("/api/firetv/shell", json={"target": "h"}).status_code == 400

    monkeypatch.setattr(ft.FireTVService, "keyevent", lambda self, t, k, p=5555: canned)
    assert (
        client.post(
            "/api/firetv/keyevent", json={"target": "h", "key": "HOME"}
        ).status_code
        == 200
    )
    assert client.post("/api/firetv/keyevent", json={"target": "h"}).status_code == 400

    monkeypatch.setattr(
        ft.FireTVService,
        "apps",
        lambda self, t, p=5555: {
            "success": True,
            "stdout": "",
            "packages": [{"package": "x"}],
        },
    )
    r = client.post("/api/firetv/apps", json={"target": "h"})
    assert r.json()["detail"]["packages"] == [{"package": "x"}]

    monkeypatch.setattr(
        ft.FireTVService,
        "pull",
        lambda self, t, rem, loc=None, p=5555: {
            "success": True,
            "stdout": "",
            "file": "/d/x",
        },
    )
    assert (
        client.post(
            "/api/firetv/pull", json={"target": "h", "remote": "/x"}
        ).status_code
        == 200
    )
    assert client.post("/api/firetv/pull", json={"target": "h"}).status_code == 400

    monkeypatch.setattr(
        ft.FireTVService,
        "screenshot",
        lambda self, t, p=5555: {"success": True, "file": "s.png"},
    )
    assert (
        client.post("/api/firetv/screenshot", json={"target": "h"}).status_code == 200
    )

    monkeypatch.setattr(
        ft.FireTVService,
        "logcat",
        lambda self, t, p=5555, lines=200: {"success": True, "lines": ["a", "b"]},
    )
    r = client.post("/api/firetv/logcat", json={"target": "h"})
    assert r.json()["output"] == "a\nb"

    monkeypatch.setattr(
        ft.FireTVService,
        "install",
        lambda self, t, apk, p=5555: {"success": False, "error": "nope"},
    )
    assert (
        client.post(
            "/api/firetv/install", json={"target": "h", "local": "a.apk"}
        ).status_code
        == 200
    )
    assert client.post("/api/firetv/install", json={"target": "h"}).status_code == 400
