"""Tests for the Metasploit RPC wrapper's module catalogue handling.

These pin the shape of the pymetasploit3 API we depend on: the module
catalogue lives in one attribute per type (`modules.exploits`, ...), and a
module's `options` may be a dict *or* a list depending on the version. A
silent empty catalogue means "no exploits found" on a perfectly good
Metasploit, so it is worth a test.
"""

from typing import ClassVar

import pytest
from services.msfrpc import MsfClient


class FakeModule:
    def __init__(self, name, description="", options=None):
        self.name = name
        self.description = description
        self.options = options if options is not None else {}


class FakeModuleManager:
    """Mimics pymetasploit3's ModuleManager (current shape)."""

    def __init__(self):
        self.exploits = [
            "multi/handler",
            "linux/ssh/openssh_auth_bypass",
            "linux/http/apache_rce",
            "windows/ssh/putty_msg_debug",
        ]
        self.auxiliary = ["scanner/discovery/arp_sweep"]
        self.post = []
        self.used: list[str] = []

    def use(self, mtype, mname):
        self.used.append(mname)
        return FakeModule(mname, description=f"desc for {mname}", options=["RHOSTS"])


class FakeLegacyModuleManager:
    """Older pymetasploit3 exposed a module_types dict."""

    def __init__(self):
        self.module_types = {"exploit": ["multi/handler"]}

    def use(self, mtype, mname):
        return FakeModule(mname)


class FakeExecModule(FakeModule):
    """Captures datastore assignment + the execute() payload kwarg."""

    def __init__(self):
        super().__init__("exploit/test", options=["RHOSTS", "LPORT"])
        self.datastore: dict = {}
        self.execute_kwargs: dict | None = None

    def __setitem__(self, key, value):
        if key == "PAYLOAD":
            raise ValueError("Invalid option 'PAYLOAD'.")
        self.datastore[key] = value

    def execute(self, *a, **k):
        self.execute_kwargs = dict(k)
        return {"job_id": 4}


@pytest.fixture()
def client():
    msf = MsfClient("127.0.0.1", 55553, "pw")

    class _Modules:
        def __init__(self, manager):
            self._m = manager

        def __getattr__(self, item):
            return getattr(self._m, item)

    class _Core:
        version: ClassVar[dict[str, str]] = {"version": "6.5.0"}

    class _Client:
        def __init__(self, manager):
            self.modules = _Modules(manager)
            self.core = _Core()

    msf._client = _Client(FakeModuleManager())
    return msf


def test_list_modules_reads_the_per_type_attribute(client):
    assert "linux/ssh/openssh_auth_bypass" in client.list_modules("exploit")
    assert client.list_modules("auxiliary") == ["scanner/discovery/arp_sweep"]


def test_list_modules_falls_back_to_module_types():
    msf = MsfClient("127.0.0.1", 55553, "pw")

    class _Modules:
        def __getattr__(self, item):
            return getattr(FakeLegacyModuleManager(), item)

    class _Core:
        version: ClassVar[dict[str, str]] = {"version": "6.5.0"}

    class _Client:
        def __init__(self):
            self.modules = _Modules()
            self.core = _Core()

    msf._client = _Client()
    assert msf.list_modules("exploit") == ["multi/handler"]


def test_get_module_info_handles_list_options(client):
    info = client.get_module_info("exploit", "linux/ssh/openssh_auth_bypass")
    assert info["fullname"] == "linux/ssh/openssh_auth_bypass"
    assert info["options"] == ["RHOSTS"]


def test_find_exploits_filters_by_service(client):
    found = client.find_exploits(service="ssh")
    names = [f["fullname"] for f in found]
    assert "linux/ssh/openssh_auth_bypass" in names
    assert "linux/http/apache_rce" not in names


def test_find_exploits_adds_the_port(client):
    found = client.find_exploits(service="ssh", port=22)
    assert found
    assert all(f["port"] == 22 for f in found)


def test_find_exploits_without_filter_returns_everything(client):
    assert len(client.find_exploits()) == 4


class FakeRpcClient:
    """Records raw msfrpcd calls (module.execute with a datastore)."""

    def __init__(self):
        self.calls: list = []

    def call(self, method, args):
        self.calls.append((method, args))
        return {"job_id": 4}


def test_execute_routes_payload_keys_to_raw_rpc(client):
    """PAYLOAD/LHOST/LPORT are payload-datastore keys, not module options:
    assigning them on the module object raises "Invalid option". They must
    travel as datastore in the raw module.execute RPC instead."""
    rpc = FakeRpcClient()
    client._client.call = rpc.call
    res = client.execute(
        "exploit",
        "unix/webapp/zoneminder_lang_exec",
        {"RHOSTS": "192.168.1.84", "PAYLOAD": "cmd/unix/bind_perl", "LPORT": 4445},
    )
    assert res == {"job_id": 4}
    assert rpc.calls == [
        (
            "module.execute",
            [
                "exploit",
                "unix/webapp/zoneminder_lang_exec",
                {
                    "RHOSTS": "192.168.1.84",
                    "PAYLOAD": "cmd/unix/bind_perl",
                    "LPORT": 4445,
                },
            ],
        )
    ]


def test_execute_without_payload_keys_uses_module_objects(client):
    mod = FakeExecModule()
    client._client.modules._m.use = lambda mtype, mname: mod
    client.execute("exploit", "x", {"RHOSTS": "h"})
    assert mod.execute_kwargs == {}
    assert mod.datastore == {"RHOSTS": "h"}


def test_check_uses_raw_rpc_not_module_object(client):
    """pymetasploit3 shadows Module.check with a bool from module info, so the
    wrapper must call module.check over RPC instead of mod.check()."""
    calls = []

    def fake_call(method, args):
        calls.append((method, args))
        if method == "module.check":
            return {"job_id": 4, "uuid": "abc"}
        # live shape: verdict nests under result
        return {
            "status": "completed",
            "result": {"code": "Appears", "message": "looks good"},
        }

    client._client.call = fake_call
    res = client.check("exploit", "x", {"RHOSTS": "h"})
    assert res["result"]["code"] == "Appears"
    assert calls[0][0] == "module.check"
    assert calls[0][1][2]["RHOSTS"] == "h"
    assert any(c[0] == "module.results" and c[1] == ["abc"] for c in calls)
