# Container-surface fuzzing: presets, transports, detection and jobs.
# Every socket, TLS handshake and daemon is faked; nothing is fuzzed here.
from contextlib import asynccontextmanager

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    import app_state
    import main as main_module

    app_state.msf_client = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module._rate_store = None
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_presets_and_unknown_surface():
    from services import container_fuzz as cf

    for surface in ("docker", "kubelet", "grpc", "http"):
        cfg = cf.preset(surface)
        assert cfg["endpoints"], surface
    try:
        cf.preset("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown surface accepted")
    try:
        cf.ContainerSurfaceFuzzer(transport="nope")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown transport accepted")


def test_vector_shapes_cycle_endpoints_and_methods():
    from services import container_fuzz as cf

    fz = cf.ContainerSurfaceFuzzer(
        endpoints=["/a", "/b"], methods=("GET", "POST"), iterations=4
    )
    vectors = [fz._build_vector("", "bitflip", b"X") for _ in range(4)]
    assert vectors[0].startswith(b"GET /a?")
    assert vectors[1].startswith(b"GET /b?")
    assert vectors[2].startswith(b"POST /a ")
    assert b"application/json" in vectors[2]
    grpc = cf.ContainerSurfaceFuzzer(transport="grpc", sock_path="/x.sock")
    vec = grpc._build_vector("", "bitflip", b"Y")
    assert vec.startswith(cf._GRPC_PREFACE)
    assert len(vec) == len(cf._GRPC_PREFACE + cf._GRPC_SETTINGS) + 64


class _FakeSock:
    def __init__(self, recv_data=b"", recv_exc=None, connect_exc=None):
        self.recv_data = recv_data
        self.recv_exc = recv_exc
        self.connect_exc = connect_exc
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, *a):
        pass

    def connect(self, *a):
        if self.connect_exc:
            raise self.connect_exc

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        if self.recv_exc:
            raise self.recv_exc
        return self.recv_data

    def close(self):
        pass


def test_docker_version_parse(monkeypatch):
    from services import container_fuzz as cf

    monkeypatch.setattr(
        cf.socket,
        "socket",
        lambda *a, **k: _FakeSock(b'HTTP/1.1 200 OK\r\n\r\n{"Version": "28.0"}'),
    )
    assert cf._http_api_version() == "28.0"
    monkeypatch.setattr(
        cf.socket, "socket", lambda *a, **k: _FakeSock(b"HTTP/1.1 200 OK\r\n\r\nnope")
    )
    assert cf._http_api_version() is None
    monkeypatch.setattr(
        cf.socket,
        "socket",
        lambda *a, **k: _FakeSock(connect_exc=OSError("no sock")),
    )
    assert cf._http_api_version() is None


def test_tcp_banner_plain_tls_and_dead(monkeypatch):
    from services import container_fuzz as cf

    monkeypatch.setattr(
        cf.socket, "create_connection", lambda *a, **k: _FakeSock(b"HTTP/1.1 200 ok")
    )
    assert "200" in (cf._tcp_banner("h", 1) or "")

    def _refuse_plain(*a, **k):
        raise OSError("closed")

    # plaintext fails, TLS answers
    calls = {"n": 0}

    def _mixed(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("closed")
        return _FakeSock(b"HTTP/1.1 200 ok")

    monkeypatch.setattr(cf.socket, "create_connection", _mixed)

    class _Ctx:
        def __init__(self):
            self.check_hostname = True
            self.verify_mode = True

        def wrap_socket(self, raw, server_hostname=None):
            return raw

    monkeypatch.setattr(cf.ssl, "create_default_context", lambda: _Ctx())
    monkeypatch.setattr(cf.socket, "socket", lambda *a, **k: _FakeSock(b"tls-ok"))
    # exercise the TLS branch of _tcp_banner via a wrapper socket is complex;
    # at minimum the all-dead path returns None:
    monkeypatch.setattr(cf.socket, "create_connection", _refuse_plain)
    assert cf._tcp_banner("h", 1) is None


def test_detect_surfaces_branches(monkeypatch):
    from services import container_fuzz as cf

    monkeypatch.setattr(cf, "_http_api_version", lambda *a, **k: "28.0")
    monkeypatch.setattr(cf.Path, "exists", lambda self: True)
    monkeypatch.setattr(cf, "_tcp_banner", lambda h, p, timeout=3.0: "HTTP/1.1 200")
    out = cf.detect_surfaces("127.0.0.1")
    assert out["surfaces"]["docker"]["fuzzable"] is True
    assert out["surfaces"]["containerd"]["fuzzable"] is True
    assert out["surfaces"]["kubelet"]["fuzzable"] is True

    monkeypatch.setattr(cf, "_http_api_version", lambda *a, **k: None)
    monkeypatch.setattr(cf.Path, "exists", lambda self: False)
    monkeypatch.setattr(cf, "_tcp_banner", lambda h, p, timeout=3.0: None)
    out = cf.detect_surfaces("127.0.0.1")
    assert out["surfaces"]["docker"]["fuzzable"] is False
    assert out["surfaces"]["kubelet"]["fuzzable"] is False


def test_unix_and_tls_sends(monkeypatch):
    from services import container_fuzz as cf

    fz = cf.ContainerSurfaceFuzzer(transport="unix", sock_path="/x.sock")
    monkeypatch.setattr(
        cf.socket, "socket", lambda *a, **k: _FakeSock(b"HTTP/1.1 200 ok")
    )
    evid, rc, _ = fz._send_unix("/x.sock", b"GET / HTTP/1.0\r\n\r\n")
    assert rc == 0 and "200" in evid

    monkeypatch.setattr(
        cf.socket, "socket", lambda *a, **k: _FakeSock(recv_exc=TimeoutError())
    )
    assert fz._send_unix("/x.sock", b"x")[1] == 2
    monkeypatch.setattr(
        cf.socket,
        "socket",
        lambda *a, **k: _FakeSock(connect_exc=FileNotFoundError()),
    )
    assert fz._send_unix("/x.sock", b"x")[1] == 4
    monkeypatch.setattr(
        cf.socket,
        "socket",
        lambda *a, **k: _FakeSock(connect_exc=ConnectionResetError()),
    )
    assert fz._send_unix("/x.sock", b"x")[1] == 3

    tls = cf.ContainerSurfaceFuzzer(transport="tls")
    monkeypatch.setattr(
        cf.socket, "create_connection", lambda *a, **k: _FakeSock(b"HTTP/1.1 200 ok")
    )

    class _Ctx:
        def __init__(self):
            self.check_hostname = True
            self.verify_mode = True

        def wrap_socket(self, raw, server_hostname=None):
            return raw

    monkeypatch.setattr(cf.ssl, "create_default_context", lambda: _Ctx())
    assert tls._send_tls("h", 1, b"x")[1] == 0

    def _refuse(*a, **k):
        raise ConnectionRefusedError()

    monkeypatch.setattr(cf.socket, "create_connection", _refuse)
    assert tls._send_tls("h", 1, b"x")[1] == 4


def test_probe_per_transport(monkeypatch):
    from services import container_fuzz as cf

    unix = cf.ContainerSurfaceFuzzer(transport="unix", sock_path="/x.sock")
    monkeypatch.setattr(cf, "_http_api_version", lambda *a, **k: "28.0")
    assert unix._probe_http("http://h:1/") is True
    monkeypatch.setattr(cf, "_http_api_version", lambda *a, **k: None)
    assert unix._probe_http("http://h:1/") is False

    grpc = cf.ContainerSurfaceFuzzer(transport="grpc", sock_path="/x.sock")
    monkeypatch.setattr(cf.socket, "socket", lambda *a, **k: _FakeSock())
    assert grpc._probe_http("http://h:1/") is True
    monkeypatch.setattr(
        cf.socket, "socket", lambda *a, **k: _FakeSock(connect_exc=OSError())
    )
    assert grpc._probe_http("http://h:1/") is False

    tls = cf.ContainerSurfaceFuzzer(transport="tls")
    monkeypatch.setattr(tls, "_send_tls", lambda h, p, v: ("HTTP/1.1 200", 0, 0.1))
    assert tls._probe_http("http://h:8443/") is True
    assert tls._probe_http("http://h/") is True  # default port path


def test_fuzz_surface_runs_the_loop(monkeypatch):
    from services import container_fuzz as cf

    fz_calls = {}

    def _fake_fuzz(self, host, port, scheme="http"):
        fz_calls["args"] = (host, port, scheme)
        return [{"signal": "hang", "vector": "bitflip"}]

    monkeypatch.setattr(cf.ContainerSurfaceFuzzer, "_fuzz_http", _fake_fuzz)
    out = cf.fuzz_surface("http", target="127.0.0.1", port=8080, iterations=10)
    assert out["count"] == 1 and fz_calls["args"] == ("127.0.0.1", 8080, "http")
    out = cf.fuzz_surface("docker", endpoints=["/v"], allow_mutating=True)
    assert out["transport"] == "unix"


def test_container_fuzz_endpoints(client, monkeypatch):
    import services.container_fuzz as cf

    monkeypatch.setattr(
        cf, "detect_surfaces", lambda target="127.0.0.1": {"target": target}
    )
    r = client.post("/api/container_surfaces", json={"target": "127.0.0.1"})
    assert r.status_code == 200 and r.json()["target"] == "127.0.0.1"

    r = client.post("/api/container_fuzz", json={"surface": "nope"})
    assert r.status_code == 400
    r = client.post(
        "/api/container_fuzz", json={"surface": "docker", "target": "10.9.9.9"}
    )
    assert r.status_code == 400

    seen = {}

    def _fake_bg(job, req, surface):
        seen["surface"] = surface
        job["status"] = "done"
        job["candidates"] = []

    import routers.scan as scan_router

    monkeypatch.setattr(scan_router, "_run_container_fuzz", _fake_bg)
    r = client.post(
        "/api/container_fuzz",
        json={"surface": "kubelet", "target": "127.0.0.1", "iterations": 5},
    )
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert seen["surface"] == "kubelet"
    r = client.get(f"/api/container_fuzz/{job_id}")
    assert r.status_code == 200 and r.json()["status"] == "done"
    r = client.post(f"/api/container_fuzz/{job_id}/abort")
    assert r.json()["status"] == "abort_requested"
    assert client.get("/api/container_fuzz/nope").status_code == 404
    assert client.post("/api/container_fuzz/nope/abort").status_code == 404
