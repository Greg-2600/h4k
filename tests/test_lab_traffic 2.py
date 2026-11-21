# Lab traffic kit (#87): packet builders, parsers, target policy, bounded
# generation, background jobs, and the HTTP API. All servers are local sockets.
import socket
import struct
import threading
import time
from contextlib import asynccontextmanager, suppress

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services import lab_traffic, wire


class TcpServer:
    def __init__(self, handler, *, read_first: bool = True):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.read_first = read_first
        self.handler = handler
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(1)
                    if self.read_first:
                        conn.recv(4096)
                    conn.sendall(self.handler())
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        with suppress(OSError):
            self.sock.close()


class UdpServer:
    def __init__(self, handler):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.handler = handler
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                self.sock.sendto(self.handler(data), addr)
            except OSError:
                return

    def close(self):
        self._stop.set()
        with suppress(OSError):
            self.sock.close()


HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nServer: lab-http/1.0\r\nContent-Type: text/html\r\n"
    b"Content-Length: 34\r\nConnection: close\r\n\r\n"
    b"<html><title>Lab</title></html>"
)


def _dns_response(data: bytes) -> bytes:
    txid = data[:2]
    question = data[12:]
    header = txid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"
    return header + question + answer


@pytest.fixture()
def client(monkeypatch):
    import app_state

    class _CveStub:
        cves: tuple = ()
        path = "stub.json"

        def refresh(self) -> bool:
            return False

    app_state.msf_client = None
    app_state.cve_db = _CveStub()  # type: ignore[assignment]
    app_state.active_engagement_id = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    main_module.reset_auth_cache()
    yield TestClient(main_module.app)
    main_module.reset_auth_cache()


# ---------------------------------------------------------------------------
# Builders / policy
# ---------------------------------------------------------------------------
def test_packet_builders_are_well_formed():
    dns = lab_traffic.build_dns_query("dc01.corp.lab", txid=0x1234)
    assert dns[:2] == b"\x12\x34"
    assert dns[-4:] == b"\x00\x01\x00\x01"
    mqtt = lab_traffic.build_mqtt_connect("h4k-test")
    assert mqtt[0] == 0x10 and b"MQTT" in mqtt
    coap = lab_traffic.build_coap_get("/temp/now")
    assert coap[0] == 0x40 and b"temp" in coap
    modbus = lab_traffic.build_modbus_read(start=2, count=1)
    assert struct.unpack("!HHHB", modbus[:7])[2] == 6
    assert modbus[7] == 0x03
    assert b"M-SEARCH" in lab_traffic.build_ssdp_search()
    assert lab_traffic.build_smb2_negotiate()[4:8] == b"\xfeSMB"


def test_parsers():
    assert lab_traffic.parse_dns_rcode(_dns_response(b"\x00\x00"))["rcode"] == 0
    assert lab_traffic.parse_mqtt_connack(b"\x20\x02\x00\x00")["accepted"] is True
    assert lab_traffic.parse_mqtt_connack(b"\x20\x02\x00\x05")["accepted"] is False
    assert lab_traffic.parse_mqtt_connack(b"") == {"connack": False}
    modbus = struct.pack("!HHHB", 1, 0, 5, 1) + b"\x03\x02\x00\x2a"
    assert lab_traffic.parse_modbus(modbus)["values"] == [42]
    error = struct.pack("!HHHB", 1, 0, 3, 1) + b"\x83\x02"
    assert lab_traffic.parse_modbus(error)["exception"] == 2


def test_lab_only_target_policy():
    assert wire.is_lab_address("127.0.0.1")
    assert wire.is_lab_address("10.1.2.3")
    assert wire.is_lab_address("192.168.1.5")
    assert wire.is_lab_address("169.254.1.1")
    assert not wire.is_lab_address("8.8.8.8")
    assert wire.check_lab_target("127.0.0.1") == ["127.0.0.1"]
    with pytest.raises(ValueError, match="public"):
        wire.check_lab_target("8.8.8.8")
    assert wire.check_lab_target("8.8.8.8", allow_public=True) == ["8.8.8.8"]
    with pytest.raises(ValueError):
        wire.parse_target("")


def test_parse_target_forms():
    assert wire.parse_target("host:8080").port == 8080
    assert wire.parse_target("10.0.0.1", default_port=53).port == 53
    assert wire.parse_target("[::1]:8443").host == "::1"


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------
def test_http_traffic_generation():
    server = TcpServer(lambda: HTTP_RESPONSE)
    try:
        result = lab_traffic.TrafficRunner().run(
            "web", f"127.0.0.1:{server.port}", count=3, rate_per_s=100, seed=1
        )
    finally:
        server.close()
    summary = result["summary"]
    assert summary["events"] == 3
    assert summary["sent_bytes"] > 0
    assert summary["by_protocol"]["http"]["total"] >= 1
    assert len(result["events"]) == 3


def test_dns_traffic_generation():
    server = UdpServer(_dns_response)
    try:
        result = lab_traffic.TrafficRunner().run(
            "dns", f"127.0.0.1:{server.port}", count=2, rate_per_s=100, seed=2
        )
    finally:
        server.close()
    assert result["summary"]["events"] == 2
    assert result["summary"]["by_protocol"]["dns"]["ok"] == 2
    assert "rcode=0" in result["events"][0]["status"]


def test_bad_profile_and_public_target_are_rejected():
    with pytest.raises(ValueError, match="unknown traffic profile"):
        lab_traffic.TrafficRunner().run("nope", "127.0.0.1")
    with pytest.raises(ValueError, match="public"):
        lab_traffic.TrafficRunner().run("web", "8.8.8.8", count=1)


def test_stop_event_ends_generation_early():
    event = threading.Event()
    event.set()
    result = lab_traffic.TrafficRunner(stop_event=event).run(
        "dns", "127.0.0.1", count=100, rate_per_s=100
    )
    assert result["summary"]["stopped"] is True
    assert result["summary"]["events"] == 0


def test_duration_bound():
    server = UdpServer(_dns_response)
    try:
        started = time.monotonic()
        result = lab_traffic.TrafficRunner().run(
            "dns", f"127.0.0.1:{server.port}", count=999, duration_s=0.25, rate_per_s=50
        )
    finally:
        server.close()
    assert time.monotonic() - started < 5
    assert result["summary"]["events"] < 999


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
def test_api_profiles_and_validation(client):
    profiles = client.get("/api/lab/traffic/profiles").json()["profiles"]
    assert {p["name"] for p in profiles} >= {"web", "dns", "iot", "mixed"}
    assert client.post("/api/lab/traffic/run", json={}).status_code == 400
    assert (
        client.post(
            "/api/lab/traffic/run", json={"profile": "nope", "target": "127.0.0.1"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/lab/traffic/run", json={"profile": "web", "target": "8.8.8.8"}
        ).status_code
        == 400
    )


def test_api_wait_and_background_jobs(client):
    server = TcpServer(lambda: HTTP_RESPONSE)
    try:
        target = f"127.0.0.1:{server.port}"
        sync = client.post(
            "/api/lab/traffic/run",
            json={
                "profile": "web",
                "target": target,
                "count": 2,
                "rate_per_s": 100,
                "wait": True,
            },
        )
        assert sync.status_code == 200
        assert sync.json()["summary"]["events"] == 2

        started = client.post(
            "/api/lab/traffic/run",
            json={"profile": "web", "target": target, "count": 3, "rate_per_s": 100},
        ).json()
        job_id = started["job_id"]
        deadline = time.time() + 5
        job = {}
        while time.time() < deadline:
            job = client.get(f"/api/lab/traffic/{job_id}").json()
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] in {"complete", "stopped"}
        assert job["summary"]["events"] == 3
        listing = client.get("/api/lab/traffic/jobs").json()
        assert any(j["id"] == job_id for j in listing["jobs"])
    finally:
        server.close()


def test_api_stop_and_404(client):
    assert client.post("/api/lab/traffic/nope/stop").status_code == 404
    assert client.get("/api/lab/traffic/nope").status_code == 404


def test_individual_generators():
    import random

    rng = random.Random(1)

    server = TcpServer(lambda data=None: b"SSH-2.0-lab\r\n", read_first=False)
    try:
        out = lab_traffic._do_banner(wire.Target("127.0.0.1", server.port), rng)
        assert out["ok"] is True and "SSH" in out["status"]
    finally:
        server.close()

    server = TcpServer(lambda data=None: b"\x02\x00\x00\x00")
    try:
        out = lab_traffic._do_smb(wire.Target("127.0.0.1", server.port), rng)
        assert out["sent"] > 0
    finally:
        server.close()

    server = TcpServer(lambda data=None: b"\x20\x02\x00\x00")
    try:
        out = lab_traffic._do_mqtt(wire.Target("127.0.0.1", server.port), rng)
        assert "mqtt rc=0" in out["status"]
    finally:
        server.close()

    modbus = struct.pack("!HHHB", 1, 0, 5, 1) + b"\x03\x02\x00\x2a"
    server = TcpServer(lambda data=None: modbus)
    try:
        out = lab_traffic._do_modbus(wire.Target("127.0.0.1", server.port), rng)
        assert "modbus fc=3" in out["status"]
    finally:
        server.close()

    server = UdpServer(lambda data: b"\x60\x45\x00\x01</temp>")
    try:
        out = lab_traffic._do_coap(wire.Target("127.0.0.1", server.port), rng)
        assert out["received"] > 0
    finally:
        server.close()

    server = UdpServer(lambda data: b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n")
    try:
        out = lab_traffic._do_ssdp(wire.Target("127.0.0.1", server.port), rng)
        assert out["ok"] is True
    finally:
        server.close()


def test_tls_and_http_generators_report_errors_without_raising():
    import random

    rng = random.Random(2)
    server = TcpServer(lambda data=None: HTTP_RESPONSE)
    try:
        result = lab_traffic._do_tls(wire.Target("127.0.0.1", server.port), rng)
        assert "ok" in result
        result = lab_traffic._do_http(wire.Target("127.0.0.1", server.port), rng)
        assert result["status"].startswith("200")
    finally:
        server.close()


def test_wire_error_and_helper_branches(monkeypatch):
    with pytest.raises(ValueError, match="cannot resolve"):
        wire.resolve_host("no-such-host.invalid")
    with pytest.raises(ValueError, match="malformed IPv6"):
        wire.parse_target("[::1")
    with pytest.raises(ValueError, match="target is required"):
        wire.parse_target("  ")

    # force resolve to return a public address, then allow it explicitly
    monkeypatch.setattr(wire, "resolve_host", lambda host: ["8.8.8.8"])
    assert wire.check_lab_target("example", allow_public=True) == ["8.8.8.8"]

    # connection refused is reported, never raised
    result = wire.tcp_exchange("127.0.0.1", 1, b"x", timeout=0.2)
    assert result["ok"] is False and result["error"]
    result = wire.udp_exchange("127.0.0.1", 1, b"x", timeout=0.2)
    assert result["ok"] is False
    result = wire.http_get("127.0.0.1", 1, timeout=0.2, tls=True)
    assert result["ok"] is False
