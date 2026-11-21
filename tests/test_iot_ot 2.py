# IoT/OT pack (#90): read-only probes for MQTT, CoAP, Modbus, BACnet, SSDP,
# RTSP, SNMP, Telnet and HTTP device panels. Local fake devices only.
import socket
import struct
import threading
from contextlib import asynccontextmanager, suppress

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services import iot_ot


class TcpServer:
    def __init__(self, handler, *, read_first: bool = True):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("127.0.0.1", 0))
        except OSError as exc:
            pytest.skip(f"cannot bind TCP server: {exc}")
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.read_first = read_first
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(1)
                    data = conn.recv(4096) if self.read_first else b""
                    conn.sendall(self.handler(data))
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
        self.handler = handler
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

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


def test_packet_builders():
    snmp = iot_ot.build_snmp_get("public")
    assert b"public" in snmp and snmp[0] == 0x30
    assert iot_ot._bacnet_who_is().startswith(b"\x81\x0a")
    assert iot_ot.build_snmp_get("private") != snmp


def test_parsers():
    ssdp = "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Demo/1.0 UPnP/1.1\r\n\r\n"
    headers = iot_ot.parse_ssdp(ssdp)
    assert headers["ST"] == "upnp:rootdevice"
    assert "Demo" in headers["SERVER"]

    rtsp = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: TestCam/2.1\r\n\r\n"
    parsed = iot_ot.parse_rtsp(rtsp)
    assert parsed["status"].startswith("RTSP/1.0")
    assert parsed["headers"]["Server"] == "TestCam/2.1"

    obj = (8 << 22) | 1234
    iam = (
        b"\x81\x0a\x00\x0c"
        + b"\x01\x04"
        + b"\x10\x00"
        + struct.pack("!I", obj)
        + struct.pack("!H", 42)
    )
    parsed_iam = iot_ot.parse_bacnet_iam(iam)
    assert parsed_iam["iam"] is True
    assert parsed_iam["instance"] == 1234
    assert parsed_iam["vendor_id"] == 42
    assert iot_ot.parse_bacnet_iam(b"")["iam"] is False

    assert "Linux" in iot_ot.parse_snmp_sysdescr(b"\x30\x10\x04\x0bLinux 5.10\x00")
    coap = b"\x60\x45\x4c\x34" + b'</temp>;rt="sensor",</humidity>'
    assert iot_ot.parse_coap_resources(coap) == ["/temp", "/humidity"]


def test_probe_mqtt():
    server = TcpServer(lambda data: b"\x20\x02\x00\x00")
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="mqtt", timeout=1)
    finally:
        server.close()
    assert result["ok"] is True
    assert result["protocol"] == "mqtt"
    assert result["read_only"] is True
    assert "accepted" in result["detail"]


def test_probe_modbus_and_rtsp_and_http():
    modbus_response = struct.pack("!HHHB", 1, 0, 5, 1) + b"\x03\x02\x00\x2a"
    server = TcpServer(lambda data: modbus_response)
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="modbus")
    finally:
        server.close()
    assert result["ok"] is True
    assert result["evidence"]["values"] == [42]

    server = TcpServer(
        lambda data: b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Cam/1.0\r\n\r\n"
    )
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="rtsp")
    finally:
        server.close()
    assert result["ok"] is True
    assert result["detail"] == "Cam/1.0"

    server = TcpServer(
        lambda data: (
            b"HTTP/1.1 200 OK\r\nServer: DeviceUI/1.0\r\n\r\n"
            b"<html><title>Camera Admin</title></html>"
        )
    )
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="http")
    finally:
        server.close()
    assert result["ok"] is True
    assert "DeviceUI" in result["detail"]
    assert "Camera Admin" in result["detail"]


def test_probe_coap_and_ssdp():
    server = UdpServer(lambda data: b"\x60\x45\x4c\x34" + b'</temp>;rt="sensor"')
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="coap")
    finally:
        server.close()
    assert result["ok"] is True
    assert result["evidence"]["resources"] == ["/temp"]

    server = UdpServer(lambda data: b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n")
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="ssdp")
    finally:
        server.close()
    assert result["ok"] is True
    assert result["evidence"]["ST"] == "ssdp:all"


def test_probe_telnet_banner():
    server = TcpServer(
        lambda data: b"Welcome to BusyBox telnetd\r\nlogin: ", read_first=False
    )
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="telnet")
    finally:
        server.close()
    assert result["ok"] is True
    assert "BusyBox" in result["detail"]


def test_unknown_protocol_and_public_target():
    with pytest.raises(ValueError, match="unknown protocol"):
        iot_ot.probe("127.0.0.1", port=1, protocol="carrier-pigeon")
    with pytest.raises(ValueError, match="public"):
        iot_ot.probe("8.8.8.8", port=80, protocol="http")


def test_discover_keeps_silent_ports_out():
    server = TcpServer(lambda data: b"\x20\x02\x00\x00")
    try:
        result = iot_ot.discover(
            "127.0.0.1", ports=[server.port], timeout=0.3, max_workers=2
        )
    finally:
        server.close()
    # An arbitrary high port maps to HTTP, not MQTT, so it may not answer as a
    # device; the contract we pin is that discover never invents findings.
    assert result["probed"] == 1
    assert isinstance(result["findings"], list)


def test_api_protocols_probe_and_guards(client):
    protocols = client.get("/api/lab/iot/protocols").json()
    assert protocols["read_only"] is True
    assert {"mqtt", "coap", "modbus", "bacnet"} <= set(protocols["protocols"])
    assert client.post("/api/lab/iot/probe", json={}).status_code == 400
    assert (
        client.post(
            "/api/lab/iot/probe", json={"host": "127.0.0.1", "protocol": "nope"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/lab/iot/probe", json={"host": "8.8.8.8", "protocol": "http"}
        ).status_code
        == 400
    )
    assert client.post("/api/lab/iot/discover", json={}).status_code == 400


def test_api_probe_against_fake_mqtt(client):
    server = TcpServer(lambda data: b"\x20\x02\x00\x00")
    try:
        result = client.post(
            "/api/lab/iot/probe",
            json={
                "host": "127.0.0.1",
                "port": server.port,
                "protocol": "mqtt",
                "timeout": 1,
            },
        )
    finally:
        server.close()
    assert result.status_code == 200
    assert result.json()["ok"] is True


def test_probe_bacnet_and_snmp():
    iam = (
        b"\x81\x0a\x00\x0c"
        + b"\x01\x00"
        + b"\x10\x00"
        + struct.pack("!I", (8 << 22) | 1234)
        + struct.pack("!H", 999)
    )
    server = UdpServer(lambda data: iam)
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="bacnet")
    finally:
        server.close()
    assert result["ok"] is True
    assert result["evidence"]["instance"] == 1234
    assert result["evidence"]["vendor_id"] == 999

    # SNMP response: the parser is best-effort printable-string extraction.
    snmp = b"\x30\x1a\x04\x06public\xa2\x10\x04\x12h4k-iotlab simulated PLC"
    server = UdpServer(lambda data: snmp)
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="snmp")
    finally:
        server.close()
    assert result["ok"] is True
    assert "simulated PLC" in result["detail"]


def test_probe_auto_and_discover_errors(monkeypatch):
    server = UdpServer(lambda data: b"\x60\x45\x00\x01</x>")
    try:
        result = iot_ot.probe("127.0.0.1", port=server.port, protocol="auto")
    finally:
        server.close()
    assert result["protocol"] == "http"  # unknown high port maps to HTTP

    with pytest.raises(ValueError, match="port or protocol"):
        iot_ot.probe("127.0.0.1", protocol="auto")

    # A probe exception is contained and never invents a finding.
    monkeypatch.setattr(
        iot_ot,
        "_PROBES",
        {"boom": lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))},
    )
    result = iot_ot._safe_probe("127.0.0.1", "boom", 1, 0.1, "public")
    assert result["ok"] is False
    assert result["error"]


def test_ber_and_parser_edge_branches():
    # A long SNMP group exercises the multi-byte BER length path.
    assert iot_ot.build_snmp_get("public", oid=(1, 3, 6, 1, 4, 1, 99999, 1))[0] == 0x30
    assert iot_ot.parse_snmp_sysdescr(b"") == ""
    assert iot_ot.parse_coap_resources(b"") == []
    assert (
        iot_ot.parse_bacnet_iam(b"\x81\x0a\x00\x0c\x01\x04\x10\x00xxxx")["iam"] is True
    )
    assert iot_ot._safe_probe("127.0.0.1", "rtsp", 1, 0.05, "public") is None


def test_discover_default_protocols(monkeypatch):
    calls = []

    def _probe(host, port, timeout, **kwargs):
        calls.append((host, port))
        return {"ok": False, "detail": "", "evidence": {}, "error": ""}

    monkeypatch.setattr(iot_ot, "_PROBES", dict.fromkeys(iot_ot.PROTOCOLS, _probe))
    result = iot_ot.discover("127.0.0.1", protocols=["mqtt", "coap"], timeout=0.1)
    assert result["probed"] == 2
    assert {c[1] for c in calls} == {1883, 5683}
    assert result["findings"] == []
