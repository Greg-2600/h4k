#!/usr/bin/env python3
"""h4k IoT/OT lab — a multi-protocol fake device for the probe pack.

One process, no dependencies, several very small servers:

  * MQTT 3.1.1 broker subset        TCP 1883
  * Modbus/TCP PLC (FC1/3/4/5/6/15/16) TCP 502
  * CoAP resource discovery         UDP 5683
  * SSDP/UPnP responder             UDP 1900
  * BACnet Who-Is → I-Am            UDP 47808
  * SNMPv2c sysDescr.0              UDP 161
  * RTSP camera                     TCP 554
  * Device admin page               TCP 8080

It is a lab fixture: the Modbus "writes" only change an in-memory register so
detection rules can see a write function code. There is no physical effect.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import socketserver
import struct
import sys
import threading
import time
from typing import Any

BIND = os.environ.get("IOT_BIND", "0.0.0.0")
MQTT_PORT = int(os.environ.get("IOT_MQTT_PORT", "1883"))
MODBUS_PORT = int(os.environ.get("IOT_MODBUS_PORT", "502"))
COAP_PORT = int(os.environ.get("IOT_COAP_PORT", "5683"))
SSDP_PORT = int(os.environ.get("IOT_SSDP_PORT", "1900"))
BACNET_PORT = int(os.environ.get("IOT_BACNET_PORT", "47808"))
SNMP_PORT = int(os.environ.get("IOT_SNMP_PORT", "161"))
RTSP_PORT = int(os.environ.get("IOT_RTSP_PORT", "554"))
HTTP_PORT = int(os.environ.get("IOT_HTTP_PORT", "8080"))

REGISTERS = [42, 7, 19, 0, 0, 0, 0, 0]
COILS = [1, 0, 1, 0]

_stop = threading.Event()


def log(message: str) -> None:
    print(f"[iotlab] {message}", flush=True)


# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------
def _mqtt_len(sock: socket.socket) -> tuple[int, int]:
    multiplier = 1
    value = 0
    bytes_read = 0
    while True:
        byte = sock.recv(1)
        if not byte:
            return 0, bytes_read
        value += (byte[0] & 127) * multiplier
        bytes_read += 1
        if not byte[0] & 128:
            return value, bytes_read
        multiplier *= 128
        if multiplier > 128**3:
            return 0, bytes_read


def mqtt_client(conn: socket.socket) -> None:
    conn.settimeout(30)
    while not _stop.is_set():
        try:
            header = conn.recv(1)
        except socket.timeout:
            return
        if not header:
            return
        packet_type = header[0] >> 4
        length, _ = _mqtt_len(conn)
        if length:
            body = b""
            while len(body) < length:
                chunk = conn.recv(length - len(body))
                if not chunk:
                    return
                body += chunk
        if packet_type == 1:  # CONNECT
            conn.sendall(b"\x20\x02\x00\x00")
            log("mqtt CONNECT accepted")
        elif packet_type == 8:  # SUBSCRIBE
            packet_id = body[:2] if len(body) >= 2 else b"\x00\x01"
            conn.sendall(b"\x90\x03" + packet_id + b"\x00")
        elif packet_type == 12:  # PINGREQ
            conn.sendall(b"\xd0\x00")
        elif packet_type == 14:  # DISCONNECT
            return
        elif packet_type == 3:  # PUBLISH
            log(f"mqtt PUBLISH {len(body)} bytes")


class MqttHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        mqtt_client(self.request)


# ---------------------------------------------------------------------------
# Modbus/TCP
# ---------------------------------------------------------------------------
def modbus_response(pdu: bytes) -> bytes:
    if not pdu:
        return b""
    function = pdu[0]
    if function in (1, 2):
        count = 8
        data = bytes([sum(COILS) and 0b00001101])
        return bytes([function, 1]) + data
    if function in (3, 4):
        start, count = struct.unpack("!HH", pdu[1:5])
        values = [REGISTERS[(start + i) % len(REGISTERS)] for i in range(min(count, 8))]
        payload = b"".join(struct.pack("!H", v) for v in values)
        return bytes([function, len(payload)]) + payload
    if function in (5, 6):
        address, value = struct.unpack("!HH", pdu[1:5])
        if function == 6:
            REGISTERS[address % len(REGISTERS)] = value
        else:
            COILS[address % len(COILS)] = 1 if value == 0xFF00 else 0
        log(f"modbus WRITE fc={function} address={address} value={value}")
        return pdu[:5]
    if function in (15, 16):
        address, count = struct.unpack("!HH", pdu[1:5])
        log(f"modbus WRITE fc={function} address={address} count={count}")
        return pdu[:5]
    return bytes([function | 0x80, 0x01])


class ModbusHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(30)
        while True:
            try:
                header = self.request.recv(7)
            except socket.timeout:
                return
            if len(header) < 7:
                return
            _txid, _pid, length, _unit = struct.unpack("!HHHB", header)
            body = b""
            while len(body) < max(0, length - 1):
                chunk = self.request.recv(length - 1 - len(body))
                if not chunk:
                    return
                body += chunk
            response_pdu = modbus_response(body)
            response = header[:4] + struct.pack("!HB", len(response_pdu) + 1, header[6]) + response_pdu
            self.request.sendall(response)


# ---------------------------------------------------------------------------
# UDP fixtures (CoAP, SSDP, BACnet, SNMP)
# ---------------------------------------------------------------------------
def coap_response(data: bytes) -> bytes:
    token_len = data[0] & 0x0F if data else 0
    token = data[4 : 4 + token_len] if len(data) >= 4 + token_len else b""
    payload = b'</temp>;rt="sensor",</humidity>;rt="sensor",</relay>;if="actuator"'
    return bytes([0x60, 0x45, data[2] if len(data) > 2 else 0, data[3] if len(data) > 3 else 1]) + token + payload


def ssdp_response(_data: bytes) -> bytes:
    return (
        "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=1800\r\n"
        "ST: upnp:rootdevice\r\n"
        'USN: uuid:h4k-iotlab::upnp:rootdevice\r\n'
        "SERVER: Linux/6.1 UPnP/1.1 h4k-iotlab/1.0\r\n"
        f"LOCATION: http://127.0.0.1:{HTTP_PORT}/device.xml\r\n\r\n"
    ).encode()


def bacnet_response(_data: bytes) -> bytes:
    # BVLC + NPDU + APDU I-Am, object type 8 (device), instance 1234, vendor 999
    obj = (8 << 22) | 1234
    return b"\x81\x0a\x00\x0c\x01\x00\x10\x00" + struct.pack("!I", obj) + struct.pack("!H", 999)


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _ber(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def snmp_response(data: bytes) -> bytes:
    community = b"public"
    if b"public" in data:
        community = b"public"
    descr = b"h4k-iotlab simulated PLC"
    oid = _ber(0x06, b"\x2b\x06\x01\x02\x01\x01\x01\x00")
    varbind = _ber(0x30, oid + _ber(0x04, descr))
    varbinds = _ber(0x30, varbind)
    pdu = _ber(0xA2, _ber(0x02, b"\x01") + _ber(0x02, b"\x00") + _ber(0x02, b"\x00") + varbinds)
    return _ber(0x30, _ber(0x02, b"\x01") + _ber(0x04, community) + pdu)


def udp_server(port: int, name: str, handler) -> threading.Thread:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, port))
    sock.settimeout(0.5)

    def _serve() -> None:
        while not _stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                sock.sendto(handler(data), addr)
                log(f"{name} responded to {addr[0]}:{addr[1]}")
            except OSError:
                pass
        sock.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return thread


# ---------------------------------------------------------------------------
# RTSP + HTTP
# ---------------------------------------------------------------------------
class RtspHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(15)
        try:
            data = self.request.recv(4096).decode("latin-1", errors="ignore")
        except OSError:
            return
        method = data.split(" ", 1)[0] if data else "OPTIONS"
        cseq = "1"
        for line in data.split("\r\n"):
            if line.lower().startswith("cseq:"):
                cseq = line.split(":", 1)[1].strip()
        if method == "DESCRIBE":
            body = (
                "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=h4k-iotlab camera\r\n"
                "t=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\n"
                "a=rtpmap:96 H264/90000\r\n"
            )
            response = (
                f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nServer: h4k-iotlab-cam/1.0\r\n"
                f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n{body}"
            )
        else:
            response = (
                f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nServer: h4k-iotlab-cam/1.0\r\n"
                "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n"
            )
        self.request.sendall(response.encode())


class HttpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            self.request.recv(4096)
        except OSError:
            pass
        body = (
            b"<html><head><title>h4k IoT lab device</title></head>"
            b"<body><h1>Simulated device</h1><p>No credentials here.</p></body></html>"
        )
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nServer: h4k-iotlab/1.0\r\n"
            b"Content-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )


def tcp_server(port: int, handler) -> socketserver.ThreadingTCPServer:
    server = socketserver.ThreadingTCPServer((BIND, port), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "registers": REGISTERS,
        "coils": COILS,
        "ports": {
            "mqtt": MQTT_PORT,
            "modbus": MODBUS_PORT,
            "coap": COAP_PORT,
            "ssdp": SSDP_PORT,
            "bacnet": BACNET_PORT,
            "snmp": SNMP_PORT,
            "rtsp": RTSP_PORT,
            "http": HTTP_PORT,
        },
    }


def main() -> None:
    servers = []
    servers.append(tcp_server(MQTT_PORT, MqttHandler))
    servers.append(tcp_server(MODBUS_PORT, ModbusHandler))
    servers.append(tcp_server(RTSP_PORT, RtspHandler))
    servers.append(tcp_server(HTTP_PORT, HttpHandler))
    udp_server(COAP_PORT, "coap", coap_response)
    udp_server(SSDP_PORT, "ssdp", ssdp_response)
    udp_server(BACNET_PORT, "bacnet", bacnet_response)
    udp_server(SNMP_PORT, "snmp", snmp_response)
    log(f"ready: {json.dumps(health())}")

    def _shutdown(signum, frame):  # noqa: ANN001
        log(f"signal {signum}; stopping")
        _stop.set()
        for server in servers:
            server.shutdown()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    try:
        while not _stop.is_set():
            time.sleep(0.5)
    finally:
        for server in servers:
            server.server_close()
        log("stopped")


if __name__ == "__main__":
    if os.environ.get("IOT_HEALTH") == "1":
        print(json.dumps(health()))
        sys.exit(0)
    main()
