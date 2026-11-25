# IoT/OT pack (#90): safe, read-only discovery and identification for the
# devices that never show up in a normal nmap report as anything useful.
#
# MQTT brokers, CoAP endpoints, Modbus PLCs, BACnet building controllers, SSDP
# media devices, RTSP cameras and SNMP agents all answer a *read* request with
# enough identity to inventory them. Every probe here is a read/discovery
# operation: no register writes, no coil forcing, no broker publishes, no
# firmware uploads, no credential guessing. The wire helpers enforce a lab-only
# target policy unless the operator explicitly overrides it.
import logging
import re
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from services import wire
from services.lab_traffic import (
    build_coap_get,
    build_modbus_read,
    build_mqtt_connect,
    build_ssdp_search,
    parse_modbus,
    parse_mqtt_connack,
)

logger = logging.getLogger("h4k.iot_ot")

PROTOCOLS: dict[str, dict[str, Any]] = {
    "mqtt": {
        "name": "mqtt",
        "port": 1883,
        "transport": "tcp",
        "description": "MQTT 3.1.1 CONNECT → CONNACK (broker version/acceptance)",
        "read_only": True,
    },
    "coap": {
        "name": "coap",
        "port": 5683,
        "transport": "udp",
        "description": "CoAP GET /.well-known/core → resource list",
        "read_only": True,
    },
    "modbus": {
        "name": "modbus",
        "port": 502,
        "transport": "tcp",
        "description": "Modbus/TCP FC3 read one holding register (no writes)",
        "read_only": True,
    },
    "bacnet": {
        "name": "bacnet",
        "port": 47808,
        "transport": "udp",
        "description": "BACnet Who-Is → I-Am device object/vendor",
        "read_only": True,
    },
    "ssdp": {
        "name": "ssdp",
        "port": 1900,
        "transport": "udp",
        "description": "SSDP M-SEARCH → device ST/USN/LOCATION headers",
        "read_only": True,
    },
    "rtsp": {
        "name": "rtsp",
        "port": 554,
        "transport": "tcp",
        "description": "RTSP OPTIONS → Server header and supported methods",
        "read_only": True,
    },
    "snmp": {
        "name": "snmp",
        "port": 161,
        "transport": "udp",
        "description": "SNMPv2c GET sysDescr.0 with the supplied community",
        "read_only": True,
    },
    "telnet": {
        "name": "telnet",
        "port": 23,
        "transport": "tcp",
        "description": "Read the login banner without sending credentials",
        "read_only": True,
    },
    "http": {
        "name": "http",
        "port": 80,
        "transport": "tcp",
        "description": "HTTP banner/title (device admin panels)",
        "read_only": True,
    },
}

_PORT_PROTOCOL = {spec["port"]: name for name, spec in PROTOCOLS.items()}


def _bacnet_who_is() -> bytes:
    return b"\x81\x0a\x00\x08" + b"\x01\x04" + b"\x10\x08"


def build_snmp_get(
    community: str = "public", oid: tuple[int, ...] = (1, 3, 6, 1, 2, 1, 1, 1, 0)
) -> bytes:
    def _len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(raw)]) + raw

    def _tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag]) + _len(len(value)) + value

    def _oid(parts: tuple[int, ...]) -> bytes:
        encoded = bytes([parts[0] * 40 + parts[1]])
        for part in parts[2:]:
            chunk = [part & 0x7F]
            part >>= 7
            while part:
                chunk.append((part & 0x7F) | 0x80)
                part >>= 7
            encoded += bytes(reversed(chunk))
        return _tlv(0x06, encoded)

    varbind = _tlv(0x30, _oid(oid) + _tlv(0x05, b""))
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(
        0xA0, _tlv(0x02, b"\x01") + _tlv(0x02, b"\x00") + _tlv(0x02, b"\x00") + varbinds
    )
    return _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x04, community.encode()) + pdu)


def parse_ssdp(text: str) -> dict[str, str]:
    lines = [ln.strip() for ln in text.split("\r\n") if ":" in ln]
    out: dict[str, str] = {}
    for line in lines:
        name, _, value = line.partition(":")
        out[name.strip().upper()] = value.strip()
    return out


def parse_rtsp(text: str) -> dict[str, Any]:
    lines = text.split("\r\n")
    status = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()
    return {"status": status, "headers": headers}


def parse_bacnet_iam(data: bytes) -> dict[str, Any]:
    """Pull the device instance and vendor out of a BVLC I-Am."""
    if len(data) < 12 or data[0] != 0x81:
        return {"iam": False}
    # APDU starts after BVLC (4) + NPDU (2); I-Am is 0x10 0x00.
    for offset in (6, 7, 8):
        if (
            len(data) >= offset + 8
            and data[offset] == 0x10
            and data[offset + 1] == 0x00
        ):
            obj = struct.unpack("!I", data[offset + 2 : offset + 6])[0]
            vendor = struct.unpack("!H", data[offset + 6 : offset + 8])[0]
            return {
                "iam": True,
                "object_type": obj >> 22,
                "instance": obj & 0x3FFFFF,
                "vendor_id": vendor,
            }
    return {"iam": True, "raw_hex": data[:64].hex()}


def parse_snmp_sysdescr(data: bytes) -> str:
    """Best-effort extraction of the sysDescr octet string from an SNMP reply."""
    if not data:
        return ""
    text = data.decode("latin-1", errors="ignore")
    matches = re.findall(r"[\x20-\x7e]{6,}", text)
    return max(matches, key=len).strip() if matches else ""


def parse_coap_resources(data: bytes) -> list[str]:
    if len(data) < 4:
        return []
    text = data[4:].decode("latin-1", errors="ignore")
    return re.findall(r"<([^>]+)>", text)


def _probe_mqtt(host: str, port: int, timeout: float, **_: Any) -> dict[str, Any]:
    payload = build_mqtt_connect("h4k-iot-probe")
    result = wire.tcp_exchange(host, port, payload, timeout=timeout)
    connack = parse_mqtt_connack(result.get("banner", "").encode("latin-1"))
    return {
        "ok": result["ok"],
        "detail": (
            f"MQTT broker accepted CONNECT (rc={connack.get('return_code')})"
            if connack.get("accepted")
            else "MQTT port answered but CONNACK was not accepted"
        ),
        "evidence": {**connack, "raw_hex": result.get("raw_hex", "")[:64]},
        "error": result["error"],
    }


def _probe_coap(host: str, port: int, timeout: float, **_: Any) -> dict[str, Any]:
    payload = build_coap_get()
    result = wire.udp_exchange(host, port, payload, timeout=timeout)
    resources = parse_coap_resources(result.get("raw", b""))
    return {
        "ok": result["ok"] and bool(result["received"]),
        "detail": f"CoAP responded with {len(resources)} resource(s)",
        "evidence": {"resources": resources[:50], "raw_hex": result["raw_hex"][:64]},
        "error": result["error"],
    }


def _probe_modbus(host: str, port: int, timeout: float, **_: Any) -> dict[str, Any]:
    payload = build_modbus_read()
    result = wire.tcp_exchange(host, port, payload, timeout=timeout)
    parsed = parse_modbus(result.get("banner", "").encode("latin-1"))
    return {
        "ok": result["ok"] and parsed["function"] is not None,
        "detail": (
            f"Modbus FC{parsed['function']} exception={parsed['exception']}"
            if parsed["exception"]
            else f"Modbus FC{parsed['function']} values={parsed['values']}"
        ),
        "evidence": parsed,
        "error": result["error"],
    }


def _probe_bacnet(host: str, port: int, timeout: float, **_: Any) -> dict[str, Any]:
    result = wire.udp_exchange(host, port, _bacnet_who_is(), timeout=timeout)
    parsed = parse_bacnet_iam(result.get("raw", b""))
    return {
        "ok": result["ok"] and bool(parsed.get("iam")),
        "detail": (
            f"BACnet device instance {parsed.get('instance')} "
            f"(vendor {parsed.get('vendor_id')})"
            if parsed.get("instance") is not None
            else "BACnet port answered (unparsed I-Am)"
        ),
        "evidence": parsed,
        "error": result["error"],
    }


def _probe_ssdp(host: str, port: int, timeout: float, **_: Any) -> dict[str, Any]:
    result = wire.udp_exchange(host, port, build_ssdp_search(), timeout=timeout)
    headers = parse_ssdp(result.get("response", ""))
    return {
        "ok": result["ok"] and bool(headers),
        "detail": headers.get("SERVER") or headers.get("ST") or "SSDP response",
        "evidence": headers,
        "error": result["error"],
    }


def _probe_rtsp(host: str, port: int, timeout: float, **_: Any) -> dict[str, Any]:
    request = (
        f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n"
        "User-Agent: h4k-iot-probe\r\n\r\n"
    ).encode()
    result = wire.tcp_exchange(host, port, request, timeout=timeout)
    parsed = parse_rtsp(result.get("banner", ""))
    return {
        "ok": result["ok"] and parsed["status"].startswith("RTSP/"),
        "detail": parsed["headers"].get("Server", parsed["status"]),
        "evidence": parsed["headers"],
        "error": result["error"],
    }


def _probe_snmp(
    host: str, port: int, timeout: float, *, community: str = "public", **_: Any
) -> dict[str, Any]:
    result = wire.udp_exchange(host, port, build_snmp_get(community), timeout=timeout)
    descr = parse_snmp_sysdescr(result.get("raw", b""))
    return {
        "ok": bool(descr),
        "detail": descr or "SNMP port answered without a readable sysDescr",
        "evidence": {"sys_descr": descr, "raw_hex": result["raw_hex"][:64]},
        "error": result["error"],
    }


def _probe_telnet(host: str, port: int, timeout: float, **_: Any) -> dict[str, Any]:
    result = wire.tcp_exchange(host, port, b"", timeout=timeout)
    banner = (result.get("banner") or "").splitlines()[:2]
    return {
        "ok": bool(banner),
        "detail": " / ".join(banner)[:160] or "no banner",
        "evidence": {"banner": banner},
        "error": result["error"],
    }


def _probe_http(host: str, port: int, timeout: float, **_: Any) -> dict[str, Any]:
    result = wire.http_get(host, port, "/", timeout=timeout)
    title = ""
    match = re.search(
        r"<title[^>]*>([^<]{1,120})</title>", result.get("body_preview", ""), re.I
    )
    if match:
        title = match.group(1).strip()
    server = ""
    for line in result.get("banner", "").split("\r\n"):
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
    return {
        "ok": result["ok"],
        "detail": " | ".join(x for x in (server, title) if x)
        or result.get("status", ""),
        "evidence": {"status": result.get("status"), "server": server, "title": title},
        "error": result["error"],
    }


_PROBES = {
    "mqtt": _probe_mqtt,
    "coap": _probe_coap,
    "modbus": _probe_modbus,
    "bacnet": _probe_bacnet,
    "ssdp": _probe_ssdp,
    "rtsp": _probe_rtsp,
    "snmp": _probe_snmp,
    "telnet": _probe_telnet,
    "http": _probe_http,
}


def probe(
    host: str,
    *,
    port: int | None = None,
    protocol: str = "auto",
    timeout: float = 2.0,
    allow_public: bool = False,
    community: str = "public",
) -> dict[str, Any]:
    name = protocol
    if name == "auto":
        if port is None:
            raise ValueError("port or protocol is required")
        name = _PORT_PROTOCOL.get(int(port), "http")
    spec = PROTOCOLS.get(name)
    if spec is None:
        raise ValueError(
            f"unknown protocol: {name} (choices: {', '.join(sorted(PROTOCOLS))})"
        )
    resolved = wire.check_lab_target(host, allow_public=allow_public)
    target_port = int(port or spec["port"])
    result = _PROBES[name](
        host, target_port, max(0.2, min(float(timeout), 10.0)), community=community
    )
    return {
        "host": host,
        "resolved": resolved,
        "port": target_port,
        "protocol": name,
        "description": spec["description"],
        "read_only": True,
        **result,
    }


def discover(
    host: str,
    *,
    protocols: list[str] | None = None,
    ports: list[int] | None = None,
    timeout: float = 1.5,
    allow_public: bool = False,
    community: str = "public",
    max_workers: int = 6,
) -> dict[str, Any]:
    """Probe the default ports (or an explicit set) concurrently."""
    resolved = wire.check_lab_target(host, allow_public=allow_public)
    jobs: list[tuple[str, int]] = []
    if ports:
        for port in ports[:64]:
            jobs.append((_PORT_PROTOCOL.get(int(port), "http"), int(port)))
    else:
        names = protocols or list(PROTOCOLS)
        for name in names:
            spec = PROTOCOLS.get(name)
            if spec:
                jobs.append((name, int(spec["port"])))
    findings: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, 12))) as pool:
        futures = {
            pool.submit(
                _safe_probe,
                host,
                name,
                port,
                timeout,
                community,
            ): (name, port)
            for name, port in jobs
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
    findings.sort(key=lambda f: (f["port"], f["protocol"]))
    return {
        "host": host,
        "resolved": resolved,
        "probed": len(jobs),
        "responsive": sum(1 for f in findings if f.get("ok")),
        "findings": findings,
        "read_only": True,
    }


def _safe_probe(
    host: str, name: str, port: int, timeout: float, community: str
) -> dict[str, Any] | None:
    try:
        result = _PROBES[name](
            host, port, max(0.2, min(float(timeout), 10.0)), community=community
        )
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "host": host,
            "port": port,
            "protocol": name,
            "ok": False,
            "detail": "",
            "evidence": {},
            "error": f"{type(exc).__name__}: {exc}",
        }
    # Keep silent ports out of the report; a closed port is not a finding.
    if not result.get("ok"):
        return None
    return {
        "host": host,
        "port": port,
        "protocol": name,
        "description": PROTOCOLS[name]["description"],
        **result,
    }
