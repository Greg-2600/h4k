# Lab traffic kit (#87): generate realistic, *benign* traffic for detection
# engineering and IDS/telemetry validation.
#
# This is the mirror image of an attack: the point is to make a lab network look
# busy — HTTP browsing, DNS lookups, TLS handshakes, SMB negotiation, MQTT
# publish, CoAP discovery, Modbus reads, SSDP search — so a defender can prove
# their sensors see normal traffic before they tune detections. Nothing here
# authenticates, brute-forces, writes OT registers, or leaves the lab: the
# target policy refuses public addresses unless explicitly overridden.
import logging
import random
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any

from services import wire

logger = logging.getLogger("h4k.lab_traffic")

MAX_EVENTS = 5000
MAX_DURATION = 600.0
MAX_EVENT_LOG = 500

HTTP_PATHS = ("/", "/index.html", "/login", "/admin", "/api/health", "/robots.txt")
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36",
    "curl/8.5.0",
    "h4k-lab-traffic/1.0",
)
AUTH_BANNER_PORTS = (21, 22, 23, 25, 110, 143, 445, 3389)
DNS_NAMES = (
    "dc01.corp.lab",
    "fileserver.corp.lab",
    "intranet.corp.lab",
    "updates.corp.lab",
    "printer01.corp.lab",
)
MQTT_TOPICS = ("lab/h4k/traffic", "factory/line1/status", "sensors/temp")


TRAFFIC_PROFILES: dict[str, dict[str, Any]] = {
    "web": {
        "name": "web",
        "description": "HTTP/HTTPS browsing: pages, favicon, API health, robots.txt",
        "protocols": ("http", "https"),
        "default_ports": (80, 443),
        "safe": True,
    },
    "dns": {
        "name": "dns",
        "description": "Recursive-style DNS A/AAAA/TXT lookups for lab names",
        "protocols": ("dns",),
        "default_ports": (53,),
        "safe": True,
    },
    "auth": {
        "name": "auth",
        "description": "Service banner grabs on SSH/FTP/Telnet/SMTP/IMAP/SMB/RDP",
        "protocols": ("banner",),
        "default_ports": AUTH_BANNER_PORTS,
        "safe": True,
    },
    "tls": {
        "name": "tls",
        "description": "TLS ClientHello handshakes with SNI against lab HTTPS",
        "protocols": ("tls",),
        "default_ports": (443, 8443),
        "safe": True,
    },
    "iot": {
        "name": "iot",
        "description": "MQTT publish, CoAP discovery, Modbus read, SSDP search",
        "protocols": ("mqtt", "coap", "modbus", "ssdp"),
        "default_ports": (1883, 5683, 502, 1900),
        "safe": True,
    },
    "mixed": {
        "name": "mixed",
        "description": "Round-robin across every protocol above",
        "protocols": (
            "http",
            "https",
            "dns",
            "banner",
            "tls",
            "mqtt",
            "coap",
            "modbus",
            "ssdp",
            "smb",
        ),
        "default_ports": (80, 443, 53, 22, 1883, 5683, 502, 1900, 445),
        "safe": True,
    },
}


def profiles() -> list[dict[str, Any]]:
    return [TRAFFIC_PROFILES[name] for name in TRAFFIC_PROFILES]


# ---------------------------------------------------------------------------
# Packet builders (all read-only / discovery)
# ---------------------------------------------------------------------------
def build_dns_query(name: str, qtype: int = 1, txid: int | None = None) -> bytes:
    txid = (
        random.randint(0, 0xFFFF) if txid is None else txid  # nosec B311 - DNS txid
    )  # nosec B311 - DNS txid, not a secret
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = (
        b"".join(
            bytes([len(label)]) + label.encode("ascii", errors="ignore")
            for label in name.strip(".").split(".")
        )
        + b"\x00"
    )
    return header + qname + struct.pack("!HH", qtype, 1)


def parse_dns_rcode(data: bytes) -> dict[str, Any]:
    if len(data) < 12:
        return {"rcode": None, "answers": 0}
    _txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    return {
        "rcode": flags & 0x000F,
        "answers": an,
        "questions": qd,
        "authoritative": bool(flags & 0x0400),
    }


def build_mqtt_connect(client_id: str = "h4k-lab") -> bytes:
    payload = (
        b"\x00\x04MQTT\x04\x02\x00\x3c"
        + struct.pack("!H", len(client_id))
        + client_id.encode()
    )
    return b"\x10" + _mqtt_len(len(payload)) + payload


def build_mqtt_publish(topic: str, message: str) -> bytes:
    payload = struct.pack("!H", len(topic)) + topic.encode() + message.encode()
    return b"\x30" + _mqtt_len(len(payload)) + payload


def parse_mqtt_connack(data: bytes) -> dict[str, Any]:
    if len(data) < 4 or data[0] != 0x20:
        return {"connack": False}
    return {
        "connack": True,
        "session_present": bool(data[2] & 0x01),
        "return_code": data[3],
        "accepted": data[3] == 0,
    }


def _mqtt_len(length: int) -> bytes:
    out = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length:
            byte |= 0x80
        out.append(byte)
        if not length:
            return bytes(out)


def build_coap_get(path: str = "/.well-known/core", msg_id: int = 1) -> bytes:
    token = b"\x4c\x34"
    options = b""
    first = True
    for segment in [p for p in path.strip("/").split("/") if p]:
        # Uri-Path option number 11: first option uses delta 11, then delta 0.
        options += bytes([((11 if first else 0) << 4) | len(segment)])
        options += segment.encode()
        first = False
    return bytes([0x40, 0x01, (msg_id >> 8) & 0xFF, msg_id & 0xFF]) + token + options


def build_modbus_read(unit: int = 1, start: int = 0, count: int = 1) -> bytes:
    pdu = struct.pack("!BHH", 0x03, start, count)
    return struct.pack("!HHHB", 1, 0, len(pdu) + 1, unit) + pdu


def parse_modbus(data: bytes) -> dict[str, Any]:
    if len(data) < 9:
        return {"function": None, "exception": None}
    function = data[7]
    exception = function & 0x80
    return {
        "function": function & 0x7F,
        "exception": data[8] if exception and len(data) > 8 else None,
        "values": (
            list(struct.unpack(f"!{data[8] // 2}H", data[9 : 9 + data[8]]))
            if not exception and len(data) >= 9 + data[8]
            else []
        ),
    }


def build_ssdp_search() -> bytes:
    return (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )


def build_smb2_negotiate() -> bytes:
    # NetBIOS session header + SMB2 NEGOTIATE with one dialect (2.0.2).
    header = b"\x00\x00\x00\x30" + b"\xfeSMB" + b"\x40\x00" + b"\x00" * 24
    header += b"\x00\x00" + b"\x02\x00" + b"\x00\x00" + b"\x00\x00\x00\x00"
    body = b"\x24\x00" + b"\x02\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00" * 24
    body += b"\x02\x02"
    return header + body


# ---------------------------------------------------------------------------
# Event generators
# ---------------------------------------------------------------------------
def _event(protocol: str, target: wire.Target, action: str, **extra: Any) -> dict:
    base = {
        "ts": time.time(),
        "protocol": protocol,
        "target": target.key(),
        "action": action,
    }
    base.update(extra)
    return base


def _do_http(target: wire.Target, rng: random.Random) -> dict:
    path = rng.choice(HTTP_PATHS)
    tls = target.port in (443, 8443)
    result = wire.http_get(target.host, target.port, path, tls=tls)
    return {
        "sent": result["sent"],
        "received": result["received"],
        "ok": result["ok"],
        "status": result.get("status", ""),
        "error": result["error"],
        "sample": f"GET {path}",
    }


def _do_dns(target: wire.Target, rng: random.Random) -> dict:
    name = rng.choice(DNS_NAMES)
    qtype = rng.choice((1, 1, 1, 28, 16))
    payload = build_dns_query(name, qtype)
    raw = wire.udp_exchange(target.host, target.port or 53, payload, timeout=2)
    parsed = parse_dns_rcode(raw.get("raw", b""))
    return {
        "sent": len(payload),
        "received": raw["received"],
        "ok": raw["ok"],
        "status": f"rcode={parsed['rcode']} answers={parsed['answers']}",
        "error": raw["error"],
        "sample": f"DNS qtype={qtype} {name}",
    }


def _do_banner(target: wire.Target, rng: random.Random) -> dict:
    result = wire.tcp_exchange(target.host, target.port, b"", timeout=2)
    banner = (result.get("banner") or "").splitlines()[:1]
    return {
        "sent": 0,
        "received": result["received"],
        "ok": result["ok"],
        "status": banner[0][:80] if banner else "",
        "error": result["error"],
        "sample": "banner grab",
    }


def _do_tls(target: wire.Target, rng: random.Random) -> dict:
    result = wire.tcp_exchange(
        target.host, target.port or 443, b"", timeout=3, tls=True, read=False
    )
    return {
        "sent": 0,
        "received": 0,
        "ok": result["ok"],
        "status": "handshake" if result["ok"] else "",
        "error": result["error"],
        "sample": "TLS ClientHello",
    }


def _do_smb(target: wire.Target, rng: random.Random) -> dict:
    payload = build_smb2_negotiate()
    result = wire.tcp_exchange(target.host, target.port or 445, payload, timeout=3)
    return {
        "sent": len(payload),
        "received": result["received"],
        "ok": result["ok"],
        "status": "negotiate" if result["ok"] else "",
        "error": result["error"],
        "sample": "SMB2 NEGOTIATE",
    }


def _do_mqtt(target: wire.Target, rng: random.Random) -> dict:
    connect = build_mqtt_connect(f"h4k-{rng.randint(1000, 9999)}")
    result = wire.tcp_exchange(target.host, target.port or 1883, connect, timeout=2)
    connack = parse_mqtt_connack(result.get("banner", "").encode("latin-1"))
    if connack.get("accepted"):
        publish = build_mqtt_publish(
            rng.choice(MQTT_TOPICS), f"lab {rng.randint(0, 100)}"
        )
        wire.tcp_exchange(target.host, target.port or 1883, publish, timeout=2)
    return {
        "sent": len(connect),
        "received": result["received"],
        "ok": result["ok"],
        "status": f"mqtt rc={connack.get('return_code')}",
        "error": result["error"],
        "sample": "MQTT CONNECT/PUBLISH",
    }


def _do_coap(target: wire.Target, rng: random.Random) -> dict:
    payload = build_coap_get(msg_id=rng.randint(1, 65535))
    result = wire.udp_exchange(target.host, target.port or 5683, payload, timeout=2)
    return {
        "sent": len(payload),
        "received": result["received"],
        "ok": result["ok"],
        "status": "coap response" if result["received"] else "",
        "error": result["error"],
        "sample": "CoAP GET /.well-known/core",
    }


def _do_modbus(target: wire.Target, rng: random.Random) -> dict:
    payload = build_modbus_read(start=rng.randint(0, 32), count=1)
    result = wire.tcp_exchange(target.host, target.port or 502, payload, timeout=2)
    parsed = parse_modbus(result.get("banner", "").encode("latin-1"))
    return {
        "sent": len(payload),
        "received": result["received"],
        "ok": result["ok"],
        "status": f"modbus fc={parsed['function']} exc={parsed['exception']}",
        "error": result["error"],
        "sample": "Modbus FC3 read holding register",
    }


def _do_ssdp(target: wire.Target, rng: random.Random) -> dict:
    payload = build_ssdp_search()
    result = wire.udp_exchange(target.host, target.port or 1900, payload, timeout=2)
    first = (result.get("response") or "").split("\r\n", 1)[0]
    return {
        "sent": len(payload),
        "received": result["received"],
        "ok": result["ok"],
        "status": first[:80],
        "error": result["error"],
        "sample": "SSDP M-SEARCH",
    }


_GENERATORS = {
    "http": _do_http,
    "https": _do_http,
    "dns": _do_dns,
    "banner": _do_banner,
    "tls": _do_tls,
    "smb": _do_smb,
    "mqtt": _do_mqtt,
    "coap": _do_coap,
    "modbus": _do_modbus,
    "ssdp": _do_ssdp,
}

_DEFAULT_PORT = {
    "http": 80,
    "https": 443,
    "dns": 53,
    "banner": 22,
    "tls": 443,
    "smb": 445,
    "mqtt": 1883,
    "coap": 5683,
    "modbus": 502,
    "ssdp": 1900,
}


@dataclass
class TrafficRunner:
    """Bounded traffic generator with a stop flag and per-protocol summary."""

    stop_event: threading.Event | None = None

    def run(
        self,
        profile: str,
        target: str,
        *,
        count: int = 20,
        duration_s: float = 0,
        rate_per_s: float = 2.0,
        allow_public: bool = False,
        ports: list[int] | None = None,
        seed: int | None = None,
    ) -> dict[str, Any]:
        spec = TRAFFIC_PROFILES.get(profile)
        if spec is None:
            raise ValueError(
                f"unknown traffic profile: {profile} "
                f"(choices: {', '.join(sorted(TRAFFIC_PROFILES))})"
            )
        count = max(1, min(int(count), MAX_EVENTS))
        duration_s = max(0.0, min(float(duration_s or 0), MAX_DURATION))
        rate = max(0.1, min(float(rate_per_s or 1), 100.0))
        if duration_s <= 0 and count > MAX_EVENTS:  # defensive, count already clamped
            raise ValueError("too many events")
        parsed = wire.parse_target(target, default_port=spec["default_ports"][0])
        addresses = wire.check_lab_target(parsed.host, allow_public=allow_public)
        rng = random.Random(seed)  # nosec B311 - reproducible traffic, not crypto
        protocols = list(spec["protocols"])
        override_ports = [int(p) for p in (ports or [])]
        explicit_port = bool(
            ":" in target and target.rsplit(":", 1)[-1].strip().isdigit()
        )
        started = time.monotonic()
        events: list[dict[str, Any]] = []
        by_protocol: dict[str, dict[str, int]] = {}
        sent_total = 0
        received_total = 0
        index = 0
        stopped = False
        while index < count:
            if self.stop_event is not None and self.stop_event.is_set():
                stopped = True
                break
            if duration_s and time.monotonic() - started >= duration_s:
                break
            proto = protocols[index % len(protocols)]
            port = (
                override_ports[index % len(override_ports)]
                if override_ports
                else (
                    parsed.port
                    if explicit_port
                    else _DEFAULT_PORT.get(proto, parsed.port)
                )
            )
            event_target = wire.Target(parsed.host, port)
            try:
                detail = _GENERATORS[proto](event_target, rng)
            except Exception as exc:  # pragma: no cover - defensive
                detail = {
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "sent": 0,
                    "received": 0,
                    "status": "",
                    "sample": proto,
                }
            event = _event(proto, event_target, detail.pop("sample", proto), **detail)
            index += 1
            sent_total += int(event.get("sent") or 0)
            received_total += int(event.get("received") or 0)
            bucket = by_protocol.setdefault(proto, {"total": 0, "ok": 0, "errors": 0})
            bucket["total"] += 1
            bucket["ok"] += 1 if event.get("ok") else 0
            bucket["errors"] += 0 if event.get("ok") else 1
            if len(events) < MAX_EVENT_LOG:
                events.append(event)
            pause = 1.0 / rate
            if duration_s:
                pause = min(pause, max(0.0, duration_s - (time.monotonic() - started)))
            if pause > 0 and index < count:
                time.sleep(pause)
        elapsed = round(time.monotonic() - started, 3)
        summary = {
            "profile": profile,
            "target": parsed.key(),
            "resolved": addresses,
            "events": index,
            "sent_bytes": sent_total,
            "received_bytes": received_total,
            "ok": sum(b["ok"] for b in by_protocol.values()),
            "errors": sum(b["errors"] for b in by_protocol.values()),
            "by_protocol": by_protocol,
            "duration_s": elapsed,
            "rate_per_s": rate,
            "stopped": stopped,
            "logged_events": len(events),
        }
        logger.info(
            "lab traffic %s -> %s: %d events, %d ok, %d errors in %ss",
            profile,
            parsed.key(),
            index,
            summary["ok"],
            summary["errors"],
            elapsed,
        )
        return {"summary": summary, "events": events}


def generate(profile: str, target: str, **kwargs: Any) -> dict[str, Any]:
    return TrafficRunner().run(profile, target, **kwargs)
