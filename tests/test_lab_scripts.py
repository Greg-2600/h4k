# Lab-script unit tests (TD-15): the Transmission/torrent helpers and the
# sanity-check client/report. Pure stdlib; every socket and HTTP call is
# faked. The live demos (transmission_rce_demo.main, sanity_check.main)
# are integration and stay out of the unit suite.
import io
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import torrent_seeder as seeder
import transmission_rpc as trpc
from sanity_check import Client, Report


def test_benc_encodes_sorted_dicts():
    assert trpc._benc(3) == b"i3e"
    assert trpc._benc(b"xy") == b"2:xy"
    assert trpc._benc("xy") == b"2:xy"
    assert trpc._benc([1, b"x"]) == b"li1e1:xe"
    assert trpc._benc({"b": 1, "a": 2}) == b"d1:ai2e1:bi1ee"  # keys sorted
    try:
        trpc._benc(object())
    except TypeError:
        pass
    else:
        raise AssertionError("benc accepted an unknown type")


def test_empty_torrent_is_valid_bencode():
    raw = trpc.empty_torrent("probe")
    assert raw.startswith(b"d") and raw.endswith(b"e")
    assert b"4:name5:probe" in raw


def test_rpc_raises_without_session_id(monkeypatch):
    def _boom_409(req, timeout=20):
        raise urllib.error.HTTPError(
            req.full_url,
            409,
            "Conflict",
            {"X-Transmission-Session-Id": "SID1"},
            io.BytesIO(),
        )

    monkeypatch.setattr(trpc.urllib.request, "urlopen", _boom_409)
    t = trpc.Transmission("h", 9091)
    try:
        t.rpc("session-get")
    except urllib.error.HTTPError as exc:
        assert exc.code == 409
    else:
        raise AssertionError("expected HTTPError without a session id")


def test_rpc_retries_with_session_id(monkeypatch):
    seen = []

    class _Resp:
        def __init__(self):
            self.headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"result":"success","arguments":{}}'

    def _sid_of(req):
        for key, value in req.headers.items():
            if key.lower() == "x-transmission-session-id":
                return value
        return None

    def _boom_409(req, timeout=20):
        seen.append(_sid_of(req))
        raise urllib.error.HTTPError(
            req.full_url,
            409,
            "Conflict",
            {"X-Transmission-Session-Id": "SID1"},
            io.BytesIO(),
        )

    def _ok(req, timeout=20):
        seen.append(_sid_of(req))
        return _Resp()

    seq = [_boom_409, _ok]
    monkeypatch.setattr(
        trpc.urllib.request, "urlopen", lambda req, timeout=20: seq.pop(0)(req, timeout)
    )
    t = trpc.Transmission("h", 9091)
    assert t.rpc("session-get")["result"] == "success"
    assert t.session_id == "SID1"
    assert seen == [None, "SID1"]  # second attempt carries the fresh id


def test_session_helpers_delegate(monkeypatch):
    seen = {}

    def _fake(self, method, args=None):
        seen["method"] = method
        seen["args"] = args
        return {"arguments": {"ok": True}}

    monkeypatch.setattr(trpc.Transmission, "rpc", _fake)
    t = trpc.Transmission("h")
    assert t.session_get() == {"ok": True}
    t.session_set({"a": 1})
    assert seen == {"method": "session-set", "args": {"a": 1}}
    t.torrent_add(filename="x.torrent")
    assert seen["method"] == "torrent-add"


def test_seeder_build_info_hash():
    digest, blob = seeder.build_info_hash(b"hello", name="f.bin")
    assert len(digest) == 40 and all(c in "0123456789abcdef" for c in digest)
    assert blob.startswith(b"d") and blob.endswith(b"e")
    assert b"f.bin" in blob


def _scripted_peer(script: list[bytes]):
    received = bytearray()

    class _Sock:
        def settimeout(self, *a):
            pass

        def recv(self, n):
            if not script:
                raise TimeoutError()
            chunk, script[0] = script[0][:n], script[0][n:]
            if not script[0]:
                script.pop(0)
            return chunk

        def sendall(self, data):
            received.extend(data)

        def close(self):
            pass

    sock = _Sock()
    return sock, received


def test_seeder_serves_requested_piece():
    payload = b"hello"
    digest, blob = seeder.build_info_hash(payload, name="f.bin")
    info_hash = bytes.fromhex(digest)
    handshake = b"\x13BitTorrent protocol" + b"\x00" * 8 + info_hash + b"\x00" * 20
    script = [
        handshake,
        b"\x00\x00\x00\x01\x02",  # interested
        b"\x00\x00\x00\x0d\x06" + (0).to_bytes(4) + (0).to_bytes(4) + (5).to_bytes(4),
    ]
    sock, received = _scripted_peer(script)
    seeder.handle(sock, info_hash, payload, 6881, blob)
    assert b"BitTorrent protocol" in received  # handshake reply
    assert payload in received  # the requested piece bytes go out


def test_seeder_drops_wrong_info_hash(capsys):
    digest, blob = seeder.build_info_hash(b"hello", name="f.bin")
    bad_hash = b"\x00" * 20
    handshake = b"\x13BitTorrent protocol" + b"\x00" * 8 + bad_hash + b"\x00" * 20
    sock, received = _scripted_peer([handshake])
    seeder.handle(sock, bytes.fromhex(digest), b"hello", 6881, blob)
    assert received == b""  # dropped before any reply
    assert "mismatch" in capsys.readouterr().out


def test_sanity_report_counts():
    rep = Report()
    assert rep.failed == 0
    rep.add("a", True)
    rep.add("b", False, "boom")
    rep.add("c", False, "meh", warn=True)
    assert rep.failed == 1  # warnings do not fail the gate
    text = rep.render()
    assert "boom" in text


def test_sanity_client_wraps_http(monkeypatch):
    import urllib.request as urlmod

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"ok": true}'

    monkeypatch.setattr(urlmod, "urlopen", lambda req, timeout=30: _Resp())
    client = Client("http://127.0.0.1:3137")
    assert client.get("/api/health") == (200, {"ok": True})
    assert client.post("/api/echo", {"a": 1})[0] == 200
    assert client.delete("/api/x")[0] == 200
