"""Tests for the passive network sniffer.

The sniffer builds on tshark.py, so these tests exercise the orchestration
and the engagement integration, not the capture itself (which needs a NIC).
"""

from services.passive_sniff import PassiveSniffer


def test_parse_hosts_extracts_ips():
    sniffer = PassiveSniffer()
    hosts = sniffer._parse_hosts(
        {"tcp_endpoints": "10.0.0.5  192.168.1.26\n10.0.0.5:443", "udp_endpoints": ""}
    )
    assert "10.0.0.5" in hosts
    assert "192.168.1.26" in hosts


def test_decode_basic_credentials():
    sniffer = PassiveSniffer()
    assert sniffer._decode_basic("Basic YWRtaW46cGFzcw==") == ("admin", "pass")
    assert sniffer._decode_basic("Basic notbase64") is None
    assert sniffer._decode_basic("Basic YWxvbmU=") is None  # no colon


def test_parse_credentials_http_basic():
    sniffer = PassiveSniffer()
    creds = sniffer._parse_credentials(
        {
            "http_basic": "2026-01-01\t10.0.0.5\tBasic YWRtaW46cGFzcw==",
            "ftp": "",
            "telnet": "",
            "smtp": "",
            "snmp": "",
        }
    )
    assert len(creds) == 1
    assert creds[0]["protocol"] == "http_basic"
    assert creds[0]["user"] == "admin"
    assert creds[0]["password"] == "pass"
    assert creds[0]["cwe"] == "CWE-522"


def test_parse_credentials_snmp():
    sniffer = PassiveSniffer()
    creds = sniffer._parse_credentials(
        {
            "http_basic": "",
            "ftp": "",
            "telnet": "",
            "smtp": "",
            "snmp": "2026-01-01\t10.0.0.5\tpublic",
        }
    )
    assert len(creds) == 1
    assert creds[0]["protocol"] == "snmp"
    assert creds[0]["password"] == "public"


def test_build_findings_from_anomalies():
    sniffer = PassiveSniffer()
    findings = sniffer._build_findings(
        creds=[],
        anomalies={
            "syn_scans": "192.168.1.5 80",
            "dns_tunneling": "",
            "unusual_ports": "",
        },
        tls={"weak_protocols": [], "expired_certificates": []},
        arp={"spoofed": {}},
        dns={"long_names": [], "suspicious": []},
    )
    assert any(f["kind"] == "syn_scans" for f in findings)
    assert findings[0]["severity"] == "medium"
    assert findings[0]["technique"] == "T1046"


def test_build_findings_arp_spoof_is_high():
    sniffer = PassiveSniffer()
    findings = sniffer._build_findings(
        creds=[],
        anomalies={},
        tls={"weak_protocols": [], "expired_certificates": []},
        arp={"spoofed": {"192.168.1.1": {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}}},
        dns={"long_names": [], "suspicious": []},
    )
    assert any(f["kind"] == "arp_spoof" for f in findings)
    spoof = next(f for f in findings if f["kind"] == "arp_spoof")
    assert spoof["severity"] == "high"
    assert spoof["cwe"] == "CWE-290"


def test_build_findings_weak_tls():
    sniffer = PassiveSniffer()
    findings = sniffer._build_findings(
        creds=[],
        anomalies={},
        tls={"weak_protocols": ["10.0.0.5"], "expired_certificates": []},
        arp={"spoofed": {}},
        dns={"long_names": [], "suspicious": []},
    )
    assert any(f["kind"] == "weak_tls" for f in findings)


def test_build_findings_cleartext_cred():
    sniffer = PassiveSniffer()
    findings = sniffer._build_findings(
        creds=[
            {"protocol": "ftp", "host": "10.0.0.5", "user": "admin", "password": "pass"}
        ],
        anomalies={},
        tls={"weak_protocols": [], "expired_certificates": []},
        arp={"spoofed": {}},
        dns={"long_names": [], "suspicious": []},
    )
    cred_f = next(f for f in findings if f["kind"] == "cleartext_credential")
    assert cred_f["severity"] == "high"
    assert cred_f["cwe"] == "CWE-522"


def test_ingest_folds_into_engagement(tmp_path):
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "e.db")
    eng = store.create_engagement("lab", ["10.0.0.0/24"])

    sniffer = PassiveSniffer()
    result = sniffer._ingest(
        store,
        eng["id"],
        ["10.0.0.5", "8.8.8.8"],
        [{"protocol": "ftp", "host": "10.0.0.5", "user": "admin", "password": "pass"}],
        [
            {
                "kind": "cleartext_credential",
                "severity": "high",
                "host": "10.0.0.5",
                "detail": "cleartext ftp credential admin:pass",
                "cwe": "CWE-522",
                "technique": "T1078",
            },
        ],
    )
    assert result["added"]["hosts"] == 1  # 8.8.8.8 skipped (out of scope)
    assert result["added"]["credentials"] == 1
    assert result["added"]["findings"] == 1
    assert "8.8.8.8" in result["skipped_out_of_scope"]
    assert store.credentials(eng["id"])[0]["user"] == "admin"
    assert store.vulns(eng["id"])[0]["host"] == "10.0.0.5"


def test_looks_like_ip():
    from services.passive_sniff import _looks_like_ip

    assert _looks_like_ip("192.168.1.26")
    assert not _looks_like_ip("not-an-ip")
    assert not _looks_like_ip("999.999.999.999")
