from services.attck import (
    TECHNIQUES,
    detection_for,
    enrich_engagement,
    techniques_for_action,
    techniques_for_finding,
)
from services.engagement import EngagementStore


def test_action_mapping():
    assert "T1046" in techniques_for_action("port_scan")
    assert "T1110" in techniques_for_action("hydra")
    assert techniques_for_action("unknown-action") == []


def test_finding_mapping():
    techs = techniques_for_finding({"name": "OpenSSH outdated", "service": "ssh"})
    assert "T1021" in techs
    techs2 = techniques_for_finding({"name": "CVE", "module": "exploit/linux/ssh/foo"})
    assert "T1190" in techs2


def test_detection_for_known_and_unknown():
    d = detection_for("T1046")
    assert d["name"] == "Network Service Discovery"
    assert "event_ids" in d["detection"]
    u = detection_for("T9999")
    assert u["name"] == "Unknown"


def test_catalog_nonempty():
    assert len(TECHNIQUES) >= 10


def test_enrich_engagement(tmp_path):
    store = EngagementStore(tmp_path / "e.db")
    e = store.create_engagement("acme", ["10.0.0.0/24"])
    store.ingest_scan(
        e["id"],
        {
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 22, "service": "ssh"}]}
            ],
            "vulns": [
                {"host": "10.0.0.5", "name": "OpenSSH outdated", "severity": "high"}
            ],
            "credentials": [
                {
                    "host": "10.0.0.5",
                    "port": 22,
                    "service": "ssh",
                    "user": "root",
                    "password": "toor",
                    "verified": True,
                }
            ],
        },
    )
    res = enrich_engagement(store, e["id"])
    assert res["techniques"]
    assert any(
        "T1021" in it["techniques"] or "T1190" in it["techniques"]
        for it in res["items"]
    )
    assert all("detection" in it for it in res["items"])
