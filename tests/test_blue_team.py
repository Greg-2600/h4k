"""Blue-team handoff: layer shape, Sigma validity, determinism (offline)."""

import re
import uuid

import yaml
from services import blue_team


def _enriched():
    return {
        "engagement_id": "e1",
        "items": [
            {
                "host": "10.0.0.5",
                "item": "OpenSSH 9.2",
                "severity": "high",
                "techniques": ["T1021", "T1046"],
            },
            {
                "host": "10.0.0.5",
                "item": "hydra ssh",
                "severity": "medium",
                "techniques": ["T1110"],
            },
        ],
        "techniques": [
            {
                "id": "T1021",
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "count": 1,
            },
            {
                "id": "T1046",
                "name": "Network Service Discovery",
                "tactic": "Discovery",
                "count": 1,
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "count": 1,
            },
        ],
    }


def test_navigator_layer_shape():
    layer = blue_team.build_navigator_layer(_enriched(), "lab")
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "v4.5"
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert sorted(ids) == ["T1021", "T1046", "T1110"]
    assert all(re.match(r"^T\d{4}(\.\d{3})?$", i) for i in ids)
    assert all(t["score"] == 1 and t["enabled"] for t in layer["techniques"])
    assert layer["gradient"]["maxValue"] >= 1


def test_navigator_layer_empty_is_valid():
    layer = blue_team.build_navigator_layer({"techniques": [], "items": []}, "lab")
    assert layer["techniques"] == []
    assert layer["domain"] == "enterprise-attack"


def test_sigma_bundle_is_deterministic_and_valid_yaml():
    a = blue_team.build_sigma_bundle(_enriched(), "lab")
    b = blue_team.build_sigma_bundle(_enriched(), "lab")
    assert [r["id"] for r in a] == [r["id"] for r in b]
    assert all(r["status"] == "experimental" and r["tuned"] is False for r in a)
    assert all(r["finding_refs"] for r in a)
    docs = list(yaml.safe_load_all(blue_team.rules_to_yaml(a)))
    assert len(docs) == len(a)
    assert all("detection" in d and "logsource" in d for d in docs)
    assert all(d["id"] and uuid.UUID(d["id"]) for d in docs)
    assert any("attack.t1110" in d.get("tags", []) for d in docs)


def test_sigma_level_follows_worst_finding():
    rules = {r["title"]: r for r in blue_team.build_sigma_bundle(_enriched(), "lab")}
    assert rules["[h4k] Possible Remote Services"]["level"] == "high"
    assert rules["[h4k] Possible Brute Force"]["level"] == "medium"


def test_defender_summary_names_techniques_and_telemetry():
    md = blue_team.defender_summary(_enriched(), "lab")
    assert "T1110" in md and "Brute Force" in md
    assert "4625" in md
    assert (
        blue_team.defender_summary({"techniques": []}, "lab").count(
            "No techniques observed"
        )
        == 1
    )
