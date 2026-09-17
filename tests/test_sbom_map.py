# Tests for the supply-chain dependency-graph map and semgrep offline mode.
import json

from services import sbom, semgrep


def _sample_sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "bom-ref": "pkg:app",
                "type": "application",
                "name": "demo",
                "version": "1.0",
            },
            {
                "bom-ref": "lodash",
                "type": "library",
                "name": "lodash",
                "version": "4.17.20",
                "licenses": [{"license": {"name": "MIT"}}],
            },
        ],
        "dependencies": [
            {"ref": "pkg:app", "dependsOn": ["lodash"]},
        ],
    }


def test_parse_sbom(tmp_path):
    f = tmp_path / "sbom.json"
    f.write_text(json.dumps(_sample_sbom()), encoding="utf-8")
    comps = sbom.parse_sbom(f)
    names = {c["name"] for c in comps}
    assert {"demo", "lodash"} <= names
    # license parsed
    lod = next(c for c in comps if c["name"] == "lodash")
    assert lod["licenses"] == ["MIT"]


def test_build_graph_edges(tmp_path):
    f = tmp_path / "sbom.json"
    f.write_text(json.dumps(_sample_sbom()), encoding="utf-8")
    gr = sbom.build_graph(f)
    assert len(gr["edges"]) == 1
    assert {"from": "pkg:app", "to": "lodash"} in gr["edges"]


def test_annotate_cves():
    gr = {
        "nodes": [{"id": "lodash", "label": "lodash@4.17.20", "cves": []}],
        "edges": [],
    }
    out = sbom.annotate_cves(gr, {"lodash": ["CVE-2021-23337"]})
    assert out["nodes"][0]["cves"] == ["CVE-2021-23337"]
    assert out["cve_total"] == 1


def test_supply_chain_map_full(tmp_path):
    f = tmp_path / "sbom.json"
    f.write_text(json.dumps(_sample_sbom()), encoding="utf-8")
    m = sbom.build_supply_chain_map(f, {"lodash": ["CVE-2021-23337"]})
    assert m["summary"]["components"] == 2
    assert m["summary"]["edges"] == 1
    assert m["summary"]["cves"] == 1


def test_semgrep_offline_detection(tmp_path, monkeypatch):
    # No bundled rules -> offline mode is False
    monkeypatch.setattr(semgrep, "OFFLINE_RULES", tmp_path / "nope")
    assert semgrep._is_offline() is False

    # With rules present -> offline mode True
    rules_dir = tmp_path / "semgrep-rules"
    rules_dir.mkdir()
    (rules_dir / "offline.yml").write_text("rules: []", encoding="utf-8")
    monkeypatch.setattr(semgrep, "OFFLINE_RULES", rules_dir)
    assert semgrep._is_offline() is True
