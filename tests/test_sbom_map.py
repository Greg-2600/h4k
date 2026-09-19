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


def test_reachability_from_roots():
    graph = {
        "nodes": [{"id": "pkg:app"}, {"id": "lodash"}, {"id": "orphan"}],
        "edges": [{"from": "pkg:app", "to": "lodash"}],
    }
    r = sbom.reachability_from_roots(graph)
    assert set(r) == {"pkg:app", "lodash"}  # orphan is not on any path
    assert "orphan" not in r


def test_reachability_annotates_vulnerable_reachable(tmp_path):
    # An orphan package is NOT reachable -> not "vulnerable & reachable" even
    # though it has a CVE; the app -> lodash path IS.
    f = tmp_path / "sbom.json"
    f.write_text(
        json.dumps(
            {
                "components": [
                    {"bom-ref": "pkg:app", "name": "demo", "version": "1.0"},
                    {"bom-ref": "lodash", "name": "lodash", "version": "4.17.20"},
                    {"bom-ref": "orphan", "name": "orphan", "version": "1.0"},
                ],
                "dependencies": [
                    {"ref": "pkg:app", "dependsOn": ["lodash"]},
                    {"ref": "lodash", "dependsOn": []},
                ],
            }
        ),
        encoding="utf-8",
    )
    m = sbom.build_supply_chain_map(f, {"lodash": ["CVE-1"], "orphan": ["CVE-9"]})
    assert m["summary"]["reachable_nodes"] == 2
    assert m["summary"]["vulnerable_reachable"] == 1
    node_by_id = {n["id"]: n for n in m["graph"]["nodes"]}
    assert node_by_id["lodash"]["reachable"] is True
    assert node_by_id["lodash"]["reachable_cves"] == ["CVE-1"]
    assert node_by_id["orphan"]["reachable"] is False
    assert node_by_id["orphan"]["reachable_cves"] == []


def test_reachability_cyclic_falls_back_to_all(tmp_path):
    f = tmp_path / "sbom.json"
    f.write_text(
        json.dumps(
            {
                "components": [{"bom-ref": "a", "name": "a", "version": "1.0"}],
                "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
            }
        ),
        encoding="utf-8",
    )
    gr = sbom.build_graph(f)
    # 'b' unknown: edge to a missing node; roots = {a} so only a reachable.
    r = sbom.reachability_from_roots(gr)
    assert set(r) == {"a"}


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
