"""Backlog #70: OS package audit + base-image freshness."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from services.os_package_audit import (
    ADVISORIES,
    analyze,
    analyze_image,
    parse_inventory,
    sandbox_result,
    to_ledger,
)

DPKG_LIST = """
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
||/ Name           Version       Architecture Description
+++-==============-=============-============-=========================
ii  sudo           1.8.31-1      amd64        Provide limited super user
ii  bash           5.1-6ubuntu1  amd64        GNU Bourne Again SHell
rc  openssl        1.1.1f-1      amd64        Secure Sockets Layer toolkit
"""

DPKG_QUERY = """Package: curl
Status: install ok installed
Version: 7.81.0-1
Architecture: amd64

Package: zlib1g
Status: install ok installed
Version: 1.2.11.dfsg-2
Architecture: amd64
"""

RPM_WHITESPACE = """sudo 1.9.5p2-1.el9.x86_64
bash 5.1.8-6.el9.x86_64
curl 7.81.0-1.el8.x86_64
"""

RPM_COMPACT = """sudo-1.8.31-1.el8.x86_64
python3-libs-3.6.8-18.el8.x86_64
bash-5.1.8-6.el9.x86_64
"""

APK_WHITESPACE = """sudo 1.9.5p2-r3
busybox 1.34.1-r3
musl 1.2.2-r3
"""

APK_COMPACT = """sudo-1.8.31-r0
busybox-1.34.1-r3
ca-certificates-20240226-r0
"""


def test_parse_dpkg_list_skips_headers() -> None:
    packages = parse_inventory(DPKG_LIST, "dpkg")
    assert [(p["name"], p["version"]) for p in packages] == [
        ("sudo", "1.8.31-1"),
        ("bash", "5.1-6ubuntu1"),
        ("openssl", "1.1.1f-1"),
    ]
    assert {p["ecosystem"] for p in packages} == {"dpkg"}


def test_parse_dpkg_query_blocks() -> None:
    packages = parse_inventory(DPKG_QUERY)
    assert [(p["name"], p["version"]) for p in packages] == [
        ("curl", "7.81.0-1"),
        ("zlib1g", "1.2.11.dfsg-2"),
    ]


def test_parse_rpm_whitespace_and_compact() -> None:
    whitespace = parse_inventory(RPM_WHITESPACE, "rpm")
    assert [p["name"] for p in whitespace] == ["sudo", "bash", "curl"]
    assert whitespace[0]["version"] == "1.9.5p2-1.el9.x86_64"

    compact = parse_inventory(RPM_COMPACT, "rpm")
    assert [(p["name"], p["version"]) for p in compact] == [
        ("sudo", "1.8.31-1.el8"),
        ("python3-libs", "3.6.8-18.el8"),
        ("bash", "5.1.8-6.el9"),
    ]


def test_parse_apk_whitespace_and_compact() -> None:
    whitespace = parse_inventory(APK_WHITESPACE, "apk")
    assert [p["name"] for p in whitespace] == ["sudo", "busybox", "musl"]

    compact = parse_inventory(APK_COMPACT, "apk")
    assert [(p["name"], p["version"]) for p in compact] == [
        ("sudo", "1.8.31-r0"),
        ("busybox", "1.34.1-r3"),
        ("ca-certificates", "20240226-r0"),
    ]


def test_auto_detect_and_generic_entries() -> None:
    mixed = parse_inventory("ii  sudo  1.8.31-1  amd64\nbash-5.1.8-6.el9.x86_64\n")
    assert [p["ecosystem"] for p in mixed] == ["dpkg", "rpm"]

    generic = parse_inventory("curl 7.81.0\n")
    assert generic == [{"name": "curl", "version": "7.81.0", "ecosystem": ""}]

    equals = parse_inventory("busybox=1.34.1-r3\n")
    assert equals[0]["name"] == "busybox"
    assert equals[0]["version"] == "1.34.1-r3"


def test_parse_validation_and_duplicates() -> None:
    assert parse_inventory("", "dpkg") == []
    assert len(parse_inventory("sudo 1.8.31\nsudo 1.8.31\n", "generic")) == 1
    with pytest.raises(ValueError, match="format must be"):
        parse_inventory("sudo 1.8.31", "nope")
    with pytest.raises(ValueError, match="inventory must be a string"):
        parse_inventory(42)  # type: ignore[arg-type]


def test_vulnerable_fixed_and_unknown_matching() -> None:
    vulnerable = analyze(
        packages=[{"name": "sudo", "version": "1.8.31", "ecosystem": "dpkg"}]
    )
    assert vulnerable["vulnerable_count"] == 1
    finding = vulnerable["findings"][0]
    assert finding["cve"] == "CVE-2021-3156"
    assert finding["fixed"] == "1.9.5p2"
    assert finding["severity"] == "HIGH"
    assert vulnerable["packages"][0]["status"] == "vulnerable"

    fixed = analyze(
        packages=[
            {
                "name": "sudo",
                "version": "1.9.5p2-3ubuntu1",
                "ecosystem": "dpkg",
            }
        ]
    )
    assert fixed["vulnerable_count"] == 0
    assert fixed["packages"][0]["status"] == "fixed"
    assert fixed["fixed_count"] == 1

    unknown = analyze(packages=[{"name": "sudo", "ecosystem": "dpkg"}])
    assert unknown["vulnerable_count"] == 0
    assert unknown["unknown_count"] == 1
    assert unknown["packages"][0]["status"] == "unknown"


def test_aliases_and_introduced_bounds() -> None:
    result = analyze(inventory="libssl1.1 1.1.1f-1\n", fmt="generic")
    assert result["vulnerable_count"] == 1
    assert result["findings"][0]["cve"] == "CVE-2022-0778"

    old = analyze(inventory="openssl 1.0.1f-1\n", fmt="generic")
    cves = {finding["cve"] for finding in old["findings"]}
    assert cves == {"CVE-2014-0160"}


def test_no_advisory_is_not_a_verdict() -> None:
    result = analyze(packages=["acme-tool 1.0.0"])
    verdict = result["packages"][0]
    assert verdict["status"] == "no_advisory"
    assert verdict["advisories"] == []
    assert result["vulnerable_count"] == 0


def test_analyze_validation() -> None:
    with pytest.raises(ValueError, match="packages, inventory or image required"):
        analyze()
    with pytest.raises(ValueError, match="packages must be a list"):
        analyze(packages="sudo")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="format must be"):
        analyze(packages=["sudo 1.8.31"], fmt="deb")
    with pytest.raises(ValueError, match="max_age_days must be non-negative"):
        analyze(packages=["sudo 1.8.31"], max_age_days=-1)
    with pytest.raises(ValueError, match="package name required"):
        analyze(packages=[{}])
    with pytest.raises(ValueError, match="package entries must be"):
        analyze(packages=[42])
    with pytest.raises(ValueError, match="cannot parse package entry"):
        analyze(packages=[""])
    with pytest.raises(ValueError, match="invalid as_of timestamp"):
        analyze(packages=["sudo 1.8.31"], as_of="not-a-date")
    with pytest.raises(ValueError, match="image metadata must be an object"):
        analyze(image="debian:12")  # type: ignore[arg-type]


def test_image_age_eol_and_slim_suggestions() -> None:
    result = analyze_image(
        {"base_image": "debian:10", "Created": "2021-01-01T00:00:00Z"},
        as_of=datetime(2026, 11, 27, tzinfo=UTC),
    )
    assert result["family"] == "debian"
    assert result["version"] == "10"
    assert result["age_days"] > 2000
    assert result["eol"] == "2024-06-30"
    assert result["eol_status"] == "expired"
    assert result["stale"] is True
    assert result["slim"] is False
    kinds = {finding["kind"] for finding in result["findings"]}
    assert kinds == {"eol"}
    assert any("slim" in suggestion for suggestion in result["suggestions"])


def test_image_supported_and_approaching_eol() -> None:
    supported = analyze_image(
        {"base_image": "debian:12-slim", "Created": "2026-01-01T00:00:00Z"},
        as_of=datetime(2026, 11, 27, tzinfo=UTC),
        max_age_days=365,
    )
    assert supported["eol_status"] == "supported"
    assert supported["slim"] is True
    assert supported["findings"] == []
    assert supported["suggestions"] == [
        "keep the slim base current and rebuild regularly"
    ]

    approaching = analyze_image(
        {"base_image": "debian:11", "Created": "2026-01-01T00:00:00Z"},
        as_of=datetime(2026, 7, 15, tzinfo=UTC),
    )
    assert approaching["eol_status"] == "approaching"
    assert approaching["findings"][0]["kind"] == "eol_soon"


def test_image_stale_unknown_and_missing_metadata() -> None:
    stale = analyze_image(
        {"base_image": "ubuntu:22.04", "Created": "2024-01-01T00:00:00Z"},
        as_of=datetime(2026, 11, 27, tzinfo=UTC),
        max_age_days=365,
    )
    assert stale["stale"] is True
    assert stale["findings"][0]["kind"] == "stale"

    unknown = analyze_image(
        {"base_image": "example/unknown:1.0", "Created": "2026-01-01T00:00:00Z"},
        as_of=datetime(2026, 11, 27, tzinfo=UTC),
    )
    assert unknown["family"] == ""
    assert unknown["eol_status"] == "unknown"
    assert "could not identify base image family/version" in unknown["warnings"]

    missing = analyze_image(
        {"base_image": "alpine:3.20"},
        as_of=datetime(2026, 11, 27, tzinfo=UTC),
    )
    assert missing["age_days"] is None
    assert "missing image creation timestamp" in missing["warnings"]


def test_image_labels_and_distroless() -> None:
    labelled = analyze_image(
        {
            "Config": {
                "Labels": {
                    "org.opencontainers.image.base.name": "gcr.io/distroless/base-debian11",
                    "org.opencontainers.image.created": "2026-01-01T00:00:00Z",
                }
            }
        },
        as_of=datetime(2026, 11, 27, tzinfo=UTC),
    )
    assert labelled["family"] == "debian"
    assert labelled["version"] == "11"
    assert labelled["slim"] is True


def test_to_ledger_maps_packages_and_images() -> None:
    result = analyze(
        packages=[
            {"name": "sudo", "version": "1.8.31", "ecosystem": "dpkg"},
            {"name": "bash", "version": "5.1", "ecosystem": "dpkg"},
        ],
        image={"base_image": "debian:10", "Created": "2021-01-01T00:00:00Z"},
        as_of="2026-11-27",
    )
    rows = to_ledger("10.10.10.5", result)
    modules = sorted(row["module"] for row in rows)
    assert modules == ["base-image", "os-package"]
    package = next(row for row in rows if row["module"] == "os-package")
    assert package["severity"] == "HIGH"
    assert package["cwe"] == "CWE-1395"
    assert "CVE-2021-3156" in package["name"]
    assert package["reference"] == "CVE-2021-3156"
    image = next(row for row in rows if row["module"] == "base-image")
    assert image["severity"] == "HIGH"
    assert image["cwe"] == "CWE-1104"
    assert "debian:10" in image["reference"]
    assert to_ledger("h", {"findings": [], "image": {}}) == []


def test_sandbox_result_is_canned_and_deterministic() -> None:
    result = sandbox_result()
    assert result["sandbox"] is True
    assert result["package_count"] == 4
    assert result["vulnerable_count"] == 3
    assert result["image_findings"] == 1
    assert result["image"]["eol_status"] == "expired"
    assert len(to_ledger("h", result)) == 4
    assert sandbox_result() == result


def test_advisory_table_is_well_formed() -> None:
    assert ADVISORIES
    for advisory in ADVISORIES:
        assert advisory["cve"].startswith("CVE-")
        assert advisory["package"] in advisory["aliases"]
        assert advisory["vulnerable_below"]
        assert advisory["fixed"]
        assert advisory["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _client(tmp_path: Any, monkeypatch: Any, sandbox: bool) -> Any:
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1" if sandbox else "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_router_sandbox_and_validation(tmp_path: Any, monkeypatch: Any) -> None:
    client = _client(tmp_path, monkeypatch, sandbox=True)
    response = client.post(
        "/api/source/os-package-audit",
        json={"inventory": DPKG_LIST, "image": {"base_image": "debian:10"}},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is True
    assert body["vulnerable_count"] == 3
    assert body["image_findings"] == 1
    assert body["ingested"] == 0
    assert client.post("/api/source/os-package-audit", json={}).status_code == 400
    assert (
        client.post(
            "/api/source/os-package-audit",
            json={"packages": ["sudo 1.8.31"], "engagement_id": "nope"},
        ).status_code
        == 404
    )

    engagement = client.post("/api/engagement/sandbox-seed").json()["engagement"]
    response = client.post(
        "/api/source/os-package-audit",
        json={
            "packages": [{"name": "sudo", "version": "1.8.31", "ecosystem": "dpkg"}],
            "host": "10.10.10.77",
            "engagement_id": engagement["id"],
        },
    )
    assert response.status_code == 200
    assert response.json()["ingested"] == 4
    vulns = client.get(f"/api/engagement/{engagement['id']}/vulns/effective").json()
    assert "os-package" in str(vulns)
    assert "base-image" in str(vulns)

    out_of_scope = client.post(
        "/api/source/os-package-audit",
        json={
            "packages": [{"name": "sudo", "version": "1.8.31", "ecosystem": "dpkg"}],
            "host": "203.0.113.9",
            "engagement_id": engagement["id"],
        },
    )
    assert out_of_scope.status_code == 200
    assert out_of_scope.json()["ingested"] == 0
    assert out_of_scope.json()["skipped_out_of_scope"] == ["203.0.113.9"]


def test_router_real_analysis_without_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
    client = _client(tmp_path, monkeypatch, sandbox=False)
    response = client.post(
        "/api/source/os-package-audit",
        json={
            "inventory": DPKG_LIST,
            "format": "dpkg",
            "image": {
                "base_image": "debian:12-slim",
                "Created": "2026-01-01T00:00:00Z",
            },
            "as_of": "2026-11-27",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is False
    assert body["package_count"] == 3
    assert body["vulnerable_count"] == 2
    assert body["findings"][0]["cve"] == "CVE-2021-3156"
    assert {finding["cve"] for finding in body["findings"]} == {
        "CVE-2021-3156",
        "CVE-2022-0778",
    }
    assert body["image"]["eol_status"] == "supported"

    bad = client.post(
        "/api/source/os-package-audit",
        json={"packages": ["sudo 1.8.31"], "format": "nope"},
    )
    assert bad.status_code == 400
