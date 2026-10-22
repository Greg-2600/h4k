# Tests for version_detector.py
import pytest

from h4k.api.services.version_detector import (
    VersionDetector,
    check_vulnerable_version,
    compare_versions,
    detect_software,
    extract_versions,
    is_version_vulnerable,
    normalize_version,
    parse_version,
)


class TestNormalizeVersion:
    @pytest.mark.parametrize(
        "version,expected",
        [
            ("1.2.3", (1, 2, 3)),
            ("2.0", (2, 0)),
            ("10.20.30", (10, 20, 30)),
            ("1.2.3-alpha", (1, 2, 3)),
            ("1.2.3p1", (1, 2, 31)),
            ("v1.2.3", (1, 2, 3)),
            ("1.2.3-beta2", (1, 2, 32)),
            ("1.2.3-rc1", (1, 2, 31)),
        ],
    )
    def test_normalize_version(self, version, expected):
        assert normalize_version(version) == expected

    def test_normalize_empty(self):
        assert normalize_version("abc") == ()

    def test_normalize_mixed(self):
        assert normalize_version("v1.2.3-beta") == (1, 2, 3)


class TestCompareVersions:
    @pytest.mark.parametrize(
        "v1,v2,expected",
        [
            ("1.0.0", "2.0.0", -1),
            ("2.0.0", "1.0.0", 1),
            ("1.0.0", "1.0.0", 0),
            ("1.2.3", "1.2.4", -1),
            ("1.2.3", "1.2.3-alpha", 0),
            ("10.0.0", "2.0.0", 1),
        ],
    )
    def test_compare_versions(self, v1, v2, expected):
        assert compare_versions(v1, v2) == expected


class TestExtractVersions:
    def test_extract_ssh_version(self):
        results = extract_versions("SSH-2.0-OpenSSH_7.9p1", "ssh")
        assert len(results) >= 1
        versions = [r["version"] for r in results]
        assert "7.9p1" in versions or "7.9" in versions

    def test_extract_http_server(self):
        results = extract_versions("Server: Apache/2.4.49", "http")
        assert len(results) >= 1
        versions = [r["version"] for r in results]
        assert any("Apache" in v or "2.4.49" in v for v in versions)

    def test_extract_nginx(self):
        results = extract_versions("Server: nginx/1.20.0", "http")
        versions = [r["version"] for r in results]
        assert any("nginx" in v or "1.20.0" in v for v in versions)

    def test_extract_mysql_version(self):
        results = extract_versions("5.7.31-log", "mysql")
        versions = [r["version"] for r in results]
        assert "5.7.31" in versions

    def test_extract_mariadb(self):
        results = extract_versions("5.5.5-10.4.20-MariaDB", "mysql")
        versions = [r["version"] for r in results]
        assert any("10.4.20" in v for v in versions)

    def test_extract_postgresql(self):
        results = extract_versions("PostgreSQL 13.4", "postgresql")
        versions = [r["version"] for r in results]
        assert "13.4" in versions

    def test_extract_redis(self):
        results = extract_versions("redis_version:6.0.16", "redis")
        versions = [r["version"] for r in results]
        assert "6.0.16" in versions

    def test_extract_generic_version(self):
        results = extract_versions("some random banner with version 1.2.3", "unknown")
        versions = [r["version"] for r in results]
        assert "1.2.3" in versions

    def test_extract_no_match(self):
        results = extract_versions("some random banner", "ssh")
        assert results == []

    def test_extract_v_pattern(self):
        results = extract_versions("myapp v2.5.0", "unknown")
        versions = [r["version"] for r in results]
        assert "2.5.0" in versions


class TestDetectSoftware:
    def test_detect_ssh(self):
        result = detect_software("SSH-2.0-OpenSSH_7.9p1", 22, "tcp")
        assert result["product"] == "ssh"
        assert result["version"] is not None

    def test_detect_http_apache(self):
        result = detect_software("Server: Apache/2.4.49", 80, "tcp")
        assert result["product"] == "http"

    def test_detect_ftp_vsftpd(self):
        result = detect_software("220-vsftpd 3.0.3", 21, "tcp")
        assert result["product"] == "ftp"

    def test_detect_redis(self):
        result = detect_software("redis_version:6.0.16", 6379, "tcp")
        assert result["product"] == "redis"

    def test_detect_mongodb(self):
        result = detect_software("MongoDB 5.0.0", 27017, "tcp")
        assert result["product"] == "mongodb"

    def test_detect_postgresql(self):
        result = detect_software("PostgreSQL 13.4", 5432, "tcp")
        assert result["product"] == "postgresql"

    def test_detect_mysql(self):
        result = detect_software("5.7.31-log MySQL Community Server", 3306, "tcp")
        assert result["product"] == "mysql"

    def test_detect_unknown(self):
        result = detect_software("some random banner", 9999, "tcp")
        assert result["product"] is None


class TestVersionDetector:
    def test_detect_empty_banner(self):
        vd = VersionDetector()
        result = vd.detect("", 80)
        assert result["product"] is None

    def test_detect_with_banner(self):
        vd = VersionDetector()
        result = vd.detect("SSH-2.0-OpenSSH_7.9p1 Debian", 22)
        assert result["product"] == "ssh"
        assert result["version"] is not None

    def test_detect_http_headers(self):
        vd = VersionDetector()
        headers = {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4"}
        result = vd.detect_from_http_headers(headers)
        assert result["product"] == "http"
        assert "Apache" in result["version"] or "2.4.49" in result["version"]


class TestParseVersion:
    @pytest.mark.parametrize(
        "version,expected",
        [
            ("1.2.3", (1, 2, 3)),
            ("v1.2.3", (1, 2, 3)),
            ("version-2.0.1", (2, 0, 1)),
            ("1.0", (1, 0)),
            ("1.2.3-alpha", (1, 2, 3)),
        ],
    )
    def test_parse_version(self, version, expected):
        assert parse_version(version) == expected


class TestIsVersionVulnerable:
    def test_within_range(self):
        assert (
            is_version_vulnerable("2.0.0", min_version="1.0.0", max_version="3.0.0")
            is True
        )

    def test_below_min(self):
        assert is_version_vulnerable("0.5.0", min_version="1.0.0") is False

    def test_above_max(self):
        assert is_version_vulnerable("5.0.0", max_version="3.0.0") is False

    def test_no_bounds(self):
        assert is_version_vulnerable("2.0.0") is True

    def test_exact_min(self):
        assert is_version_vulnerable("1.0.0", min_version="1.0.0") is True

    def test_exact_max(self):
        assert is_version_vulnerable("3.0.0", max_version="3.0.0") is True


class TestCheckVulnerableVersion:
    def test_openssh_vulnerable(self):
        result = check_vulnerable_version("openssh", "7.4")
        assert len(result) >= 1
        assert result[0]["cve"] == "CVE-2018-15473"

    def test_openssh_not_vulnerable(self):
        result = check_vulnerable_version("openssh", "9.5")
        assert result == []

    def test_apache_vulnerable(self):
        result = check_vulnerable_version("apache", "2.4.48")
        assert len(result) >= 1

    def test_unknown_product(self):
        result = check_vulnerable_version("unknownproduct", "1.0.0")
        assert result == []

    def test_multiple_cves(self):
        result = check_vulnerable_version("openssh", "8.1")
        assert len(result) >= 1
