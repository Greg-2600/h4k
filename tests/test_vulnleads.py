# Tests for the version-lead (EOL/outdated) engine.
from services.vulnleads import _lt, _parse_version, analyze_service


def test_parse_version():
    assert _parse_version("OpenSSH_9.2p1") >= (9, 2)
    assert _parse_version("Apache/2.4.54") == (2, 4, 54)
    assert _parse_version("no version here") == ()


def test_lt():
    assert _lt((2, 4), (2, 5)) is True
    assert _lt((9, 2), (7, 0)) is False
    assert _lt((2, 4, 1), (2, 4)) is False


def test_old_openssh_flagged():
    leads = analyze_service("10.0.0.1", "ssh", "SSH-2.0-OpenSSH_6.7p1 Debian")
    assert any(
        lead["product"] == "openssh" and lead["level"] == "old" for lead in leads
    )


def test_modern_apache_not_flagged_below_threshold():
    # 2.4.54 is above the eol_below (2,4,0) so no 'old' lead
    leads = analyze_service("10.0.0.2", "http", "Apache/2.4.54 (Debian)")
    # note: version < (2,4,0) is old; 2.4.54 is not, so empty
    assert all(lead["level"] != "old" for lead in leads)


def test_beta_flagged():
    leads = analyze_service("10.0.0.3", "http", "nginx/1.25.0 (beta)")
    assert any(lead["level"] == "beta" for lead in leads)


def test_unknown_service_no_leads():
    assert analyze_service("10.0.0.4", "weird", "random string") == []
