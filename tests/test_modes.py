# Tests for the OPSEC mode configuration.
from services.modes import (
    MODES,
    TOR_SOCKS,
    get_mode,
    scanners_for_service,
)


def test_all_modes_present():
    assert {"stealth", "tor", "overt"} <= set(MODES)


def test_tor_proxies_use_socks():
    assert MODES["tor"].proxies == TOR_SOCKS
    assert "9050" in TOR_SOCKS


def test_stealth_and_overt_have_no_proxy():
    assert MODES["stealth"].proxies is None
    assert MODES["overt"].proxies is None


def test_stealth_is_non_invasive():
    args = MODES["stealth"].nmap_args
    # no OS detection, slow timing, limited ports
    assert "-sT" in args
    assert "-T2" in args
    assert "--top-ports" in args
    assert "100" in args
    assert "-O" not in args


def test_overt_has_os_detection():
    args = MODES["overt"].nmap_args
    assert "-O" in args
    assert "-T4" in args


def test_get_mode_falls_back_to_overt():
    assert get_mode("nonsense").name == "overt"
    assert get_mode("stealth").name == "stealth"


def test_tor_nmap_args_are_polite():
    args = MODES["tor"].nmap_args
    assert "-T2" in args


def test_scanners_for_service_known():
    ssh = scanners_for_service("ssh")
    assert "auxiliary/scanner/ssh/ssh_version" in ssh
    smb = scanners_for_service("microsoft-ds")
    assert "auxiliary/scanner/smb/smb_version" in smb


def test_scanners_for_service_unknown_returns_empty():
    assert scanners_for_service("mystery-service") == []


def test_scanners_for_service_none():
    assert scanners_for_service(None) == []
