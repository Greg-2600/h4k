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
    args = MODES["stealth"].base_args
    # no OS detection, slow timing
    assert "-sT" in args
    assert "-T2" in args
    assert "-O" not in args
    # Port breadth is a separate axis (depth), not baked into the mode.
    assert "--top-ports" not in args
    assert "-p-" not in args


def test_depth_controls_port_breadth_not_mode():
    for mode in ("stealth", "tor", "overt"):
        for depth, expect_top, expect_all in (
            ("quick", 100, False),
            ("standard", 1000, False),
            ("full", None, True),
        ):
            args = get_mode(mode, depth).nmap_args
            if expect_all:
                assert "-p-" in args, (mode, depth)
                assert "--top-ports" not in args, (mode, depth)
            else:
                assert "--top-ports" in args, (mode, depth)
                assert "-p-" not in args, (mode, depth)
                assert args[args.index("--top-ports") + 1] == str(expect_top)


def test_coverage_never_claims_completeness_for_partial_depth():
    assert get_mode("overt", "quick").coverage()["complete"] is False
    assert get_mode("overt", "standard").coverage()["complete"] is False
    assert get_mode("overt", "full").coverage()["complete"] is True
    assert get_mode("overt", "full").coverage()["ports_spec"] == "1-65535"
    assert get_mode("overt", "standard").coverage()["max_ports"] == 1000


def test_full_depth_relaxes_the_host_timeout():
    # A full sweep truncated by the top-ports 120s budget is a silent partial
    # result, which is exactly the bug this axis exists to prevent.
    std = get_mode("overt", "standard").nmap_args
    full = get_mode("overt", "full").nmap_args
    assert std[std.index("--host-timeout") + 1] == "120s"
    assert full[full.index("--host-timeout") + 1] == "900s"


def test_get_mode_falls_back_to_overt():
    assert get_mode("nonsense").name == "overt"
    assert get_mode("stealth").name == "stealth"


def test_unknown_depth_falls_back_to_standard():
    assert get_mode("overt", "nonsense").coverage()["depth"] == "standard"


def test_overt_has_os_detection():
    args = MODES["overt"].nmap_args
    assert "-O" in args
    assert "-T4" in args


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
