# Tests for discovery.py
from unittest.mock import MagicMock, patch

import pytest

from h4k.api.services.discovery import (
    NeighborFinder,
    _get_default_interface,
    _oui_vendor,
)


class TestOuiVendor:
    @pytest.mark.parametrize(
        "mac,expected",
        [
            ("00:50:56:ab:cd:ef", "VMware"),
            ("00:0c:29:ab:cd:ef", "VMware"),
            ("52:54:00:ab:cd:ef", "QEMU/KVM"),
            ("08:00:27:ab:cd:ef", "VirtualBox"),
            ("b8:27:eb:ab:cd:ef", "Raspberry Pi"),
            ("dc:a6:32:ab:cd:ef", "Raspberry Pi"),
            ("e4:5f:01:ab:cd:ef", "Raspberry Pi"),
            ("00:1a:4a:ab:cd:ef", "Apple"),
            ("00:03:93:ab:cd:ef", "Apple"),
            ("cc:32:e5:ab:cd:ef", "MikroTik"),
            ("00:1b:21:ab:cd:ef", "Intel"),
            ("f8:ca:b8:ab:cd:ef", "Netgear"),
            ("04:a1:51:ab:cd:ef", "TP-Link"),
            ("00:14:6c:ab:cd:ef", "Netgear"),
            ("00:0d:3a:ab:cd:ef", "Microsoft"),
            ("00:15:5d:ab:cd:ef", "Microsoft"),
            ("18:e8:29:ab:cd:ef", "Ubiquiti"),
            ("00:16:3e:ab:cd:ef", "Xen"),
            ("00:1c:58:ab:cd:ef", "Arista"),
            ("00:0d:56:ab:cd:ef", "Dell"),
            ("3c:d9:2b:ab:cd:ef", "HP"),
            ("00:23:cd:ab:cd:ef", "Western Digital"),
            ("00:00:85:ab:cd:ef", "Canon"),
            ("04:4b:ed:ab:cd:ef", "Nvidia"),
            ("00:1f:ab:cd:ef", "ASRock"),
            ("aa:bb:cc:dd:ee:ff", None),
            (None, None),
            ("", None),
            ("not:a:mac", None),
        ],
    )
    def test_oui_vendor(self, mac, expected):
        assert _oui_vendor(mac) == expected

    def test_oui_vendor_lowercase(self):
        assert _oui_vendor("00:50:56:AB:CD:EF") == "VMware"

    def test_oui_vendor_no_colons(self):
        assert _oui_vendor("005056abcdef") == "VMware"


class TestGetDefaultInterface:
    @patch("subprocess.run")
    def test_returns_interface_from_ip_route(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 1000"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = _get_default_interface()

        assert result == "eth0"
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_returns_fallback_env_var(self, mock_run):
        mock_run.side_effect = Exception("no network")

        with patch.dict("os.environ", {"H4K_NET_IFACE": "wlan0"}):
            result = _get_default_interface()

        assert result == "wlan0"

    @patch("subprocess.run")
    def test_returns_eth0_on_exception(self, mock_run):
        mock_run.side_effect = Exception("no network")

        with patch.dict("os.environ", {}, clear=True):
            result = _get_default_interface()

        assert result == "eth0"

    @patch("subprocess.run")
    def test_no_dev_in_output(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "1.1.1.1 via 10.0.0.1 src 10.0.0.42 uid 1000"
        mock_run.return_value = mock_proc

        with patch.dict("os.environ", {}, clear=True):
            result = _get_default_interface()

        assert result == "eth0"


class TestNeighborFinderInit:
    def test_init_with_interface(self):
        mock_msf = MagicMock()
        finder = NeighborFinder(mock_msf, interface="wlan0")
        assert finder.interface == "wlan0"
        assert finder.msf is mock_msf

    def test_init_without_interface(self):
        mock_msf = MagicMock()
        with patch(
            "h4k.api.services.discovery._get_default_interface", return_value="eth1"
        ):
            finder = NeighborFinder(mock_msf)
        assert finder.interface == "eth1"


class TestNeighborFinderDiscover:
    @patch("h4k.api.services.discovery.NeighborFinder._snmp_discovery")
    @patch("h4k.api.services.discovery.NeighborFinder._ipv6_neighbor_discovery")
    @patch("h4k.api.services.discovery.NeighborFinder._arp_cache")
    @patch("h4k.api.services.discovery.NeighborFinder._arp_scan")
    def test_discover_combines_all_sources(
        self, mock_arp_scan, mock_arp_cache, mock_ipv6, mock_snmp
    ):
        from schemas import Neighbor

        mock_msf = MagicMock()
        mock_msf.execute.return_value = None

        n1 = Neighbor(ip="10.0.0.1", mac="00:11:22:33:44:55")
        n2 = Neighbor(ip="10.0.0.2", mac="00:22:33:44:55:66")
        n3 = Neighbor(ip="10.0.0.3", mac="00:33:44:55:66:77")

        mock_arp_scan.return_value = [n1, n2]
        mock_arp_cache.return_value = [n1, n3]
        mock_ipv6.return_value = []
        mock_snmp.return_value = []

        finder = NeighborFinder(mock_msf, interface="eth0")
        results = finder.discover("10.0.0.0/24")

        assert len(results) == 3
        ips = {r.ip for r in results}
        assert ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
        mock_msf.execute.assert_called_once()

    @patch("h4k.api.services.discovery.NeighborFinder._snmp_discovery")
    @patch("h4k.api.services.discovery.NeighborFinder._ipv6_neighbor_discovery")
    @patch("h4k.api.services.discovery.NeighborFinder._arp_cache")
    @patch("h4k.api.services.discovery.NeighborFinder._arp_scan")
    def test_discover_deduplicates_by_ip(
        self, mock_arp_scan, mock_arp_cache, mock_ipv6, mock_snmp
    ):
        from schemas import Neighbor

        mock_msf = MagicMock()
        mock_msf.execute.return_value = None

        n1 = Neighbor(ip="10.0.0.1", mac="00:11:22:33:44:55")
        n2 = Neighbor(ip="10.0.0.1", mac="00:aa:bb:cc:dd:ee")

        mock_arp_scan.return_value = [n1]
        mock_arp_cache.return_value = [n2]
        mock_ipv6.return_value = []
        mock_snmp.return_value = []

        finder = NeighborFinder(mock_msf, interface="eth0")
        results = finder.discover("10.0.0.0/24")

        assert len(results) == 1
        assert results[0].mac == "00:11:22:33:44:55"


class TestNeighborFinderArpScan:
    @patch("subprocess.run")
    def test_parses_arp_scan_output(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = (
            "Interface: eth0\n"
            "10.0.0.1    00:50:56:ab:cd:ef    VMware\n"
            "10.0.0.2    08:00:27:12:34:56    localhost\n"
        )
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        mock_msf = MagicMock()
        finder = NeighborFinder(mock_msf, interface="eth0")
        results = finder._arp_scan("10.0.0.0/24")

        assert len(results) == 2
        assert results[0].ip == "10.0.0.1"
        assert results[0].mac == "00:50:56:ab:cd:ef"
        assert results[0].vendor == "VMware"
        assert results[1].ip == "10.0.0.2"
        assert results[1].vendor == "VirtualBox"

    @patch("subprocess.run")
    def test_returns_empty_on_error(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = "arp-scan failed"
        mock_run.return_value = mock_proc

        mock_msf = MagicMock()
        finder = NeighborFinder(mock_msf, interface="eth0")
        results = finder._arp_scan("10.0.0.0/24")

        assert results == []


class TestNeighborFinderArpCache:
    @patch("subprocess.run")
    def test_parses_arp_a_output(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = (
            "? (10.0.0.1) at 00:50:56:ab:cd:ef [ether] on eth0\n"
            "? (10.0.0.2) at 08:00:27:12:34:56 [ether] on eth0\n"
        )
        mock_run.return_value = mock_proc

        results = NeighborFinder._arp_cache()

        assert len(results) == 2
        assert results[0].ip == "10.0.0.1"
        assert results[0].mac == "00:50:56:ab:cd:ef"
        assert results[1].ip == "10.0.0.2"

    @patch("subprocess.run")
    def test_file_not_found_returns_empty(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        results = NeighborFinder._arp_cache()

        assert results == []


class TestNeighborFinderIpv6:
    @patch("subprocess.run")
    def test_ipv6_neighbor_discovery(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = (
            "192.168.1.1 dev eth0 lladdr 00:50:56:ab:cd:ef REACHABLE\n"
            "fe80::1 dev eth0 lladdr 08:00:27:12:34:56 REACHABLE\n"
        )
        mock_run.return_value = mock_proc

        mock_msf = MagicMock()
        finder = NeighborFinder(mock_msf, interface="eth0")
        results = finder._ipv6_neighbor_discovery()

        assert len(results) == 2
        assert results[0].mac == "00:50:56:ab:cd:ef"
        assert results[1].mac == "08:00:27:12:34:56"


class TestNeighborFinderSnmp:
    @patch("subprocess.run")
    def test_snmp_discovery(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = 'SNMPv2-MIB::sysDescr.0 = STRING: "Linux router, hostname: myrouter, kernel 5.10"\n'
        mock_run.return_value = mock_proc

        mock_msf = MagicMock()
        finder = NeighborFinder(mock_msf, interface="eth0")
        results = finder._snmp_discovery("10.0.0.1")

        assert len(results) == 1
        assert results[0].ip == "10.0.0.1"
        assert results[0].hostname == "myrouter"

    @patch("subprocess.run")
    def test_snmp_file_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        mock_msf = MagicMock()
        finder = NeighborFinder(mock_msf, interface="eth0")
        results = finder._snmp_discovery("10.0.0.1")

        assert results == []


class TestNeighborsToDicts:
    def test_converts_neighbors(self):
        from schemas import Neighbor

        mock_msf = MagicMock()
        finder = NeighborFinder(mock_msf)
        neighbors = [
            Neighbor(ip="10.0.0.1", mac="00:11:22:33:44:55", vendor="VMware"),
            Neighbor(ip="10.0.0.2", mac=None, vendor=None),
        ]
        result = finder.neighbors_to_dicts(neighbors)

        assert len(result) == 2
        assert result[0]["ip"] == "10.0.0.1"
        assert "mac" not in result[1]
