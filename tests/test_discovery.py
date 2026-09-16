# Tests for neighbor discovery and report/export routing helpers.
from services.discovery import Neighbor, NeighborFinder, _oui_vendor


def test_oui_vendor_recognized():
    assert _oui_vendor("08:00:27:aa:bb:cc") == "VirtualBox"
    assert _oui_vendor("b8:27:eb:11:22:33") == "Raspberry Pi"
    assert _oui_vendor("00:50:56:11:22:33") == "VMware"


def test_oui_vendor_none():
    assert _oui_vendor(None) is None
    assert _oui_vendor("") is None
    assert _oui_vendor("ff:ff:ff:ff:ff:ff") is None


def test_neighbor_dict_roundtrip():
    n = Neighbor(
        ip="10.0.0.1", mac="08:00:27:aa:bb:cc", vendor="VirtualBox", hostname="lab"
    )
    d = NeighborFinder.neighbors_to_dicts([n])
    assert d[0]["ip"] == "10.0.0.1"
    assert d[0]["vendor"] == "VirtualBox"


def test_arp_cache_empty_is_safe():
    # returns a list without raising (FileNotFoundError handled)
    res = NeighborFinder._arp_cache()
    assert isinstance(res, list)
