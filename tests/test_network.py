from types import SimpleNamespace

from secram.platforms.linux import network


def test_discover_local_network_selects_default_gateway(monkeypatch):
    monkeypatch.setattr(
        network, "_default_gateways", lambda: {"eth0": "192.168.1.1"}
    )
    monkeypatch.setattr(
        network.psutil,
        "net_if_addrs",
        lambda: {
            "lo": [SimpleNamespace(family="AF_INET", address="127.0.0.1", netmask="255.0.0.0")],
            "eth0": [SimpleNamespace(family="AF_INET", address="192.168.1.25", netmask="255.255.255.0")],
        },
    )
    monkeypatch.setattr(
        network.psutil,
        "net_if_stats",
        lambda: {"eth0": SimpleNamespace(isup=True)},
    )
    result = network.discover_local_network()
    assert result["status"] == "ok"
    assert result["default"] == {
        "interface": "eth0",
        "address": "192.168.1.25",
        "netmask": "255.255.255.0",
        "cidr": "192.168.1.0/24",
        "gateway": "192.168.1.1",
        "is_up": True,
    }


def test_discover_network_without_gateway_still_returns_interface(monkeypatch):
    monkeypatch.setattr(network, "_default_gateways", lambda: {})
    monkeypatch.setattr(
        network.psutil,
        "net_if_addrs",
        lambda: {"eth0": [SimpleNamespace(family="AF_INET", address="10.0.0.7", netmask="255.255.255.0")]},
    )
    monkeypatch.setattr(network.psutil, "net_if_stats", lambda: {})
    result = network.discover_local_network()
    assert result["status"] == "ok"
    assert result["default"] is None
    assert result["interfaces"][0]["cidr"] == "10.0.0.0/24"
