"""Read-only local network discovery for the beginner UI."""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import psutil


def _default_gateways() -> dict[str, str]:
    """Read Linux's IPv4 default routes without invoking a shell command."""
    routes: dict[str, str] = {}
    route_file = Path("/proc/net/route")
    try:
        lines = route_file.read_text(encoding="ascii").splitlines()[1:]
    except (OSError, UnicodeError):
        return routes
    for line in lines:
        fields = line.split()
        if len(fields) < 4 or fields[1] != "00000000":
            continue
        try:
            gateway = str(ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(fields[2]), "little")))
        except (ValueError, IndexError):
            continue
        if gateway != "0.0.0.0":
            routes.setdefault(fields[0], gateway)
    return routes


def discover_local_network() -> dict[str, Any]:
    """Return local non-loopback IPv4 interfaces and their default gateway."""
    gateways = _default_gateways()
    interfaces: list[dict[str, Any]] = []
    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception as exc:
        return {"status": "unavailable", "interfaces": [], "default": None,
                "error": f"{type(exc).__name__}: {exc}"}

    for interface, entries in addresses.items():
        for entry in entries:
            family = getattr(entry, "family", None)
            family_name = getattr(family, "name", str(family))
            address = str(getattr(entry, "address", "")).split("%", 1)[0]
            netmask = getattr(entry, "netmask", None)
            if family_name not in {"AF_INET", "AddressFamily.AF_INET"} or not address or not netmask:
                continue
            try:
                ip = ipaddress.IPv4Address(address)
                network = ipaddress.IPv4Interface(f"{ip}/{netmask}").network
            except ValueError:
                continue
            if ip.is_loopback or ip.is_unspecified:
                continue
            item = {
                "interface": interface,
                "address": str(ip),
                "netmask": str(netmask),
                "cidr": str(network),
                "gateway": gateways.get(interface),
                "is_up": bool(getattr(stats.get(interface), "isup", True)),
            }
            interfaces.append(item)

    default = next((item for item in interfaces if item.get("gateway")), None)
    return {
        "status": "ok" if interfaces else "unavailable",
        "interfaces": interfaces,
        "default": default,
        "error": None if interfaces else "Kullanılabilir non-loopback IPv4 arayüzü bulunamadı.",
    }
