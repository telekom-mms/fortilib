__version__ = "1.0.16"

import ipaddress
from collections.abc import Iterable


def get_by(attrname: str, attrvalue: str, haystack: Iterable):
    for o in haystack:
        if attrvalue == getattr(o, attrname):
            return o
    return None


def serialise_ipaddress_interface(
    address: ipaddress.IPv4Interface | None,
) -> str:
    if address is None:
        return ""
    return f"{address.ip} {address.netmask}"


def deserialize_ipaddress_interface(
    address: str | ipaddress.IPv4Interface,
) -> ipaddress.IPv4Interface | None:
    if isinstance(address, ipaddress.IPv4Interface):
        return address

    ip, netmask = address.split(" ")
    return ipaddress.IPv4Interface(f"{ip}/{netmask}")


def serialise_ipaddress_network(
    address: ipaddress.IPv4Network | None,
) -> str:
    if address is None:
        return ""
    return f"{address.network_address} {address.netmask}"


def deserialize_ipaddress_network(
    address: str | ipaddress.IPv4Network,
) -> ipaddress.IPv4Network | None:
    if isinstance(address, ipaddress.IPv4Network):
        return address

    ip, netmask = address.split()
    return ipaddress.IPv4Network(f"{ip}/{netmask}")


class FortigateMemberNotFoundError(Exception):
    """Raised when a member of a Fortigate object is not found in the search list."""
