from __future__ import annotations

__version__ = "1.0.16"

import ipaddress
from collections.abc import Iterable

from pydantic import BaseModel, Field


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


def serialise_enable_disable_bool(value: bool) -> str:
    return "enable" if value else "disable"


def deserialize_enable_disable_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    return value != "disable"


class FortigateMemberNotFoundError(Exception):
    """Raised when a member of a Fortigate object is not found in the search list."""


class PortRange(BaseModel):
    start_port: int = Field(gt=0, le=65536)
    end_port: int | None = Field(default=None, gt=0, le=65536)

    @classmethod
    def serialize(cls, value: "PortRange") -> str:
        if value.end_port is not None:
            return f"{value.start_port}-{value.end_port}"
        return f"{value.start_port}"

    @classmethod
    def deserialize(cls, value: str | PortRange) -> PortRange:
        if isinstance(value, PortRange):
            return value
        if "-" in value:
            start_port, end_port = value.split("-")
            return PortRange(
                start_port=int(start_port), end_port=int(end_port)
            )
        return PortRange(start_port=int(value))
