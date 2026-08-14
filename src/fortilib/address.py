import ipaddress
from typing import Annotated

from pydantic import BeforeValidator, Field, PlainSerializer

from fortilib import deserialize_ipaddress_network, serialise_ipaddress_network
from fortilib.base import (
    FortigateColoredObject,
    FortigateCommentedObject,
    FortigateNamedObject,
)
from fortilib.interface import (
    FortigateInterfaceObject,
    InterfaceObject,
    interface_field,
)


class FortigateAddress(
    FortigateNamedObject,
    FortigateCommentedObject,
    FortigateColoredObject,
    FortigateInterfaceObject,
):
    interface: InterfaceObject = interface_field("associated-interface")


class FortigateIpMaskAddress(FortigateAddress):
    type: str = Field(default="ipmask", frozen=True)
    subnet: Annotated[
        ipaddress.IPv4Network,
        PlainSerializer(serialise_ipaddress_network),
        BeforeValidator(deserialize_ipaddress_network),
    ]


class FortigateFQDNAddress(FortigateAddress):
    type: str = Field(default="fqdn", frozen=True)
    fqdn: str


class FortigateIPRangeAddress(FortigateAddress):
    type: str = Field(default="iprange", frozen=True)
    start_ip: Annotated[
        ipaddress.IPv4Address,
        PlainSerializer(str),
        BeforeValidator(ipaddress.IPv4Address),
    ] = Field(alias="start-ip")
    end_ip: Annotated[
        ipaddress.IPv4Address,
        PlainSerializer(str),
        BeforeValidator(ipaddress.IPv4Address),
    ] = Field(alias="end-ip")
