from typing import Annotated

from pydantic import BeforeValidator, Field, PlainSerializer

from fortilib import (
    PortRange,
    deserialize_enable_disable_bool,
    serialise_enable_disable_bool,
)
from fortilib.base import (
    FortigateCommentedObject,
    FortigateNameIdentifiedObject,
)


class FortigateService(
    FortigateNameIdentifiedObject,
    FortigateCommentedObject,
):
    visibility: Annotated[
        bool,
        PlainSerializer(serialise_enable_disable_bool),
        BeforeValidator(deserialize_enable_disable_bool),
    ] = True


class FortigateTCPUDPService(FortigateService):
    protocol: str = Field(default="TCP/UDP/UDP-Lite/SCTP", frozen=True)
    tcp_portrange: Annotated[
        PortRange | None,
        PlainSerializer(PortRange.serialize),
        BeforeValidator(PortRange.deserialize),
    ] = None
    udp_portrange: Annotated[
        PortRange | None,
        PlainSerializer(PortRange.serialize),
        BeforeValidator(PortRange.deserialize),
    ] = None


class FortigateICMPService(FortigateService):
    protocol: str = Field(default="ICMP", frozen=True)
    icmptype: int = Field(default=0, ge=0, le=255)
    icmpcode: int = Field(default=0, ge=0, le=255)


class FortigateICMP6Service(FortigateICMPService):
    protocol: str = Field(default="ICMP6", frozen=True)


class FortigateIPService(FortigateService):
    protocol: str = Field(default="IP", frozen=True)
    protocol_number: int = 0


class FortigateProxyService(FortigateService):
    protocol: str = Field(default="ALL", frozen=True)
    proxy: Annotated[
        bool,
        PlainSerializer(serialise_enable_disable_bool),
        BeforeValidator(deserialize_enable_disable_bool),
    ] = True
    tcp_portrange: str = ""
