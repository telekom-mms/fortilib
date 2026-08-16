import ipaddress
from typing import Annotated

from pydantic import BeforeValidator, Field, PlainSerializer

from fortilib import (
    deserialize_enable_disable_bool,
    serialise_enable_disable_bool,
)
from fortilib.base import (
    FortigateCommentedObjectWithCommentsAlias,
    FortigateNameIdentifiedObject,
    FortigateObject,
)


class FortigateIPPool(
    FortigateNameIdentifiedObject,
    FortigateCommentedObjectWithCommentsAlias,
):
    start_ip: Annotated[
        ipaddress.IPv4Address,
        PlainSerializer(str),
        BeforeValidator(ipaddress.IPv4Address),
    ] = Field(alias="startip")
    end_ip: Annotated[
        ipaddress.IPv4Address,
        PlainSerializer(str),
        BeforeValidator(ipaddress.IPv4Address),
    ] = Field(alias="endip")
    arp_reply: Annotated[
        bool,
        PlainSerializer(serialise_enable_disable_bool),
        BeforeValidator(deserialize_enable_disable_bool),
    ] = Field(alias="arp-reply", default=True)


class FortigateIPPoolNat64(FortigateObject):
    nat64: Annotated[
        bool,
        PlainSerializer(serialise_enable_disable_bool),
        BeforeValidator(deserialize_enable_disable_bool),
    ] = Field(default=False)


class FortigateIPPoolOverload(FortigateIPPool, FortigateIPPoolNat64):
    type: str = Field(default="overload", frozen=True)


class FortigateIPPoolOneToOne(FortigateIPPool):
    type: str = Field(default="one-to-one", frozen=True)
