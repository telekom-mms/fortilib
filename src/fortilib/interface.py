import ipaddress
from typing import Annotated

from pydantic import BeforeValidator, Field, PlainSerializer

from fortilib import (
    deserialize_ipaddress_interface,
    serialise_ipaddress_interface,
)
from fortilib.base import (
    FortigateCommentedObject,
    FortigateNameIdentifiedObject,
    FortigateObject,
)


class FortigateInterface(
    FortigateNameIdentifiedObject, FortigateCommentedObject
):
    alias: str = ""
    address: Annotated[
        ipaddress.IPv4Interface | None,
        PlainSerializer(serialise_ipaddress_interface),
        BeforeValidator(deserialize_ipaddress_interface),
    ] = None


def serialise_interface_object(interface: FortigateInterface | None) -> str:
    if isinstance(interface, FortigateInterface):
        return interface.name

    return ""


def deserialize_interface_object(
    interface: str | FortigateInterface,
) -> FortigateInterface | None:
    if isinstance(interface, FortigateInterface):
        return interface

    if not interface:
        return None

    return FortigateInterface(name=interface)


InterfaceObject = Annotated[
    FortigateInterface | None,
    PlainSerializer(serialise_interface_object),
    BeforeValidator(deserialize_interface_object),
]


def interface_field(alias: str = "interface"):
    return Field(alias=alias, default=None)


class FortigateInterfaceObject(FortigateObject):
    interface: InterfaceObject = interface_field()
