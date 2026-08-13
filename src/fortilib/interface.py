import ipaddress
from typing import Annotated

from pydantic import BeforeValidator, Field, PlainSerializer

from fortilib import (
    deserialize_ipaddress_interface,
    serialise_ipaddress_interface,
)
from fortilib.base import (
    FortigateCommentedObject,
    FortigateNamedObject,
    FortigateObject,
)


class FortigateInterface(FortigateNamedObject, FortigateCommentedObject):
    alias: str = ""
    address: Annotated[
        ipaddress.IPv4Interface | None,
        PlainSerializer(serialise_ipaddress_interface),
        BeforeValidator(deserialize_ipaddress_interface),
    ] = None


class FortigateInterfaceObject(FortigateObject):
    _interface_alias: str = "interface"

    interface: FortigateInterface | None = Field(alias=_interface_alias)
