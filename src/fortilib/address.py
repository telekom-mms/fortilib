import ipaddress

from fortilib.base import (
    FortigateColoredObject,
    FortigateCommentedObject,
    FortigateNamedObject,
)
from fortilib.interface import FortigateInterfaceObject


class FortigateAddress(
    FortigateNamedObject,
    FortigateCommentedObject,
    FortigateColoredObject,
    FortigateInterfaceObject,
):
    _interface_alias: str = "associated-interface"


class FortigateIpMaskAddress(FortigateAddress):
    subnet: ipaddress.IPv4Network
