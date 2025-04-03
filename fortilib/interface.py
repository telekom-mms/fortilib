from __future__ import annotations

from typing import (
    Dict,
    List,
    Union,
)
import ipaddress

from fortilib import (
    get_by,
    get_fortigate_member_array,
)
from fortilib.base import FortigateNamedObject

class FortigateInterface(FortigateNamedObject):
    """Fortigate object for interfaces.

    :ivar alias: Alternative name e.g. INTERNET
    :ivar ip: Interface ip
    """

    def __init__(self):
        super().__init__()

        self.alias: str = ""
        self.type: str = ""
        self.ip: ipaddress.IPv4Interface = None
        self.zone: FortigateZone = None

    def __eq__(self, other):
        if isinstance(other, FortigateInterface):
            return (
                self.name == other.name
                and self.alias == other.alias
                and self.ip == other.ip
            )

        return False

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.alias = object_data.get("alias", self.alias)
        self.type = object_data.get("type", self.type)
        if "ip" in object_data:
            self.ip = ipaddress.ip_interface(
                "{}/{}".format(
                    object_data.get("ip", "0.0.0.0/0").split()[0],
                    object_data.get("ip", "0.0.0.0/0").split()[1],
                )
            )

    @staticmethod
    def add_zone(zone: FortigateZone) -> FortigateInterface:
        intf = FortigateInterface.from_dict({"name": zone.name, "type": "zone", "zone": zone})
        return intf

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "Internet_interface",
                    "alias": "INTERNET",
                    "type": "physical interface",
                    "ip": "2.235.23.16",
                    "comment": "Test comment",
                }
        """
        return {
            "name": self.name,
            "alias": self.alias,
            "type ": self.type,
            "ip": f"{self.ip.ip} {self.ip.netmask}",
            "comment": self.comment,
        }

    def __repr__(self):
        return f"{self.__class__.__name__} {self.name} IP: {self.ip} Alias: {self.alias} Type: {self.type}"




class FortigateZone(FortigateNamedObject):
    """Fortigate object for zones.

    :ivar alias: Alternative name e.g. INTERNET
    :ivar ip: Zone ip
    """

    def __init__(self):
        super().__init__()

        self.intf: List[FortigateInterface] = []

    def __eq__(self, other):
        if isinstance(other, FortigateZone):
            return (
                self.name == other.name
                and self.alias == other.alias
                and self.intf == other.intf
            )

        return False

    def populate(self, object_data: dict):
        super().populate(object_data)

    def find_interfaces(self, all_interfaces: List[FortigateInterface]) -> List[FortigateInterface]:
        intf_arr: List[Dict] = self.object_data.get("interface")
        for intf_dict in intf_arr:
            name = intf_dict["interface-name"]
            interface = get_by("name", name, all_interfaces)
            if interface is None:
                raise Exception(
                    f"no interface found "
                    f"with name {name}"
                )
            self.intf.append(interface)

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "Internet_zone",
                    "intf": ["eth0",],
                }
        """
        return {
            "name": self.name,
            "intf": self.intf,
        }

    def __repr__(self):
        return f"{self.__class__.__name__} {self.name} Intf: {self.intf}"

