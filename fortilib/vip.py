import ipaddress

from fortilib.address import FortigateAddress
from fortilib.mixins.interface import FortigateInterfaceMixin


class FortigateVIP(FortigateAddress, FortigateInterfaceMixin):
    """Fortigate object for VIPs.

    :ivar interface_attribute: Overwrite variable of :class:`fortilib.mixin.interface.FortigateInterfaceMixin` (default: "extintf")
    :ivar extip: ip address (usually external/public) of starting range e.g. 172.29.210.128
    :ivar extip_end: ip address (usually external/public) of ending range e.g. 172.29.210.143
    :ivar mappedip: ip address (usually internal/private) of starting range e.g. 10.10.210.128
    :ivar mappedip_end: ip address (usually internal/private) of ending range e.g. 10.10.210.143
    :ivar extport: port (usually external/public) e.g. 8080
    :ivar mappedport: port (usually internal/private) e.g. 80
    :ivar protocol: "tcp", "udp" or "icmp"
    :ivar portforward: "enable" or "disable"
    """

    interface_attribute = "extintf"

    def __init__(self):
        super().__init__()

        self.extip: ipaddress.IPv4Address = None
        self.extip_end: ipaddress.IPv4Address = None
        self.mappedip: ipaddress.IPv4Address = None
        self.mappedip_end: ipaddress.IPv4Address = None
        self.extport: str = "0-65535"
        self.mappedport: str = "0-65535"
        self.protocol: str = ""
        self.portforward: str = "disable"
        self.type: str = ""

    def populate(self, object_data: dict):
        """Parse raw dict data to vip object.

        :param object_data: raw dict of firewall object representation
        """

        super().populate(object_data)

        extip_split = object_data.get("extip").split("-")
        mappedip_split = object_data.get("mappedip")[0]["range"].split("-")

        self.extip = ipaddress.ip_address(
            extip_split[0],
        )
        self.mappedip = ipaddress.ip_address(
            mappedip_split[0],
        )

        if len(extip_split) == 2:
            self.extip_end = ipaddress.ip_address(
                extip_split[1],
            )
            self.mappedip_end = ipaddress.ip_address(
                mappedip_split[1],
            )

        self.extport = object_data.get("extport", self.extport)
        self.mappedport = object_data.get("mappedport", self.mappedport)
        self.protocol = object_data.get("protocol", self.protocol)
        self.portforward = object_data.get("portforward", self.portforward)
        self.type = object_data.get("type", self.type)

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "test_vip",
                    "extip": "172.29.210.128-172.29.210.143"
                    "mappedip": [
                        {
                            "range": "10.10.210.128-10.10.210.143",
                        }
                    ],
                    "interface": "any",
                    "comments": "Test comment",
                }

        """
        if self.extip_end is None and self.extip_end is None:
            return {
                "name": self.name,
                "extip": f"{self.extip}",
                "mappedip": [
                    {
                        "range": f"{self.mappedip}",
                    }
                ],
                "comment": self.comment,
                "extintf": self.interface.name if self.interface else "any",
                "portforward": self.portforward,
                "protocol": self.protocol,
                "extport": self.extport,
                "mappedport": self.mappedport,
                "color": self.color,
            }
        else:
            return {
                "name": self.name,
                "extip": f"{self.extip}-{self.extip_end}",
                "mappedip": [
                    {
                        "range": f"{self.mappedip}-{self.mappedip_end}",
                    }
                ],
                "comment": self.comment,
                "extintf": self.interface.name if self.interface else "any",
                "portforward": self.portforward,
                "protocol": self.protocol,
                "extport": self.extport,
                "mappedport": self.mappedport,
                "color": self.color,
            }

    def __repr__(self):
        return f"FortigateVIP {self.name}"

    def __eq__(self, other):
        if isinstance(other, FortigateVIP):
            return (
                self.name,
                self.extip,
                self.extip_end,
                self.mappedip,
                self.mappedip_end,
                self.extport,
                self.mappedport,
            ) == (
                other.name,
                other.extip,
                other.extip_end,
                other.mappedip,
                other.mappedip_end,
                other.extport,
                other.mappedport,
            )
        return False

    def __hash__(self):
        return hash(
            (
                self.name,
                self.extip,
                self.extip_end,
                self.mappedip,
                self.mappedip_end,
                self.extport,
                self.mappedport,
            )
        )
