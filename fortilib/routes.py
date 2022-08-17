import ipaddress

from fortilib.base import FortigateObject
from fortilib.interface import FortigateInterface
from fortilib.mixins.interface import FortigateInterfaceMixin


class FortigateStaticRoute(FortigateObject, FortigateInterfaceMixin):
    """Fortigate object for static routes.

    :ivar interface_attribute: (default: "device")
    :ivar status: Status - en-/disable static routes (default: "enable")
    :ivar seq_num: Sequence number - is unique for every route like an id (default: 0)
    :ivar dst: Destination - routing subnet
    :ivar gateway: Gateway
    :ivar distance: (default: 10)
    :ivar weight: (default: 0)
    :ivar priority: (default: 1)
    :ivar interface: Interface the static route belongs to
    """

    interface_attribute = "device"

    def __init__(self):
        super().__init__()

        self.status = "enable"
        self.seq_num: int = 0
        self.dst: ipaddress.IPv4Network = None
        self.gateway: ipaddress.IPv4Address = None
        self.distance: int = 10
        self.weight: int = 0
        self.priority: int = 1
        self.interface: FortigateInterface = None

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.status = object_data["status"]
        self.seq_num = object_data["seq-num"]
        self.dst = ipaddress.ip_network(
            "{}/{}".format(
                object_data["dst"].split()[0],
                object_data["dst"].split()[1],
            )
        )
        self.gateway = ipaddress.IPv4Address(object_data["gateway"])

        self.distance = object_data["distance"]
        self.weight = object_data["weight"]
        self.priority = object_data["priority"]

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "status": "enable",
                    "seq-num": 0,
                    "dst": "10.0.0.0 255.0.0.0",
                    "gateway": "2.235.23.16",
                    "distance": 10,
                    "weight": 0,
                    "priority": 1,
                    "device": "port4",
                    "comment": "Test comment",
                }
        """
        return {
            "status": self.status,
            "seq-num": self.seq_num,
            "dst": f"{self.dst.network_address} {self.dst.netmask}",
            "gateway": str(self.gateway),
            "distance": self.distance,
            "weight": self.weight,
            "priority": self.priority,
            "device": self.interface.name if self.interface else "",
            "comment": self.comment,
        }

    def is_enabled(self) -> bool:
        return self.status == "enable"

    def __eq__(self, other):
        if isinstance(other, FortigateStaticRoute):
            return self.render() == other.render()
        return False
