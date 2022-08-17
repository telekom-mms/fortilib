import ipaddress

from fortilib.base import FortigateNamedObject
from fortilib.interface import FortigateInterface
from fortilib.mixins.interface import FortigateInterfaceMixin


class FortigateAddress(FortigateNamedObject, FortigateInterfaceMixin):
    """Fortigate object for addresses.

    :ivar interface: Interface the address is connected to
    """

    def __init__(self):
        super().__init__()

        self.interface: FortigateInterface = None
        self.color: int = 0

    # TODO mabye not need because super-element FortigateNamedObject implements it already -> delete?!
    def populate(self, object_data: dict):
        super().populate(object_data)

        self.color = object_data["color"]


class FortigateIpMask(FortigateAddress):
    """Fortigate object for ip mask \
        extends :class:`fortilib.address.FortigateAddress` with a subnet.

    :ivar subnet: Adress subnet e.g. "10.10.10.1/255.255.255.255"
    """

    def __init__(self):
        super().__init__()
        self.subnet: ipaddress.IPv4Network = None

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.subnet = ipaddress.ip_network(
            "{}/{}".format(
                object_data["subnet"].split()[0],
                object_data["subnet"].split()[1],
            )
        )

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "Test_address",
                    "type": "ipmask",
                    "subnet": "10.10.10.1 255.255.255.255",
                    "interface": "port4",
                    "comments": "Test comment",
                }
        """
        return {
            "name": self.name,
            "type": "ipmask",
            "subnet": f"{self.subnet.network_address} {self.subnet.netmask}",
            "comment": self.comment,
            "interface": self.interface.name if self.interface else "",
            "color": self.color,
        }


class FortigateIpRange(FortigateAddress):
    """Fortigate object for ip ranges \
        extends :class:`fortilib.address.FortigateAddress` with a ip range.

    :ivar ip_start: Start of ip range
    :ivar ip_end: End of ip range
    """

    def __init__(self):
        super().__init__()
        self.ip_start: ipaddress.IPv4Address = None
        self.ip_end: ipaddress.IPv4Address = None

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.ip_start = ipaddress.ip_address(object_data["start-ip"])
        self.ip_end = ipaddress.ip_address(object_data["end-ip"])

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "Test_ip_range",
                    "type": "iprange",
                    "start-ip": "10.10.10.1",
                    "end-ip": "10.10.10.15",
                    "interface": "port4",
                    "comments": "Test comment",
                }
        """
        return {
            "name": self.name,
            "type": "iprange",
            "start-ip": str(self.ip_start),
            "end-ip": str(self.ip_end),
            "comment": self.comment,
            "interface": self.interface.name if self.interface else "",
            "color": self.color,
        }


class FortigateFQDN(FortigateAddress):
    """Fortigate object for ip ranges \
        extends :class:`fortilib.address.FortigateAddress` with a ip range.

    :ivar fqdn: \
        Fully qualified domain name (FQDN) - use domain name e.g. "kernel.org"
    """

    def __init__(self):
        super().__init__()
        self.fqdn: str = ""

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.fqdn = object_data["fqdn"]

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "Test_fqdn",
                    "type": "fqdn",
                    "fqdn": "kernel.org",
                    "interface": "port4",
                    "comments": "Test comment",
                }
        """
        return {
            "name": self.name,
            "type": "fqdn",
            "fqdn": self.fqdn,
            "comment": self.comment,
            "interface": self.interface.name if self.interface else "",
            "color": self.color,
        }
