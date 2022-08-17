import ipaddress

from fortilib.base import FortigateNamedObject


class FortigateInterface(FortigateNamedObject):
    """Fortigate object for interfaces.

    :ivar alias: Alternative name e.g. INTERNET
    :ivar ip: Interface ip
    """

    def __init__(self):
        super().__init__()

        self.alias: str = ""
        self.ip: ipaddress.IPv4Interface = None

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

        self.alias = object_data["alias"]
        self.ip = ipaddress.ip_interface(
            "{}/{}".format(
                object_data["ip"].split()[0],
                object_data["ip"].split()[1],
            )
        )

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "Internet_interface",
                    "alias": "INTERNET",
                    "ip": "2.235.23.16",
                    "comment": "Test comment",
                }
        """
        return {
            "name": self.name,
            "alias": self.alias,
            "ip": f"{self.ip.ip} {self.ip.netmask}",
            "comment": self.comment,
        }

    def __repr__(self):
        return f"{self.__class__.__name__} {self.name} IP: {self.ip} Alias: {self.alias}"
