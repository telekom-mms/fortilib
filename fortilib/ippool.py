import ipaddress

from fortilib.base import FortigateNamedObject


class FortigateIPPool(FortigateNamedObject):
    """Fortigate object for ip pools.

    :ivar type: \
        see `Fortigate Docu IP Pools https://kb.fortinet.com/kb/viewContent.do?externalId=FD50126` (default: "overload")
    :ivar startip: Start of ip range
    :ivar endip: End of ip range
    :ivar source_startip: Start of source ip range
    :ivar source_endip: End of source ip range
    """

    def __init__(self):
        super().__init__()

        self.type: str = "overload"
        self.startip: ipaddress.IPv4Address = None
        self.endip: ipaddress.IPv4Address = None
        self.source_startip: ipaddress.IPv4Address = ipaddress.ip_address(
            "0.0.0.0"
        )
        self.source_endip: ipaddress.IPv4Address = ipaddress.ip_address(
            "0.0.0.0"
        )

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.comment = object_data["comments"]
        self.type = object_data["type"]
        self.startip = ipaddress.ip_address(object_data["startip"])
        self.endip = ipaddress.ip_address(object_data["endip"])
        self.source_startip = ipaddress.ip_address(
            object_data["source-startip"]
        )
        self.source_endip = ipaddress.ip_address(object_data["source-endip"])

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "Test_SNAT",
                    "type": "overload",
                    "startip": "10.10.10.1",
                    "endip": "10.10.10.1",
                    "source-startip": "0.0.0.0",
                    "source-endip": "0.0.0.0",
                    "comments": "Test comment",
                }
        """
        return {
            "name": self.name,
            "type": self.type,
            "startip": str(self.startip),
            "endip": str(self.endip),
            "source-startip": str(self.source_startip),
            "source-endip": str(self.source_endip),
            "comments": self.comment,
        }
