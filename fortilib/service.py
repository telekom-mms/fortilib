from fortilib.base import FortigateNamedObject


class FortigateService(FortigateNamedObject):
    """Fortigate object for services.

    :ivar protocol: Name of internet protocol \
        ("TCP", "UDP", "TCP/UDP/SCTP", "ICMP", "ICMP6", "IP")
    """

    def __init__(self):
        super().__init__()

        self.protocol: str = ""
        self.visibility: str = "enable"

    def __eq__(self, other):
        if isinstance(other, FortigateService):
            return self.name == other.name and self.protocol == other.protocol

        return False

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.protocol = object_data.get("protocol", self.protocol)
        self.visibility = object_data.get("visibility", self.visibility)


class FortigateTCPUDPService(FortigateService):
    """Fortigate object for TCP/UDP services.

    :ivar protocol: Name of internet protocol (default: "TCP/UDP/SCTP")
    :ivar tcp_portrange: Port number for TCP (default: "")
    :ivar udp_portrange: Port number for UDP (default: "")
    """

    def __init__(self):
        super().__init__()

        self.protocol = "TCP/UDP/SCTP"
        self.tcp_portrange: str = ""
        self.udp_portrange: str = ""

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.tcp_portrange = object_data.get(
            "tcp-portrange", self.tcp_portrange
        )
        self.udp_portrange = object_data.get(
            "udp-portrange", self.udp_portrange
        )

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "test_service_tcp_udp",
                    "protocol": "TCP/UDP/SCTP",
                    "tcp-portrange": "80",
                    "udp-portrange": "",
                    "comment": "Test comment",
                }
        """
        return {
            "name": self.name,
            "protocol": self.protocol,
            "tcp-portrange": self.tcp_portrange,
            "udp-portrange": self.udp_portrange,
            "visibility": self.visibility,
            "comment": self.comment,
        }


class FortigateICMPService(FortigateService):
    """Fortigate object for ICMP services.

    :ivar protocol: Name of internet protocol (default: "ICMP")
    :ivar icmptype: ICMP type e.g. 8 (default: 0)
    :ivar icmpcode: ICMP code (default: "")
    """

    def __init__(self):
        super().__init__()

        self.protocol = "ICMP"
        self.icmptype: int = 0
        self.icmpcode: str = ""

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.icmptype = object_data.get("icmptype", self.icmptype)
        self.icmpcode = object_data.get("icmpcode", self.icmpcode)

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "test_service_icmp",
                    "protocol": "ICMP",
                    "icmptype": 8,
                    "icmpcode": "",
                    "comment": "Test comment",
                }

        """
        return {
            "name": self.name,
            "protocol": self.protocol,
            "icmptype": self.icmptype,
            "icmpcode": self.icmpcode,
            "comment": self.comment,
        }


class FortigateICMP6Service(FortigateICMPService):
    """Fortigate object for ICMP6 services.

    :ivar protocol: Name of internet protocol (default: "ICMP6")
    """

    def __init__(self):
        super().__init__()

        self.protocol = "ICMP6"

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "test_service_icmp6",
                    "protocol": "ICMP6",
                    "icmptype": "",
                    "comment": "Test comment",
                }

        """
        return {
            "name": self.name,
            "protocol": self.protocol,
            "icmptype": self.icmptype,
            "comment": self.comment,
        }


class FortigateIPService(FortigateService):
    """Fortigate object for IP services.

    :ivar protocol: Name of internet protocol (default: "IP")
    :ivar protocol_number: Protocol number (default: 0)
    """

    def __init__(self):
        super().__init__()

        self.protocol = "IP"
        self.protocol_number: int = 0

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.protocol_number = object_data.get(
            "protocol-number", self.protocol_number
        )

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "test_service_ip",
                    "protocol": "IP",
                    "protocol-number": 47,
                    "comment": "Test comment",
                }

        """
        return {
            "name": self.name,
            "protocol": self.protocol,
            "protocol-number": self.protocol_number,
            "comment": self.comment,
        }


class FortigateProxyService(FortigateService):
    """Fortigate object for IP services.

    :ivar protocol: Name of internet protocol (default: "ALL")
    :ivar proxy: proxy flag (default: "enable")
    :ivar tcp_portrange: Port number for TCP (default: "")
    """

    def __init__(self):
        super().__init__()

        self.protocol = "ALL"
        self.proxy = "enable"
        self.tcp_portrange: str = ""

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.proxy = object_data.get("proxy", self.proxy)
        self.tcp_portrange = object_data.get(
            "tcp-portrange", self.tcp_portrange
        )

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "test_service_proxy",
                    "protocol": "ALL",
                    "proxy": "enable",
                    "tcp-portrange": "443",
                    "comment": "Test comment",
                }

        """
        return {
            "name": self.name,
            "protocol": self.protocol,
            "proxy": self.proxy,
            "tcp-portrange": self.tcp_portrange,
            "comment": self.comment,
        }
