import ipaddress

from fortilib import remove_empty_dict_values
from fortilib.base import FortigateNamedObject


class FortigatePhase2KeylifeType:
    SECONDS = "seconds"
    KILOBYTES = "kbs"
    BOTH = "both"


class FortigatePhase2AddressType:
    IP = "ip"
    RANGE = "range"
    SUBNET = "subnet"


class FortigatePhase2Interface(FortigateNamedObject):
    """Fortigate object for phase2 interfaces.

    :ivar phase1_name: Name of phase1
    :ivar src_start_ip: Source address e.g. 10.0.0.10
    :ivar src_end_ip: Source address e.g. 10.0.0.20
    :ivar src_subnet: Source subnet e.g. 10.0.0.0/8
    :ivar src_addr_type: Source address type e.g. subnet
    :ivar dst_start_ip: Destination address e.g. 192.168.100.10
    :ivar dst_end_ip: Destination address e.g. 192.168.100.20
    :ivar dst_subnet: Destination subnet e.g. 192.168.100.0/24
    :ivar dst_addr_type: Destination address type e.g. subnet
    :ivar dhgrp: Diffie-Hellman group e.g. 20
    :ivar auto_negotiate: Auto-negotiate enable/disable (default: "disable")
    :ivar keepalive: Keepalive enable/disable (default: "disable")
    :ivar replay: Replay detection enable/disable (default: "enable")
    :ivar pfs: PFS feature enable/disable (default: "enable")
    :ivar keylife_seconds: Key lifetime in seconds for phase2 e.g. 14400
    :ivar keylife_kbs: Key lifetime in number of kilobytes for phase2 e.g. 5120
    :ivar keylife_type: Key lifetime type for phase2 e.g. seconds, kbs or both (default: "seconds")
    :ivar proposal: Encryption and authentication algorithms for proposal e.g. chacha20poly1305 aes256-sha512 aes256gcm
    """

    def __init__(self):
        super().__init__()

        self.phase1_name: str = ""
        self.dst_subnet: ipaddress.IPv4Network = None
        self.src_subnet: ipaddress.IPv4Network = None
        self.dst_start_ip: ipaddress.IPv4Address = None
        self.dst_end_ip: ipaddress.IPv4Address = None
        self.src_start_ip: ipaddress.IPv4Address = None
        self.src_end_ip: ipaddress.IPv4Address = None
        self.dst_addr_type: FortigatePhase2AddressType = (
            FortigatePhase2AddressType.SUBNET
        )
        self.src_addr_type: FortigatePhase2AddressType = (
            FortigatePhase2AddressType.SUBNET
        )
        self.dhgrp: str = ""
        self.auto_negotiate: str = "disable"
        self.keepalive: str = "disable"
        self.pfs: str = "enable"
        self.replay: str = "enable"
        self.keylife_seconds: int = None
        self.keylife_kbs: int = None
        self.keylife_type: FortigatePhase2KeylifeType = (
            FortigatePhase2KeylifeType.SECONDS
        )
        self.proposal: str = ""

    def __eq__(self, other):
        if isinstance(other, FortigatePhase2Interface):
            return (
                self.name == other.name
                and self.dst_subnet == other.dst_subnet
                and self.src_subnet == other.src_subnet
            )

        return False

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.phase1_name = object_data.get("phase1name", self.phase1_name)
        self.dst_addr_type = object_data.get(
            "dst-addr-type", FortigatePhase2AddressType.SUBNET
        )
        self.src_addr_type = object_data.get(
            "src-addr-type", FortigatePhase2AddressType.SUBNET
        )
        if self.dst_addr_type == "subnet":
            self.dst_subnet = ipaddress.ip_network(
                "{}/{}".format(
                    object_data.get("dst-subnet", "0.0.0.0/0").split()[0],
                    object_data.get("dst-subnet", "0.0.0.0/0").split()[1],
                )
            )

        if self.src_addr_type == FortigatePhase2AddressType.SUBNET:
            self.src_subnet = ipaddress.ip_network(
                "{}/{}".format(
                    object_data.get("src-subnet", "0.0.0.0/0").split()[0],
                    object_data.get("src-subnet", "0.0.0.0/0").split()[1],
                )
            )
        if (
            self.dst_addr_type == FortigatePhase2AddressType.IP
            or self.dst_addr_type == FortigatePhase2AddressType.RANGE
        ):
            self.dst_start_ip = ipaddress.ip_address(
                object_data.get("dst-start-ip", "0.0.0.0")
            )
            if self.dst_addr_type == FortigatePhase2AddressType.RANGE:
                self.dst_end_ip = ipaddress.ip_address(
                    object_data.get("dst-end-ip", "0.0.0.0")
                )
        if (
            self.src_addr_type == FortigatePhase2AddressType.IP
            or self.src_addr_type == FortigatePhase2AddressType.RANGE
        ):
            self.src_start_ip = ipaddress.ip_address(
                object_data.get("src-start-ip", "0.0.0.0")
            )
            if self.src_addr_type == FortigatePhase2AddressType.RANGE:
                self.src_end_ip = ipaddress.ip_address(
                    object_data.get("src-end-ip", "0.0.0.0")
                )

        self.dhgrp = object_data.get("dhgrp", self.dhgrp)
        self.auto_negotiate = object_data.get(
            "auto-negotiate", self.auto_negotiate
        )
        self.pfs = object_data.get("pfs", self.pfs)
        self.replay = object_data.get("replay", self.replay)
        self.keepalive = object_data.get("keepalive", self.keepalive)
        self.keylife_seconds = object_data.get(
            "keylifeseconds", self.keylife_seconds
        )
        self.keylife_kbs = object_data.get("keylifekbs", self.keylife_kbs)
        self.keylife_type = object_data.get("keylife-type", self.keylife_type)
        self.proposal = object_data.get("proposal", self.proposal)
        self.comment = object_data.get("comments", self.comment)

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "vpn_phase2",
                    "phase1name": "vpn_phase1",
                    "dst-addr-type": "subnet"
                    "dst-subnet": "192.168.100.0/24",
                    "dst-start-ip": "192.168.100.1",
                    "dst-end-ip": "192.168.100.128",
                    "src-addr-type": "subnet"
                    "src-subnet": "10.0.0.0/8",
                    "src-start-ip": "10.0.0.1",
                    "src-end-ip": "10.0.0.128",
                    "dhgrp": "20",
                    "pfs": "enable",
                    "replay": "enable",
                    "keepalive": "disable",
                    "auto-negotiate": "enable",
                    "keylifeseconds": 14400,
                    "keylifekbs": 5120,
                    "keylife-type": "seconds",
                    "proposal": "chacha20poly1305 aes256-sha512 aes256gcm",
                    "comments": "",
                },
        """
        return remove_empty_dict_values(
            {
                "name": self.name,
                "phase1name": self.phase1_name,
                "dst-addr-type": self.dst_addr_type,
                "dst-subnet": str(self.dst_subnet) if self.dst_subnet else "",
                "dst-start-ip": (
                    str(self.dst_start_ip) if self.dst_start_ip else ""
                ),
                "dst-end-ip": str(self.dst_end_ip) if self.dst_end_ip else "",
                "src-addr-type": self.src_addr_type,
                "src-subnet": str(self.src_subnet) if self.src_subnet else "",
                "src-start-ip": (
                    str(self.src_start_ip) if self.src_start_ip else ""
                ),
                "src-end-ip": str(self.src_end_ip) if self.src_end_ip else "",
                "dhgrp": self.dhgrp,
                "pfs": self.pfs,
                "replay": self.replay,
                "keepalive": self.keepalive,
                "auto-negotiate": self.auto_negotiate,
                "keylifeseconds": self.keylife_seconds,
                "keylifekbs": self.keylife_kbs,
                "keylife-type": self.keylife_type,
                "proposal": self.proposal,
                "comments": self.comment,
            }
        )

    def __repr__(self):
        return f"{self.__class__.__name__} {self.name} Phase1 Name: {self.phase1_name}"
