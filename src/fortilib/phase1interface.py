import ipaddress

from fortilib.base import FortigateNamedObject
from fortilib.interface import FortigateInterface
from fortilib.mixins.interface import FortigateInterfaceMixin


class FortigatePhase1Interface(FortigateNamedObject, FortigateInterfaceMixin):
    """Fortigate object for phase1 interfaces.

    :ivar default_gw: Default gateway e.g. 0.0.0.0
    :ivar dhgrp: Diffie-Hellman group e.g. 20
    :ivar dpd: Dead Peer Detection e.g. on-demand
    :ivar ike_version: IKE version e.g. 2
    :ivar interface: Interface used for traffic
    :ivar keepalive: Keepalive time in seconds e.g. 10
    :ivar keylife: Key Lifetime for phase1 e.g. 86400
    :ivar localid: Local ID
    :ivar nattraversal: NAT Traversal e.g. disable
    :ivar proposal: Encryption algorithms and pseudo random function e.g. chacha20poly1305-prfsha256
    :ivar psksecret: Pre-shared Key
    :ivar remote_gw: Remote gateway
    """

    def __init__(self):
        super().__init__()

        self.default_gw: ipaddress.IPv4Network = None
        self.dhgrp: str = ""
        self.dpd: str = ""
        self.ike_version: str = "2"
        self.interface: FortigateInterface = None
        self.keepalive: int = None
        self.keylife: int = None
        self.nattraversal: str = ""
        self.localid: str = ""
        self.proposal: str = ""
        self.psksecret: str = ""
        self.remote_gw: ipaddress.IPv4Network = None

    def __eq__(self, other):
        if isinstance(other, FortigatePhase1Interface):
            return (
                self.name == other.name
                and self.default_gw == other.default_gw
                and self.remote_gw == other.remote_gw
            )

        return False

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.default_gw = ipaddress.IPv4Address(
            object_data.get("default-gw", self.default_gw)
        )
        self.dhgrp = object_data.get("dhgrp", self.dhgrp)
        self.dpd = object_data.get("dpd", self.dpd)
        self.ike_version = object_data.get("ike-version", self.ike_version)
        self.keepalive = object_data.get("keepalive", self.keepalive)
        self.keylife = object_data.get("keylife", self.keylife)
        self.localid = object_data.get("localid", self.localid)
        self.nattraversal = object_data.get("nattraversal", self.nattraversal)
        self.proposal = object_data.get("proposal", self.proposal)
        self.psksecret = object_data.get("psksecret", self.psksecret)
        self.remote_gw = ipaddress.IPv4Address(
            object_data.get("remote-gw", self.remote_gw)
        )
        self.comment = object_data.get("comments", self.comment)

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "vpn_phase1",
                    "default-gw": "0.0.0.0",
                    "dhgrp": "20",
                    "dpd": "on-demand",
                    "ike-version": "2",
                    "interface": "port1",
                    "keepalive": 10,
                    "keylife": 86400,
                    "localid": "",
                    "nattraversal": "disable",
                    "proposal": "chacha20poly1305-prfsha256 aes256gcm-prfsha384",
                    "psksecret": "ENC XXXX",
                    "remote-gw": "1.1.1.1",
                    "comments": "",
                },
        """
        return {
            "name": self.name,
            "default-gw": str(self.default_gw),
            "dhgrp": self.dhgrp,
            "dpd": self.dpd,
            "ike-version": self.ike_version,
            "interface": self.interface.name if self.interface else "",
            "keepalive": self.keepalive,
            "keylife": self.keylife,
            "localid": self.localid,
            "nattraversal": self.nattraversal,
            "proposal": self.proposal,
            "psksecret": self.psksecret,
            "remote-gw": str(self.remote_gw),
            "comments": self.comment,
        }

    def __repr__(self):
        return f"{self.__class__.__name__} {self.name} Default Gateway: {self.default_gw} Remote Gateway: {self.remote_gw}"
