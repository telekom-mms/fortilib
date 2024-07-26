import ipaddress

from fortilib import get_by
from fortilib.phase1interface import FortigatePhase1Interface
from fortilib.routes import FortigateStaticRoute
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_phase2_interfaces(self):
        phase2_interface: FortigatePhase1Interface = get_by(
            "name", "vpn_phase2", self.fw.phase2_interfaces
        )
        self.assertEqual(
            phase2_interface.render(),
            {
                "name": "vpn_phase2",
                "phase1name": "vpn_phase1",
                "dst-subnet": "192.168.100.0/24",
                "src-subnet": "10.0.0.0/8",
                "dhgrp": "20",
                "pfs": "enable",
                "replay": "enable",
                "keepalive": "disable",
                "auto-negotiate": "enable",
                "keylifeseconds": 43200,
                "keylifekbs": 5120,
                "keylife-type": "seconds",
                "proposal": "chacha20poly1305 aes256gcm",
                "comments": "test phase2",
            },
        )
        route: FortigateStaticRoute = get_by(
            "gateway",
            ipaddress.IPv4Address("10.187.88.49"),
            self.fw.static_routes,
        )
        self.assertEqual(phase2_interface == route, False)

        self.assertEqual(
            str(phase2_interface),
            "FortigatePhase2Interface vpn_phase2 Phase1 Name: vpn_phase1 SRC: 10.0.0.0/8 DST: 192.168.100.0/24",
        )
