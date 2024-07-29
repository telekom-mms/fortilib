import ipaddress

from fortilib import get_by
from fortilib.phase1interface import FortigatePhase1Interface
from fortilib.routes import FortigateStaticRoute
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_phase1_interfaces(self):
        phase1_interface: FortigatePhase1Interface = get_by(
            "name", "vpn_phase1", self.fw.phase1_interfaces
        )
        self.assertEqual(
            phase1_interface.render(),
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
                "psksecret": "123456",
                "remote-gw": "1.1.1.1",
                "comments": "test phase1",
            },
        )
        route: FortigateStaticRoute = get_by(
            "gateway",
            ipaddress.IPv4Address("10.187.88.49"),
            self.fw.static_routes,
        )
        self.assertEqual(phase1_interface == route, False)

        self.assertEqual(
            str(phase1_interface),
            "FortigatePhase1Interface vpn_phase1 Default Gateway: 0.0.0.0 Remote Gateway: 1.1.1.1",
        )
