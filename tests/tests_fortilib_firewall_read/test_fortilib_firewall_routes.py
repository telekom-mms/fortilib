import ipaddress

from fortilib import get_by
from fortilib.routes import FortigateStaticRoute
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_routes(self):
        route: FortigateStaticRoute = get_by(
            "gateway",
            ipaddress.IPv4Address("10.187.88.49"),
            self.fw.static_routes,
        )
        self.assertEqual(
            route.render(),
            {
                "status": "enable",
                "seq-num": 24,
                "gateway": "10.187.88.49",
                "dst": "199.40.0.0 255.254.0.0",
                "device": "port4",
                "distance": 10,
                "weight": 0,
                "priority": 0,
                "comment": "CN",
            },
        )
        self.assertEqual(route.interface.name, "port4")
        self.assertEqual(
            route.interface.ip,
            ipaddress.ip_interface("10.187.88.52/255.255.255.240"),
        )
        self.assertTrue(route.is_enabled())

        route: FortigateStaticRoute = get_by(
            "gateway",
            ipaddress.IPv4Address("172.16.0.54"),
            self.fw.static_routes,
        )
        self.assertEqual(
            route.render(),
            {
                "status": "enable",
                "seq-num": 1,
                "gateway": "172.16.0.54",
                "dst": "0.0.0.0 0.0.0.0",
                "device": "port5",
                "distance": 10,
                "weight": 0,
                "priority": 0,
                "comment": "default to inet",
            },
        )
        self.assertEqual(route.interface.name, "port5")
        self.assertEqual(
            route.interface.ip,
            ipaddress.ip_interface("172.16.0.52/255.255.255.248"),
        )
        self.assertTrue(route.is_enabled())
