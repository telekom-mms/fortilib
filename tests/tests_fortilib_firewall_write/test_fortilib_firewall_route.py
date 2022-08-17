import ipaddress

from fortilib import get_by
from fortilib.routes import FortigateStaticRoute
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_route_static_create(self):
        route = FortigateStaticRoute()
        route.gateway = ipaddress.ip_address("10.0.0.1")
        route.dst = ipaddress.ip_network("192.168.32.0/24")
        route.seq_num = self.fw.get_next_free_static_route_seq_number()
        route.comment = "Kommentar"

        self.fw.create_firewall_route_static(route)

        self.fw.fortigate.create_firewall_route_static.assert_called_once()
        self.fw.fortigate.create_firewall_route_static.assert_called_with(
            str(route.seq_num),
            {
                "status": "enable",
                "seq-num": route.seq_num,
                "dst": "192.168.32.0 255.255.255.0",
                "gateway": "10.0.0.1",
                "distance": 10,
                "weight": 0,
                "priority": 1,
                "device": "",
                "comment": "Kommentar",
            },
        )
        self.assertTrue(route in self.fw.static_routes)

    def test_firewall_base_route_static_update(self):
        route: FortigateStaticRoute = get_by(
            "seq_num", 24, self.fw.static_routes
        )

        route.gateway = ipaddress.ip_address("10.0.0.2")

        self.fw.update_firewall_route_static(route)

        self.fw.fortigate.update_firewall_route_static.assert_called_once()
        self.fw.fortigate.update_firewall_route_static.assert_called_with(
            "24",
            {
                "status": "enable",
                "seq-num": 24,
                "dst": "199.40.0.0 255.254.0.0",
                "gateway": "10.0.0.2",
                "distance": 10,
                "weight": 0,
                "priority": 0,
                "device": "port4",
                "comment": "CN",
            },
        )

    def test_firewall_base_route_static_delete(self):
        route: FortigateStaticRoute = get_by(
            "seq_num", 24, self.fw.static_routes
        )

        self.fw.delete_firewall_route_static(route)

        self.fw.fortigate.delete_firewall_route_static.assert_called_once()
        self.fw.fortigate.delete_firewall_route_static.assert_called_with(
            "24",
        )
        self.assertTrue(route not in self.fw.static_routes)
