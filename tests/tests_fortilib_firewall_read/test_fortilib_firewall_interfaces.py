from fortilib import get_by
from fortilib.interface import FortigateInterface
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_interfaces(self):
        interface: FortigateInterface = get_by(
            "name", "port4", self.fw.interfaces
        )
        self.assertEqual(
            interface.render(),
            {
                "name": "port4",
                "alias": "CN",
                "ip": "10.187.88.52 255.255.255.240",
                "comment": "",
            },
        )

        interface: FortigateInterface = get_by(
            "name", "port5", self.fw.interfaces
        )
        self.assertEqual(
            interface.render(),
            {
                "name": "port5",
                "alias": "DMZ",
                "ip": "172.16.0.52 255.255.255.248",
                "comment": "",
            },
        )
