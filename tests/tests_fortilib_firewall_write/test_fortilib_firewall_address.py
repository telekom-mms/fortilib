import ipaddress

from fortilib import get_by
from fortilib.address import (
    FortigateAddress,
    FortigateIpMask,
)
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_address_create(self):
        address = FortigateIpMask()
        address.name = "Test_Net"
        address.comment = "Kommentar"
        address.subnet = ipaddress.ip_network("10.0.0.0/24")

        self.fw.create_firewall_address(address)

        self.fw.fortigate.create_firewall_address.assert_called_once()
        self.fw.fortigate.create_firewall_address.assert_called_with(
            "Test_Net",
            {
                "name": "Test_Net",
                "type": "ipmask",
                "subnet": "10.0.0.0 255.255.255.0",
                "comment": "Kommentar",
                "associated-interface": "",
                "color": 0,
            },
        )
        self.assertTrue(address in self.fw.addresses)

    def test_firewall_base_address_update(self):
        address: FortigateIpMask = get_by(
            "name", "NET_198.141.216.0_22", self.fw.addresses
        )

        self.assertEqual("", address.comment)
        self.assertEqual(
            ipaddress.ip_network("198.141.216.0/22"), address.subnet
        )

        address.subnet = ipaddress.ip_network("198.141.216.0/24")
        address.comment = "Kommentar"

        self.fw.update_firewall_address(address)

        self.fw.fortigate.update_firewall_address.assert_called_once()
        self.fw.fortigate.update_firewall_address.assert_called_with(
            "NET_198.141.216.0_22",
            {
                "type": "ipmask",
                "name": "NET_198.141.216.0_22",
                "subnet": "198.141.216.0 255.255.255.0",
                "comment": "Kommentar",
                "associated-interface": "",
                "color": 0,
            },
        )

    def test_firewall_base_address_delete(self):
        address: FortigateAddress = get_by(
            "name", "NET_198.141.216.0_22", self.fw.addresses
        )

        self.fw.delete_firewall_address(address)

        self.fw.fortigate.delete_firewall_address.assert_called_once()
        self.fw.fortigate.delete_firewall_address.assert_called_with(
            "NET_198.141.216.0_22",
        )
        self.assertTrue(address not in self.fw.addresses)
