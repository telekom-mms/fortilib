import ipaddress

from fortilib import get_by
from fortilib.address import FortigateAddress
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_addresses_ipmask(
        self,
    ):
        address: FortigateAddress = get_by(
            "name", "NET_198.141.216.0_22", self.fw.addresses
        )
        self.assertEqual(
            address.render(),
            {
                "type": "ipmask",
                "name": "NET_198.141.216.0_22",
                "subnet": "198.141.216.0 255.255.252.0",
                "comment": "",
                "interface": "",
                "color": 0,
            },
        )
        self.assertEqual(address.interface, None)

    def test_firewall_base_addresses_ipmask_with_interface(self):
        address: FortigateAddress = get_by(
            "name", "NET_199.40.1.0_24", self.fw.addresses
        )
        self.assertEqual(
            address.render(),
            {
                "type": "ipmask",
                "name": "NET_199.40.1.0_24",
                "subnet": "199.40.1.0 255.255.255.0",
                "comment": "test comment",
                "interface": "port4",
                "color": 0,
            },
        )
        self.assertEqual(address.interface.name, "port4")
        self.assertEqual(
            address.interface.ip,
            ipaddress.ip_interface("10.187.88.52/255.255.255.240"),
        )

    def test_firewall_base_addresses_iprange(
        self,
    ):
        address: FortigateAddress = get_by(
            "name", "RANGE_10.188.128.106-108", self.fw.addresses
        )
        self.assertEqual(
            address.render(),
            {
                "type": "iprange",
                "name": "RANGE_10.188.128.106-108",
                "start-ip": "10.188.128.106",
                "end-ip": "10.188.128.108",
                "comment": "snke 20200122 DPDHL 2020012170002501",
                "interface": "",
                "color": 0,
            },
        )
        self.assertEqual(address.interface, None)

    def test_firewall_base_addresses_fqdn(
        self,
    ):
        address: FortigateAddress = get_by(
            "name", "FQDN_aadcdn.msauth.net", self.fw.addresses
        )
        self.assertEqual(
            address.render(),
            {
                "type": "fqdn",
                "name": "FQDN_aadcdn.msauth.net",
                "fqdn": "aadcdn.msauth.net",
                "comment": "",
                "interface": "",
                "color": 19,
            },
        )
        self.assertEqual(address.interface, None)
