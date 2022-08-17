import ipaddress

from fortilib import get_by
from fortilib.interface import FortigateInterface
from fortilib.vip import FortigateVIP
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_vip_create(self):
        interface: FortigateInterface = FortigateInterface()
        interface.name = "any"

        vip: FortigateVIP = FortigateVIP()
        vip.name = "test_vip"
        vip.extip = ipaddress.ip_address("172.29.229.129")
        vip.extip_end = ipaddress.ip_address("172.29.229.142")
        vip.mappedip = ipaddress.ip_address("172.29.228.129")
        vip.mappedip_end = ipaddress.ip_address("172.29.228.142")
        vip.extport = "1-65535"
        vip.mappedport = "1-65535"
        vip.protocol = "tcp"
        vip.portforward = "enable"
        vip.interface = interface

        self.fw.create_firewall_vip(vip)

        self.fw.fortigate.create_firewall_vip.assert_called_once()
        self.fw.fortigate.create_firewall_vip.assert_called_with(
            "test_vip",
            {
                "name": "test_vip",
                "extip": "172.29.229.129-172.29.229.142",
                "mappedip": [
                    {
                        "range": "172.29.228.129-172.29.228.142",
                    }
                ],
                "comment": "",
                "extintf": "any",
                "portforward": "enable",
                "protocol": "tcp",
                "extport": "1-65535",
                "mappedport": "1-65535",
                "color": 0,
            },
        )
        self.assertTrue(vip in self.fw.vips)

    def test_firewall_base_vip_update(self):
        vip: FortigateVIP = get_by("name", "vip_test", self.fw.vips)

        self.assertEqual("", vip.comment, "")
        self.assertEqual(ipaddress.ip_address("172.29.229.129"), vip.extip)
        self.assertEqual(ipaddress.ip_address("172.29.229.142"), vip.extip_end)
        self.assertEqual(ipaddress.ip_address("192.168.229.129"), vip.mappedip)
        self.assertEqual(
            ipaddress.ip_address("192.168.229.142"), vip.mappedip_end
        )

        vip.extip = ipaddress.ip_address("172.29.229.129")
        vip.extip_end = ipaddress.ip_address("172.29.229.143")
        vip.mappedip = ipaddress.ip_address("192.168.229.129")
        vip.mappedip_end = ipaddress.ip_address("192.168.229.143")
        vip.extport = "1-65535"
        vip.mappedport = "1-65535"
        vip.protocol = "tcp"
        vip.portforward = "enable"
        vip.comment = "Kommentar"

        self.fw.update_firewall_vip(vip)

        self.fw.fortigate.update_firewall_vip.assert_called_once()
        self.fw.fortigate.update_firewall_vip.assert_called_with(
            "vip_test",
            {
                "name": "vip_test",
                "extip": "172.29.229.129-172.29.229.143",
                "mappedip": [
                    {
                        "range": "192.168.229.129-192.168.229.143",
                    }
                ],
                "comment": "Kommentar",
                "extintf": "port4",
                "portforward": "enable",
                "protocol": "tcp",
                "extport": "1-65535",
                "mappedport": "1-65535",
                "color": 0,
            },
        )

    def test_firewall_base_vip_delete(self):
        vip: FortigateVIP = get_by("name", "vip_test", self.fw.vips)

        self.fw.delete_firewall_vip(vip)

        self.fw.fortigate.delete_firewall_vip.assert_called_once()
        self.fw.fortigate.delete_firewall_vip.assert_called_with(
            "vip_test",
        )
        self.assertTrue(vip not in self.fw.vips)
