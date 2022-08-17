import ipaddress

from fortilib import get_by
from fortilib.vip import FortigateVIP
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_vips(self):
        vip: FortigateVIP = get_by("name", "vip_test", self.fw.vips)
        self.assertEqual(len(self.fw.vips), 2)
        self.assertEqual(
            vip.render(),
            {
                "name": "vip_test",
                "extip": "172.29.229.129-172.29.229.142",
                "mappedip": [{"range": "192.168.229.129-192.168.229.142"}],
                "comment": "",
                "extintf": "port4",
                "portforward": "disable",
                "protocol": "tcp",
                "extport": "0-65535",
                "mappedport": "0-65535",
                "color": 0,
            },
        )
        self.assertEqual(vip.interface.name, "port4")
        self.assertEqual(vip.extip, ipaddress.ip_address("172.29.229.129"))
        self.assertEqual(vip.extip_end, ipaddress.ip_address("172.29.229.142"))
        self.assertEqual(vip.mappedip, ipaddress.ip_address("192.168.229.129"))
        self.assertEqual(
            vip.mappedip_end, ipaddress.ip_address("192.168.229.142")
        )
