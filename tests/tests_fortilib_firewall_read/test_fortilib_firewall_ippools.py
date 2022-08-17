import ipaddress

from fortilib import get_by
from fortilib.ippool import FortigateIPPool
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_vips(self):
        ippool: FortigateIPPool = get_by(
            "name", "Post_DynCom-SNAT", self.fw.ippools
        )
        self.assertEqual(len(self.fw.ippools), 2)
        self.assertEqual(
            ippool.render(),
            {
                "name": "Post_DynCom-SNAT",
                "type": "overload",
                "startip": "10.197.113.240",
                "endip": "10.197.113.240",
                "source-startip": "0.0.0.0",
                "source-endip": "0.0.0.0",
                "comments": "",
            },
        )
        self.assertEqual(
            ippool.startip, ipaddress.ip_address("10.197.113.240")
        )
        self.assertEqual(ippool.endip, ipaddress.ip_address("10.197.113.240"))
        self.assertEqual(
            ippool.source_startip, ipaddress.ip_address("0.0.0.0")
        )
        self.assertEqual(ippool.source_endip, ipaddress.ip_address("0.0.0.0"))
