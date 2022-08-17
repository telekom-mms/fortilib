import ipaddress

from fortilib import get_by
from fortilib.ippool import FortigateIPPool
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_ippool_create(self):
        ippool = FortigateIPPool()
        ippool.name = "test-pool"
        ippool.startip = ipaddress.ip_address("10.0.0.1")
        ippool.endip = ipaddress.ip_address("10.0.0.5")

        self.fw.create_firewall_ippool(ippool)

        self.fw.fortigate.create_firewall_ippool.assert_called_once()
        self.fw.fortigate.create_firewall_ippool.assert_called_with(
            "test-pool",
            {
                "name": "test-pool",
                "type": "overload",
                "startip": "10.0.0.1",
                "endip": "10.0.0.5",
                "source-startip": "0.0.0.0",
                "source-endip": "0.0.0.0",
                "comments": "",
            },
        )
        self.assertTrue(ippool in self.fw.ippools)

    def test_firewall_base_ippool_update(self):
        ippool: FortigateIPPool = get_by(
            "name", "Post_DynCom-SNAT", self.fw.ippools
        )

        self.assertEqual(
            ipaddress.ip_address("10.197.113.240"), ippool.startip
        )
        self.assertEqual(ipaddress.ip_address("10.197.113.240"), ippool.endip)
        self.assertEqual(
            ipaddress.ip_address("0.0.0.0"), ippool.source_startip
        )
        self.assertEqual(ipaddress.ip_address("0.0.0.0"), ippool.source_endip)

        ippool.endip = ipaddress.ip_address("10.197.113.241")
        ippool.comment = "Kommentar nix"

        self.fw.update_firewall_ippool(ippool)

        self.fw.fortigate.update_firewall_ippool.assert_called_once()
        self.fw.fortigate.update_firewall_ippool.assert_called_with(
            "Post_DynCom-SNAT",
            {
                "name": "Post_DynCom-SNAT",
                "type": "overload",
                "startip": "10.197.113.240",
                "endip": "10.197.113.241",
                "source-startip": "0.0.0.0",
                "source-endip": "0.0.0.0",
                "comments": "Kommentar nix",
            },
        )

    def test_firewall_base_ippool_delete(self):
        ippool: FortigateIPPool = get_by(
            "name", "Post_DynCom-SNAT", self.fw.ippools
        )

        self.fw.delete_firewall_ippool(ippool)

        self.fw.fortigate.delete_firewall_ippool.assert_called_once()
        self.fw.fortigate.delete_firewall_ippool.assert_called_with(
            "Post_DynCom-SNAT",
        )
        self.assertTrue(ippool not in self.fw.ippools)
