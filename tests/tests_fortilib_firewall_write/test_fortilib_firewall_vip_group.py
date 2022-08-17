import ipaddress

from fortilib import get_by
from fortilib.interface import FortigateInterface
from fortilib.vip import FortigateVIP
from fortilib.vipgroup import FortigateVIPGroup
from tests import FortigateTest


class TestFortilibFirewallVIPGroup(FortigateTest):
    def test_firewall_base_vip_group_create(self):
        interface: FortigateInterface = FortigateInterface()
        interface.name = "any"

        vip: FortigateVIP = FortigateVIP()
        vip.name = "test_vip"
        vip.extip = ipaddress.ip_address("172.29.229.129")
        vip.extip_end = ipaddress.ip_address("172.29.229.142")
        vip.mappedip = ipaddress.ip_address("172.29.228.129")
        vip.mappedip_end = ipaddress.ip_address("172.29.228.142")
        vip.extport = "0-65535"
        vip.mappedport = "0-65535"
        vip.protocol = "tcp"
        vip.portforward = "enable"
        vip.interface = interface

        vip_group = FortigateVIPGroup()
        vip_group.name = "Test_Group"
        vip_group.member.append(vip)

        self.fw.create_firewall_vip_group(vip_group)

        self.fw.fortigate.create_firewall_vip_group.assert_called_once()
        self.fw.fortigate.create_firewall_vip_group.assert_called_with(
            "Test_Group",
            {
                "name": "Test_Group",
                "member": [
                    {"name": "test_vip"},
                ],
                "interface": "any",
                "comments": "",
                "color": 0,
            },
        )
        self.assertTrue(vip_group in self.fw.vip_groups)

    def test_firewall_base_vip_group_update(self):
        vip_group: FortigateVIPGroup = get_by(
            "name", "vip group 1", self.fw.vip_groups
        )

        self.assertEqual("test comment", vip_group.comment)
        self.assertEqual("vip_test", vip_group.member[0].name)
        self.assertEqual("vip_test_2", vip_group.member[1].name)

        vip_group.comment = "Test"
        vip_group.member.remove(vip_group.member[0])

        self.fw.update_firewall_vip_group(vip_group)
        self.fw.fortigate.update_firewall_vip_group.assert_called_once()
        self.fw.fortigate.update_firewall_vip_group.assert_called_with(
            "vip group 1",
            {
                "name": "vip group 1",
                "member": [
                    {"name": "vip_test_2"},
                ],
                "interface": "port4",
                "comments": "Test",
                "color": 0,
            },
        )

    def test_firewall_base_vip_group_delete(self):
        vip_group: FortigateVIPGroup = get_by(
            "name", "vip group 1", self.fw.vip_groups
        )

        self.fw.delete_firewall_vip_group(vip_group)
        self.fw.fortigate.delete_firewall_vip_group.assert_called_once()
        self.fw.fortigate.delete_firewall_vip_group.assert_called_with(
            vip_group.name
        )
        self.assertTrue(vip_group not in self.fw.vip_groups)
