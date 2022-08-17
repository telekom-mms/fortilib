import ipaddress

from fortilib import get_by
from fortilib.address import FortigateIpMask
from fortilib.addressgroup import FortigateAddressGroup
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_address_group_create(self):
        address = FortigateIpMask()
        address.name = "Test_Net"
        address.comment = "Kommentar"
        address.subnet = ipaddress.ip_network("10.0.0.0/24")

        group = FortigateAddressGroup()
        group.name = "Test_Group"
        group.member.append(address)

        self.fw.create_firewall_address_group(group)

        self.fw.fortigate.create_firewall_address_group.assert_called_once()
        self.fw.fortigate.create_firewall_address_group.assert_called_with(
            "Test_Group",
            {
                "name": "Test_Group",
                "member": [
                    {"name": "Test_Net"},
                ],
                "comment": "",
                "color": 0,
            },
        )
        self.assertTrue(group in self.fw.address_groups)

    def test_firewall_base_address_group_update(self):
        group: FortigateAddressGroup = get_by(
            "name", "test group 1", self.fw.address_groups
        )

        self.assertEqual("", group.comment)
        self.assertEqual("FQDN_aadcdn.msauth.net", group.member[0].name)
        self.assertEqual("NET_198.141.216.0_22", group.member[1].name)

        group.comment = "Test"
        group.member.remove(group.member[0])

        self.fw.update_firewall_address_group(group)
        self.fw.fortigate.update_firewall_address_group.assert_called_once()
        self.fw.fortigate.update_firewall_address_group.assert_called_with(
            "test group 1",
            {
                "name": "test group 1",
                "member": [
                    {"name": "NET_198.141.216.0_22"},
                ],
                "comment": "Test",
                "color": 3,
            },
        )

    def test_firewall_base_address_group_delete(self):
        group: FortigateAddressGroup = get_by(
            "name", "test group 1", self.fw.address_groups
        )

        self.fw.delete_firewall_address_group(group)
        self.fw.fortigate.delete_firewall_address_group.assert_called_once()
        self.fw.fortigate.delete_firewall_address_group.assert_called_with(
            group.name
        )
        self.assertTrue(group not in self.fw.address_groups)
