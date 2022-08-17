from unittest.mock import MagicMock

from fortilib import get_by
from fortilib.address import (
    FortigateFQDN,
    FortigateIpMask,
    FortigateIpRange,
)
from fortilib.addressgroup import FortigateAddressGroup
from tests import (
    FortigateTest,
    data,
)


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_address_group_simple(self):
        group: FortigateAddressGroup = get_by(
            "name", "test group 1", self.fw.address_groups
        )
        self.assertEqual(
            group.render(),
            {
                "name": "test group 1",
                "member": [
                    {"name": "FQDN_aadcdn.msauth.net"},
                    {"name": "NET_198.141.216.0_22"},
                ],
                "comment": "",
                "color": 3,
            },
        )
        self.assertEqual(len(group.member), 2)
        self.assertEqual(group.member[0].name, "FQDN_aadcdn.msauth.net")
        self.assertEqual(isinstance(group.member[0], FortigateFQDN), True)
        self.assertEqual(group.member[1].name, "NET_198.141.216.0_22")
        self.assertEqual(isinstance(group.member[1], FortigateIpMask), True)

    def test_firewall_base_address_group_nested(self):
        group: FortigateAddressGroup = get_by(
            "name", "test group 2", self.fw.address_groups
        )
        self.assertEqual(
            group.render(),
            {
                "name": "test group 2",
                "member": [
                    {"name": "test group 1"},
                ],
                "comment": "",
                "color": 3,
            },
        )
        self.assertEqual(len(group.member), 1)
        self.assertEqual(group.member[0].name, "test group 1")
        self.assertEqual(
            isinstance(group.member[0], FortigateAddressGroup), True
        )

    def test_firewall_base_address_group_mixed(self):
        group: FortigateAddressGroup = get_by(
            "name", "test group 3", self.fw.address_groups
        )
        self.assertEqual(
            group.render(),
            {
                "name": "test group 3",
                "member": [
                    {"name": "RANGE_10.188.128.106-108"},
                    {"name": "test group 1"},
                ],
                "comment": "",
                "color": 3,
            },
        )
        self.assertEqual(len(group.member), 2)
        self.assertEqual(group.member[0].name, "test group 1")
        self.assertEqual(
            isinstance(group.member[0], FortigateAddressGroup), True
        )
        self.assertEqual(group.member[1].name, "RANGE_10.188.128.106-108")
        self.assertEqual(isinstance(group.member[1], FortigateIpRange), True)

    def test_firewall_base_address_group_member_not_found(self):
        self.fw.fortigate.get_firewall_address_group = MagicMock(
            return_value=data.address_groups_member_missing
        )

        with self.assertRaises(Exception) as ex:
            self.fw.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "group member 'missing member' of group 'test group 4' not found",
        )
