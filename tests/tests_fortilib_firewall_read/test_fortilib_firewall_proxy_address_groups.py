from unittest.mock import MagicMock

from fortilib import get_by
from fortilib.proxyaddress import FortigateProxyAddress
from fortilib.proxyaddressgroup import FortigateProxyAddressGroup
from tests import (
    FortigateTest,
    data,
)


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_proxy_address_group_simple(self):
        group: FortigateProxyAddressGroup = get_by(
            "name", "test proxy group 1", self.fw.proxy_address_groups
        )
        self.assertEqual(
            group.render(),
            {
                "name": "test proxy group 1",
                "member": [
                    {"name": "http.kali.org"},
                    {"name": "http.kali.org\\/kali"},
                ],
                "comment": "test",
                "type": "dst",
            },
        )
        self.assertEqual(len(group.member), 2)
        self.assertEqual(group.member[0].name, "http.kali.org")
        self.assertEqual(
            isinstance(group.member[0], FortigateProxyAddress), True
        )
        self.assertEqual(group.member[1].name, "http.kali.org\\/kali")
        self.assertEqual(
            isinstance(group.member[1], FortigateProxyAddress), True
        )

    def test_firewall_base_proxy_address_group_nested(self):
        group: FortigateProxyAddressGroup = get_by(
            "name", "test proxy group 2", self.fw.proxy_address_groups
        )
        self.assertEqual(
            group.render(),
            {
                "name": "test proxy group 2",
                "member": [
                    {"name": "test proxy group 1"},
                ],
                "comment": "",
                "type": "dst",
            },
        )
        self.assertEqual(len(group.member), 1)
        self.assertEqual(group.member[0].name, "test proxy group 1")
        self.assertEqual(
            isinstance(group.member[0], FortigateProxyAddressGroup), True
        )

    def test_firewall_base_proxy_address_group_mixed(self):
        group: FortigateProxyAddressGroup = get_by(
            "name", "test proxy group 3", self.fw.proxy_address_groups
        )
        self.assertEqual(
            group.render(),
            {
                "name": "test proxy group 3",
                "member": [
                    {"name": "*.azure.net"},
                    {"name": "test proxy group 1"},
                ],
                "comment": "",
                "type": "dst",
            },
        )
        self.assertEqual(len(group.member), 2)
        self.assertEqual(group.member[0].name, "*.azure.net")
        self.assertEqual(
            isinstance(group.member[0], FortigateProxyAddress), True
        )
        self.assertEqual(group.member[1].name, "test proxy group 1")
        self.assertEqual(
            isinstance(group.member[1], FortigateProxyAddressGroup), True
        )

    def test_firewall_base_proxy_address_group_member_not_found(self):
        self.fw.fortigate.get_firewall_proxy_address_group = MagicMock(
            return_value=data.proxy_address_groups_member_missing
        )

        with self.assertRaises(Exception) as ex:
            self.fw.get_all_objects()

        self.assertEqual(
            Exception,
            type(ex.exception),
        )

        self.assertEqual(
            "group member 'missing member' of group 'test proxy group 4' not found",
            str(ex.exception),
        )
