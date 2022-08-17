from fortilib import get_by
from fortilib.vip import FortigateVIP
from fortilib.vipgroup import FortigateVIPGroup
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_vip_group_simple(self):
        group: FortigateVIPGroup = get_by(
            "name", "vip group 1", self.fw.vip_groups
        )
        self.assertEqual(
            group.render(),
            {
                "name": "vip group 1",
                "member": [
                    {"name": "vip_test"},
                    {"name": "vip_test_2"},
                ],
                "interface": "port4",
                "comments": "test comment",
                "color": 0,
            },
        )
        self.assertEqual(len(group.member), 2)
        self.assertEqual(group.member[0].name, "vip_test")
        self.assertEqual(isinstance(group.member[0], FortigateVIP), True)
        self.assertEqual(group.member[1].name, "vip_test_2")
        self.assertEqual(isinstance(group.member[1], FortigateVIP), True)

    def test_firewall_base_vip_group_nested(self):
        group: FortigateVIPGroup = get_by(
            "name", "vip group 2", self.fw.vip_groups
        )

        self.assertEqual(
            group.render(),
            {
                "name": "vip group 2",
                "member": [
                    {"name": "vip group 1"},
                ],
                "interface": "port4",
                "comments": "test comment",
                "color": 0,
            },
        )
        self.assertEqual(len(group.member), 1)
        self.assertEqual(group.member[0].name, "vip group 1")
        self.assertEqual(isinstance(group.member[0], FortigateVIPGroup), True)

    def test_firewall_base_vip_group_mixed(self):
        group: FortigateVIPGroup = get_by(
            "name", "vip group 3", self.fw.vip_groups
        )

        self.assertEqual(
            group.render(),
            {
                "name": "vip group 3",
                "member": [
                    {"name": "vip group 1"},
                    {"name": "vip_test"},
                ],
                "interface": "port4",
                "comments": "test comment",
                "color": 0,
            },
        )
        self.assertEqual(len(group.member), 2)
        self.assertEqual(group.member[0].name, "vip_test")
        self.assertEqual(isinstance(group.member[0], FortigateVIP), True)
        self.assertEqual(group.member[1].name, "vip group 1")
        self.assertEqual(isinstance(group.member[1], FortigateVIPGroup), True)
