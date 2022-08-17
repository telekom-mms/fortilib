from fortilib import get_by
from fortilib.service import FortigateService
from fortilib.servicegroup import FortigateServiceGroup
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_service_group_simple(self):
        group: FortigateServiceGroup = get_by(
            "name", "service group 1", self.fw.service_groups
        )
        self.assertEqual(
            group.render(),
            {
                "name": "service group 1",
                "member": [
                    {"name": "DNS"},
                    {"name": "HTTP"},
                ],
                "comment": "",
            },
        )
        self.assertEqual(len(group.member), 2)
        self.assertEqual(group.member[0].name, "HTTP")
        self.assertEqual(isinstance(group.member[0], FortigateService), True)
        self.assertEqual(group.member[1].name, "DNS")
        self.assertEqual(isinstance(group.member[1], FortigateService), True)

    def test_firewall_base_service_group_nested(self):
        group: FortigateServiceGroup = get_by(
            "name", "service group 2", self.fw.service_groups
        )

        self.assertEqual(
            group.render(),
            {
                "name": "service group 2",
                "member": [
                    {"name": "service group 1"},
                ],
                "comment": "",
            },
        )
        self.assertEqual(len(group.member), 1)
        self.assertEqual(group.member[0].name, "service group 1")
        self.assertEqual(
            isinstance(group.member[0], FortigateServiceGroup), True
        )

    def test_firewall_base_service_group_mixed(self):
        group: FortigateServiceGroup = get_by(
            "name", "service group 3", self.fw.service_groups
        )

        self.assertEqual(
            group.render(),
            {
                "name": "service group 3",
                "member": [
                    {"name": "HTTP"},
                    {"name": "service group 1"},
                ],
                "comment": "",
            },
        )
        self.assertEqual(len(group.member), 2)
        self.assertEqual(group.member[0].name, "HTTP")
        self.assertEqual(isinstance(group.member[0], FortigateService), True)
        self.assertEqual(group.member[1].name, "service group 1")
        self.assertEqual(
            isinstance(group.member[1], FortigateServiceGroup), True
        )
