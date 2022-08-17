from fortilib import get_by
from fortilib.servicegroup import FortigateServiceGroup
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_service_group_create(self):
        group = FortigateServiceGroup()
        group.name = "test-group"
        group.member.append(get_by("name", "DNS", self.fw.services))
        group.member.append(get_by("name", "HTTP", self.fw.services))
        group.member.append(
            get_by("name", "service group 1", self.fw.service_groups)
        )

        self.fw.create_firewall_service_group(group)

        self.fw.fortigate.create_firewall_service_group.assert_called_once()
        self.fw.fortigate.create_firewall_service_group.assert_called_with(
            "test-group",
            {
                "name": "test-group",
                "member": [
                    {"name": "DNS"},
                    {"name": "HTTP"},
                    {"name": "service group 1"},
                ],
                "comment": "",
            },
        )
        self.assertTrue(group in self.fw.service_groups)

    def test_firewall_base_service_group_update(self):
        group: FortigateServiceGroup = get_by(
            "name", "service group 1", self.fw.service_groups
        )

        self.assertEqual(
            "",
            group.comment,
        )

        group.member.append(get_by("name", "GRE", self.fw.services))
        group.comment = "Kommentar"

        self.fw.update_firewall_service_group(group)

        self.fw.fortigate.update_firewall_service_group.assert_called_once()
        self.fw.fortigate.update_firewall_service_group.assert_called_with(
            "service group 1",
            {
                "name": "service group 1",
                "member": [
                    {"name": "DNS"},
                    {"name": "GRE"},
                    {"name": "HTTP"},
                ],
                "comment": "Kommentar",
            },
        )

    def test_firewall_base_service_group_delete(self):
        group: FortigateServiceGroup = get_by(
            "name", "service group 1", self.fw.service_groups
        )

        self.fw.delete_firewall_service_group(group)

        self.fw.fortigate.delete_firewall_service_group.assert_called_once()
        self.fw.fortigate.delete_firewall_service_group.assert_called_with(
            "service group 1"
        )
        self.assertTrue(group not in self.fw.service_groups)
