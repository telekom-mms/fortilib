from fortilib import get_by
from fortilib.proxyaddress import FortigateProxyAddressHostRegex
from fortilib.proxyaddressgroup import FortigateProxyAddressGroup
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_proxy_address_group_create(self):
        address = FortigateProxyAddressHostRegex()
        address.name = "*.azure.net"
        address.comment = "Kommentar"
        address.host_regex = "\\.azure\\.net$"

        group = FortigateProxyAddressGroup()
        group.name = "Test_Proxy_Group"
        group.member.append(address)
        group.type = "dst"

        self.fw.create_firewall_proxy_address_group(group)

        self.fw.fortigate.create_firewall_proxy_address_group.assert_called_once()
        self.fw.fortigate.create_firewall_proxy_address_group.assert_called_with(
            "Test_Proxy_Group",
            {
                "name": "Test_Proxy_Group",
                "member": [
                    {"name": "*.azure.net"},
                ],
                "comment": "",
                "type": "dst",
            },
        )
        self.assertTrue(group in self.fw.proxy_address_groups)

    def test_firewall_base_proxy_address_group_update(self):
        group: FortigateProxyAddressGroup = get_by(
            "name", "test proxy group 1", self.fw.proxy_address_groups
        )

        self.assertEqual("test", group.comment)
        self.assertEqual("http.kali.org", group.member[0].name)
        self.assertEqual("http.kali.org\\/kali", group.member[1].name)

        group.comment = "Test"
        group.member.remove(group.member[0])

        self.fw.update_firewall_proxy_address_group(group)
        self.fw.fortigate.update_firewall_proxy_address_group.assert_called_once()
        self.fw.fortigate.update_firewall_proxy_address_group.assert_called_with(
            "test proxy group 1",
            {
                "name": "test proxy group 1",
                "member": [
                    {"name": "http.kali.org\\/kali"},
                ],
                "comment": "Test",
                "type": "dst",
            },
        )

    def test_firewall_base_proxy_address_group_delete(self):
        group: FortigateProxyAddressGroup = get_by(
            "name", "test proxy group 1", self.fw.proxy_address_groups
        )

        self.fw.delete_firewall_proxy_address_group(group)
        self.fw.fortigate.delete_firewall_proxy_address_group.assert_called_once()
        self.fw.fortigate.delete_firewall_proxy_address_group.assert_called_with(
            group.name
        )
        self.assertTrue(group not in self.fw.proxy_address_groups)
