from fortilib import get_by
from fortilib.proxyaddress import (
    FortigateProxyAddressHostRegex,
    FortigateProxyAddressURL,
)
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_proxy_address_host_regex_create(self):
        address = FortigateProxyAddressHostRegex()
        address.name = "test.url.de"
        address.comment = "Kommentar"
        address.host_regex = "^test\\.url\\.de$"

        self.fw.create_firewall_proxy_address(address)

        self.fw.fortigate.create_firewall_proxy_address.assert_called_once()
        self.fw.fortigate.create_firewall_proxy_address.assert_called_with(
            "test.url.de",
            {
                "name": "test.url.de",
                "type": "host-regex",
                "host-regex": "^test\\.url\\.de$",
                "comment": "Kommentar",
            },
        )
        self.assertTrue(address in self.fw.proxy_addresses)

    def test_firewall_base_proxy_address_host_regex_update(self):
        address: FortigateProxyAddressHostRegex = get_by(
            "name", "http.kali.org", self.fw.proxy_addresses
        )

        self.assertEqual("http.kali.org", address.comment)
        self.assertEqual("^http\\.kali\\.org$", address.host_regex)

        address.name = "kali.org"
        address.host_regex = "^kali\\.org$"
        address.comment = "kali.org"

        self.fw.update_firewall_proxy_address(address)

        self.fw.fortigate.update_firewall_proxy_address.assert_called_once()
        self.fw.fortigate.update_firewall_proxy_address.assert_called_with(
            "kali.org",
            {
                "name": "kali.org",
                "type": "host-regex",
                "host-regex": "^kali\\.org$",
                "comment": "kali.org",
            },
        )

    def test_firewall_base_proxy_address_host_regex_delete(self):
        address: FortigateProxyAddressHostRegex = get_by(
            "name", "http.kali.org", self.fw.proxy_addresses
        )

        self.fw.delete_firewall_proxy_address(address)

        self.fw.fortigate.delete_firewall_proxy_address.assert_called_once()
        self.fw.fortigate.delete_firewall_proxy_address.assert_called_with(
            "http.kali.org",
        )
        self.assertTrue(address not in self.fw.proxy_addresses)

    def test_firewall_base_proxy_address_url_create(self):
        host = get_by("name", "http.kali.org", self.fw.proxy_addresses)

        address = FortigateProxyAddressURL()
        address.name = "test.url.de\\/test"
        address.comment = "Kommentar"
        address.host = host
        address.path = "\\/test"

        self.fw.create_firewall_proxy_address(address)

        self.fw.fortigate.create_firewall_proxy_address.assert_called_once()
        self.fw.fortigate.create_firewall_proxy_address.assert_called_with(
            "test.url.de\\/test",
            {
                "name": "test.url.de\\/test",
                "type": "url",
                "host": "http.kali.org",
                "path": "\\/test",
                "comment": "Kommentar",
            },
        )
        self.assertTrue(address in self.fw.proxy_addresses)

    def test_firewall_base_proxy_address_url_update(self):
        address: FortigateProxyAddressURL = get_by(
            "name", "http.kali.org\\/kali", self.fw.proxy_addresses
        )
        address.find_host(self.fw.proxy_addresses)

        self.assertEqual("http.kali.org\\/kali", address.comment)
        self.assertEqual("http.kali.org", address.host.name)
        self.assertEqual("\\/kali", address.path)

        address.name = "kali.org\\/blog"
        address.path = "\\/blog"
        address.comment = "kali.org\\/blog"

        self.fw.update_firewall_proxy_address(address)

        self.fw.fortigate.update_firewall_proxy_address.assert_called_once()
        self.fw.fortigate.update_firewall_proxy_address.assert_called_with(
            "kali.org\\/blog",
            {
                "name": "kali.org\\/blog",
                "type": "url",
                "host": "http.kali.org",
                "path": "\\/blog",
                "comment": "kali.org\\/blog",
            },
        )

    def test_firewall_base_proxy_address_url_delete(self):
        address: FortigateProxyAddressURL = get_by(
            "name", "http.kali.org\\/kali", self.fw.proxy_addresses
        )

        self.fw.delete_firewall_proxy_address(address)

        self.fw.fortigate.delete_firewall_proxy_address.assert_called_once()
        self.fw.fortigate.delete_firewall_proxy_address.assert_called_with(
            "http.kali.org\\/kali",
        )
        self.assertTrue(address not in self.fw.proxy_addresses)
