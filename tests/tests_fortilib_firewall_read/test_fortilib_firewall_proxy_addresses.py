from fortilib import get_by
from fortilib.proxyaddress import (
    FortigateProxyAddressHostRegex,
    FortigateProxyAddressURL,
)
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_proxy_addresses_host_regex(
        self,
    ):
        address: FortigateProxyAddressHostRegex = get_by(
            "name", "http.kali.org", self.fw.proxy_addresses
        )
        self.assertEqual(
            address.render(),
            {
                "type": "host-regex",
                "name": "http.kali.org",
                "host-regex": "^http\\.kali\\.org$",
                "comment": "http.kali.org",
            },
        )

    def test_firewall_base_proxy_addresses_url(self):
        address: FortigateProxyAddressURL = get_by(
            "name", "http.kali.org\\/kali", self.fw.proxy_addresses
        )
        address.find_host(self.fw.proxy_addresses)
        self.assertEqual(
            address.render(),
            {
                "type": "url",
                "name": "http.kali.org\\/kali",
                "host": "http.kali.org",
                "path": "\\/kali",
                "comment": "http.kali.org\\/kali",
            },
        )
