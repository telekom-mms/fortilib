import ipaddress

import pytest

from fortilib.interface import FortigateInterface
from tests.unittests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_interfaces(self):
        interface = FortigateInterface(name="internet")
        self.assertDictEqual(
            interface.model_dump(),
            {
                "name": "internet",
                "comment": "",
                "alias": "",
                "address": "",
            },
        )

        interface = FortigateInterface(
            name="internet",
            comment="WAN interface",
            alias="WAN interface alias",
            address=ipaddress.IPv4Interface("10.0.0.1/24"),
        )
        self.assertDictEqual(
            interface.model_dump(),
            {
                "name": "internet",
                "comment": "WAN interface",
                "alias": "WAN interface alias",
                "address": "10.0.0.1 255.255.255.0",
            },
        )

    def test_firewall_base_interfaces_from_json(self):
        data = {
            "name": "internet",
        }
        interface = FortigateInterface(**data)
        self.assertDictEqual(
            interface.model_dump(),
            {
                "name": "internet",
                "comment": "",
                "alias": "",
                "address": "",
            },
        )

        data = {
            "name": "internet",
            "comment": "WAN interface",
            "alias": "WAN interface alias",
            "address": "10.0.0.1 255.255.255.0",
        }
        interface = FortigateInterface(**data)
        self.assertDictEqual(
            interface.model_dump(),
            {
                "name": "internet",
                "comment": "WAN interface",
                "alias": "WAN interface alias",
                "address": "10.0.0.1 255.255.255.0",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_get(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/system/interface",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {"name": "internet"},
                    {
                        "name": "lan",
                        "address": "10.0.0.1 255.255.255.0",
                        "comment": "LAN Interface",
                    },
                ]
            },
        )

        interfaces = self.fw.get_interfaces()
        self.assertEqual(len(interfaces), 2)
        self.assertDictEqual(
            interfaces[0].model_dump(),
            {
                "name": "internet",
                "comment": "",
                "alias": "",
                "address": "",
            },
        )

        self.assertDictEqual(
            interfaces[1].model_dump(),
            {
                "name": "lan",
                "comment": "LAN Interface",
                "alias": "",
                "address": "10.0.0.1 255.255.255.0",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_get_empty(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/system/interface",
            params={"vdom": "root"},
        ).respond(
            json={"results": []},
        )

        interfaces = self.fw.get_interfaces()
        self.assertEqual(len(interfaces), 0)
