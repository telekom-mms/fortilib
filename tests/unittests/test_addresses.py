import ipaddress

import pytest

from fortilib.address import (
    FortigateAddress,
    FortigateFQDNAddress,
    FortigateIpMaskAddress,
    FortigateIPRangeAddress,
)
from fortilib.interface import FortigateInterface
from tests.unittests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_address_ipmask(self):
        address = FortigateIpMaskAddress(
            name="host1", subnet=ipaddress.IPv4Network("10.0.0.0/24")
        )
        self.assertDictEqual(
            address.model_dump(),
            {
                "name": "host1",
                "comment": "",
                "color": 0,
                "subnet": "10.0.0.0 255.255.255.0",
                "associated-interface": "",
                "type": "ipmask",
            },
        )

        address = FortigateIpMaskAddress(
            name="host1",
            subnet=ipaddress.IPv4Network("10.0.0.0/24"),
            comment="Test host",
            color=1,
            interface=FortigateInterface(name="internet"),
        )
        self.assertDictEqual(
            address.model_dump(),
            {
                "name": "host1",
                "comment": "Test host",
                "color": 1,
                "subnet": "10.0.0.0 255.255.255.0",
                "associated-interface": "internet",
                "type": "ipmask",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_ipmask_get(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={"results": []},
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 0)

        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "subnet": "10.0.0.0 255.255.255.0",
                        "associated-interface": "",
                        "type": "ipmask",
                    },
                    {
                        "name": "host2",
                        "comment": "Test host 2",
                        "color": 1,
                        "subnet": "10.1.0.0 255.255.255.0",
                        "associated-interface": "internet",
                        "type": "ipmask",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 2)
        self.assertTrue(isinstance(addresses[0], FortigateIpMaskAddress))
        self.assertTrue(isinstance(addresses[1], FortigateIpMaskAddress))

        self.assertDictEqual(
            addresses[0].model_dump(),
            {
                "name": "host1",
                "comment": "",
                "color": 0,
                "subnet": "10.0.0.0 255.255.255.0",
                "associated-interface": "",
                "type": "ipmask",
            },
        )

        self.assertDictEqual(
            addresses[1].model_dump(),
            {
                "name": "host2",
                "comment": "Test host 2",
                "color": 1,
                "subnet": "10.1.0.0 255.255.255.0",
                "associated-interface": "internet",
                "type": "ipmask",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_ipmask_get_unkown_type(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "associated-interface": "",
                        "type": "foo",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 1)
        self.assertTrue(isinstance(addresses[0], FortigateAddress))

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_ipmask_create(self) -> None:
        self.httpx2_mock.post(
            "/api/v2/cmdb/firewall/address",
            json={
                "name": "host1",
                "comment": "",
                "color": 0,
                "subnet": "10.0.0.0 255.255.255.0",
                "associated-interface": "",
                "type": "ipmask",
            },
            params={"vdom": "root"},
        ).respond()

        address = FortigateIpMaskAddress(
            name="host1", subnet=ipaddress.IPv4Network("10.0.0.0/24")
        )
        self.fw.create_address(address)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_ipmask_update(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "subnet": "10.0.0.0 255.255.255.0",
                        "associated-interface": "",
                        "type": "ipmask",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 1)

        address = addresses[0]
        address.comment = "test"
        address.color = 1

        self.httpx2_mock.put(
            "/api/v2/cmdb/firewall/address/host1",
            json={
                "name": "host1",
                "comment": "test",
                "color": 1,
                "subnet": "10.0.0.0 255.255.255.0",
                "associated-interface": "",
                "type": "ipmask",
            },
            params={"vdom": "root"},
        ).respond()

        self.fw.update_address(address)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_ipmask_delete(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "subnet": "10.0.0.0 255.255.255.0",
                        "associated-interface": "",
                        "type": "ipmask",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 1)

        address = addresses[0]

        self.httpx2_mock.delete(
            "/api/v2/cmdb/firewall/address/host1",
            params={"vdom": "root"},
        ).respond()

        self.fw.delete_address(address)

    def test_address_fqdn(self):
        address = FortigateFQDNAddress(name="host1", fqdn="example.com")
        self.assertDictEqual(
            address.model_dump(),
            {
                "name": "host1",
                "comment": "",
                "color": 0,
                "fqdn": "example.com",
                "associated-interface": "",
                "type": "fqdn",
            },
        )

        address = FortigateFQDNAddress(
            name="host1",
            fqdn="example.com",
            comment="Test host",
            color=1,
            interface=FortigateInterface(name="internet"),
        )
        self.assertDictEqual(
            address.model_dump(),
            {
                "name": "host1",
                "comment": "Test host",
                "color": 1,
                "fqdn": "example.com",
                "associated-interface": "internet",
                "type": "fqdn",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_fqdn_get(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={"results": []},
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 0)

        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "fqdn": "example.com",
                        "associated-interface": "",
                        "type": "fqdn",
                    },
                    {
                        "name": "host2",
                        "comment": "Test host 2",
                        "color": 1,
                        "fqdn": "api.example.com",
                        "associated-interface": "internet",
                        "type": "fqdn",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 2)
        self.assertTrue(isinstance(addresses[0], FortigateFQDNAddress))
        self.assertTrue(isinstance(addresses[1], FortigateFQDNAddress))

        self.assertDictEqual(
            addresses[0].model_dump(),
            {
                "name": "host1",
                "comment": "",
                "color": 0,
                "fqdn": "example.com",
                "associated-interface": "",
                "type": "fqdn",
            },
        )

        self.assertDictEqual(
            addresses[1].model_dump(),
            {
                "name": "host2",
                "comment": "Test host 2",
                "color": 1,
                "fqdn": "api.example.com",
                "associated-interface": "internet",
                "type": "fqdn",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_fqdn_create(self) -> None:
        self.httpx2_mock.post(
            "/api/v2/cmdb/firewall/address",
            json={
                "name": "host1",
                "comment": "",
                "color": 0,
                "fqdn": "example.com",
                "associated-interface": "",
                "type": "fqdn",
            },
            params={"vdom": "root"},
        ).respond()

        address = FortigateFQDNAddress(name="host1", fqdn="example.com")
        self.fw.create_address(address)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_fqdn_update(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "fqdn": "example.com",
                        "associated-interface": "",
                        "type": "fqdn",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 1)

        address = addresses[0]
        address.comment = "test"
        address.color = 1

        self.httpx2_mock.put(
            "/api/v2/cmdb/firewall/address/host1",
            json={
                "name": "host1",
                "comment": "test",
                "color": 1,
                "fqdn": "example.com",
                "associated-interface": "",
                "type": "fqdn",
            },
            params={"vdom": "root"},
        ).respond()

        self.fw.update_address(address)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_fqdn_delete(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "fqdn": "example.com",
                        "associated-interface": "",
                        "type": "fqdn",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 1)

        address = addresses[0]

        self.httpx2_mock.delete(
            "/api/v2/cmdb/firewall/address/host1",
            params={"vdom": "root"},
        ).respond()

        self.fw.delete_address(address)

    def test_address_iprange(self):
        address = FortigateIPRangeAddress(
            name="host1",
            start_ip=ipaddress.IPv4Address("10.0.0.10"),
            end_ip=ipaddress.IPv4Address("10.0.0.20"),
        )
        self.assertDictEqual(
            address.model_dump(),
            {
                "name": "host1",
                "comment": "",
                "color": 0,
                "start-ip": "10.0.0.10",
                "end-ip": "10.0.0.20",
                "associated-interface": "",
                "type": "iprange",
            },
        )

        address = FortigateIPRangeAddress(
            name="host1",
            start_ip=ipaddress.IPv4Address("10.0.0.10"),
            end_ip=ipaddress.IPv4Address("10.0.0.20"),
            comment="Test host",
            color=1,
            interface=FortigateInterface(name="internet"),
        )
        self.assertDictEqual(
            address.model_dump(),
            {
                "name": "host1",
                "comment": "Test host",
                "color": 1,
                "start-ip": "10.0.0.10",
                "end-ip": "10.0.0.20",
                "associated-interface": "internet",
                "type": "iprange",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_iprange_get(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={"results": []},
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 0)

        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "start-ip": "10.0.0.10",
                        "end-ip": "10.0.0.20",
                        "associated-interface": "",
                        "type": "iprange",
                    },
                    {
                        "name": "host2",
                        "comment": "Test host 2",
                        "color": 1,
                        "start-ip": "10.0.1.10",
                        "end-ip": "10.0.1.20",
                        "associated-interface": "internet",
                        "type": "iprange",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 2)
        self.assertTrue(isinstance(addresses[0], FortigateIPRangeAddress))
        self.assertTrue(isinstance(addresses[1], FortigateIPRangeAddress))

        self.assertDictEqual(
            addresses[0].model_dump(),
            {
                "name": "host1",
                "comment": "",
                "color": 0,
                "start-ip": "10.0.0.10",
                "end-ip": "10.0.0.20",
                "associated-interface": "",
                "type": "iprange",
            },
        )

        self.assertDictEqual(
            addresses[1].model_dump(),
            {
                "name": "host2",
                "comment": "Test host 2",
                "color": 1,
                "start-ip": "10.0.1.10",
                "end-ip": "10.0.1.20",
                "associated-interface": "internet",
                "type": "iprange",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_iprange_create(self) -> None:
        self.httpx2_mock.post(
            "/api/v2/cmdb/firewall/address",
            json={
                "name": "host1",
                "comment": "",
                "color": 0,
                "start-ip": "10.0.0.10",
                "end-ip": "10.0.0.20",
                "associated-interface": "",
                "type": "iprange",
            },
            params={"vdom": "root"},
        ).respond()

        address = FortigateIPRangeAddress(
            name="host1",
            start_ip=ipaddress.IPv4Address("10.0.0.10"),
            end_ip=ipaddress.IPv4Address("10.0.0.20"),
        )
        self.fw.create_address(address)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_iprange_update(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "start-ip": "10.0.0.10",
                        "end-ip": "10.0.0.20",
                        "associated-interface": "",
                        "type": "iprange",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 1)

        address = addresses[0]
        address.comment = "test"
        address.color = 1

        self.httpx2_mock.put(
            "/api/v2/cmdb/firewall/address/host1",
            json={
                "name": "host1",
                "comment": "test",
                "color": 1,
                "start-ip": "10.0.0.10",
                "end-ip": "10.0.0.20",
                "associated-interface": "",
                "type": "iprange",
            },
            params={"vdom": "root"},
        ).respond()

        self.fw.update_address(address)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_iprange_delete(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/address",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "host1",
                        "comment": "",
                        "color": 0,
                        "start-ip": "10.0.0.10",
                        "end-ip": "10.0.0.20",
                        "associated-interface": "",
                        "type": "iprange",
                    },
                ]
            },
        )

        addresses = self.fw.get_addresses()
        self.assertEqual(len(addresses), 1)

        address = addresses[0]

        self.httpx2_mock.delete(
            "/api/v2/cmdb/firewall/address/host1",
            params={"vdom": "root"},
        ).respond()

        self.fw.delete_address(address)
