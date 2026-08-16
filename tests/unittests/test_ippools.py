import ipaddress

import pytest

from fortilib.ippool import (
    FortigateIPPool,
    FortigateIPPoolOneToOne,
    FortigateIPPoolOverload,
)
from tests.unittests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_ippool_overload(self):
        pool = FortigateIPPoolOverload(
            name="test-pool",
            comment="test-comment",
            start_ip=ipaddress.IPv4Address("10.0.0.10"),
            end_ip=ipaddress.IPv4Address("10.0.0.20"),
        )

        self.assertDictEqual(
            pool.model_dump(),
            {
                "name": "test-pool",
                "type": "overload",
                "comments": "test-comment",
                "startip": "10.0.0.10",
                "endip": "10.0.0.20",
                "arp-reply": "enable",
                "nat64": "disable",
            },
        )

    def test_ippool_one_to_one(self):
        pool = FortigateIPPoolOneToOne(
            name="test-pool",
            comment="test-comment",
            start_ip=ipaddress.IPv4Address("10.0.0.10"),
            end_ip=ipaddress.IPv4Address("10.0.0.20"),
        )

        self.assertDictEqual(
            pool.model_dump(),
            {
                "name": "test-pool",
                "type": "one-to-one",
                "comments": "test-comment",
                "startip": "10.0.0.10",
                "endip": "10.0.0.20",
                "arp-reply": "enable",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_ippool_get(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/ippool",
            params={"vdom": "root"},
        ).respond(
            json={"results": []},
        )

        pools = self.fw.get_ippools()
        self.assertEqual(len(pools), 0)

        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/ippool",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "pool1",
                        "type": "overload",
                        "comments": "Test pool 1",
                        "startip": "10.0.0.10",
                        "endip": "10.0.0.20",
                        "arp-reply": "enable",
                        "nat64": "disable",
                    },
                    {
                        "name": "pool2",
                        "type": "one-to-one",
                        "comments": "Test pool 2",
                        "startip": "10.0.1.10",
                        "endip": "10.0.1.20",
                        "arp-reply": "disable",
                    },
                    {
                        "name": "pool3",
                        "comments": "Test pool 3",
                        "startip": "10.0.2.10",
                        "endip": "10.0.2.20",
                        "arp-reply": "disable",
                    },
                ]
            },
        )

        pools = self.fw.get_ippools()
        self.assertEqual(len(pools), 3)
        self.assertTrue(isinstance(pools[0], FortigateIPPoolOverload))
        self.assertTrue(isinstance(pools[1], FortigateIPPoolOneToOne))
        self.assertTrue(isinstance(pools[2], FortigateIPPool))

        self.assertDictEqual(
            pools[0].model_dump(),
            {
                "name": "pool1",
                "type": "overload",
                "comments": "Test pool 1",
                "startip": "10.0.0.10",
                "endip": "10.0.0.20",
                "arp-reply": "enable",
                "nat64": "disable",
            },
        )

        self.assertDictEqual(
            pools[1].model_dump(),
            {
                "name": "pool2",
                "type": "one-to-one",
                "comments": "Test pool 2",
                "startip": "10.0.1.10",
                "endip": "10.0.1.20",
                "arp-reply": "disable",
            },
        )

        self.assertDictEqual(
            pools[2].model_dump(),
            {
                "name": "pool3",
                "comments": "Test pool 3",
                "startip": "10.0.2.10",
                "endip": "10.0.2.20",
                "arp-reply": "disable",
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_ippool_create(self) -> None:
        self.httpx2_mock.post(
            "/api/v2/cmdb/firewall/ippool",
            json={
                "name": "pool1",
                "type": "overload",
                "comments": "Test pool 1",
                "startip": "10.0.0.10",
                "endip": "10.0.0.20",
                "arp-reply": "enable",
                "nat64": "disable",
            },
            params={"vdom": "root"},
        ).respond()

        pool = FortigateIPPoolOverload(
            name="pool1",
            comment="Test pool 1",
            start_ip=ipaddress.IPv4Address("10.0.0.10"),
            end_ip=ipaddress.IPv4Address("10.0.0.20"),
        )
        self.fw.create_ippool(pool)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_ippool_update(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/ippool",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "pool1",
                        "type": "overload",
                        "comments": "Test pool 1",
                        "startip": "10.0.0.10",
                        "endip": "10.0.0.20",
                        "arp-reply": "enable",
                        "nat64": "disable",
                    },
                ]
            },
        )

        pools = self.fw.get_ippools()
        self.assertEqual(len(pools), 1)

        pool = pools[0]
        pool.comment = "Updated pool"
        pool.arp_reply = False

        self.httpx2_mock.put(
            "/api/v2/cmdb/firewall/ippool/pool1",
            json={
                "name": "pool1",
                "type": "overload",
                "comments": "Updated pool",
                "startip": "10.0.0.10",
                "endip": "10.0.0.20",
                "arp-reply": "disable",
                "nat64": "disable",
            },
            params={"vdom": "root"},
        ).respond()

        self.fw.update_ippool(pool)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_ippool_delete(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/ippool",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "pool1",
                        "type": "overload",
                        "comments": "Test pool 1",
                        "startip": "10.0.0.10",
                        "endip": "10.0.0.20",
                        "arp-reply": "enable",
                        "nat64": "disable",
                    },
                ]
            },
        )

        pools = self.fw.get_ippools()
        self.assertEqual(len(pools), 1)

        pool = pools[0]

        self.httpx2_mock.delete(
            "/api/v2/cmdb/firewall/ippool/pool1",
            params={"vdom": "root"},
        ).respond()

        self.fw.delete_ippool(pool)
