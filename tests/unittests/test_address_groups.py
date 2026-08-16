import ipaddress

import pytest

from fortilib import FortigateMemberNotFoundError
from fortilib.address import FortigateIpMaskAddress
from fortilib.address_group import FortigateAddressGroup
from tests.unittests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_address_address_group(self):
        address = FortigateIpMaskAddress(
            name="host1", subnet=ipaddress.IPv4Network("10.0.0.0/24")
        )

        group1 = FortigateAddressGroup(
            name="group1",
            member=[address],
        )
        self.assertDictEqual(
            group1.model_dump(),
            {
                "name": "group1",
                "member": [{"name": "host1"}],
                "color": 0,
                "comment": "",
            },
        )
        self.assertTrue(isinstance(group1.member[0], FortigateIpMaskAddress))
        self.assertEqual(len(group1.member), 1)

        group2 = FortigateAddressGroup(
            name="group2",
            member=[address, group1],
        )

        self.assertTrue(isinstance(group2.member[0], FortigateIpMaskAddress))
        self.assertTrue(isinstance(group2.member[1], FortigateAddressGroup))
        self.assertEqual(len(group2.member), 2)

        self.assertDictEqual(
            group2.model_dump(),
            {
                "name": "group2",
                "member": [
                    {"name": "host1"},
                    {"name": "group1"},
                ],
                "color": 0,
                "comment": "",
            },
        )

        data = {"name": "group1", "member": [{"name": "host1"}]}
        group1 = FortigateAddressGroup(**data)  # ty: ignore[invalid-argument-type]
        group1.resolve_member([address])
        self.assertEqual(len(group1.member), 1)
        self.assertTrue(isinstance(group1.member[0], FortigateIpMaskAddress))

        group1 = FortigateAddressGroup(**data)  # ty: ignore[invalid-argument-type]
        with self.assertRaises(FortigateMemberNotFoundError) as context:
            group1.resolve_member([])

        self.assertEqual(
            "Address group member host1 not found",
            str(context.exception),
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_group_get(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/addrgrp",
            params={"vdom": "root"},
        ).respond(
            json={"results": []},
        )

        groups = self.fw.get_address_groups()
        self.assertEqual(len(groups), 0)

        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/addrgrp",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "group1",
                        "comment": "",
                        "color": 0,
                        "member": [{"name": "host1"}],
                    },
                    {
                        "name": "group2",
                        "comment": "Test group 2",
                        "color": 1,
                        "member": [{"name": "group1"}, {"name": "host1"}],
                    },
                ]
            },
        )

        groups = self.fw.get_address_groups()
        self.assertEqual(len(groups), 2)
        self.assertTrue(isinstance(groups[0], FortigateAddressGroup))
        self.assertTrue(isinstance(groups[1], FortigateAddressGroup))

        self.assertDictEqual(
            groups[0].model_dump(),
            {
                "name": "group1",
                "comment": "",
                "color": 0,
                "member": [{"name": "host1"}],
            },
        )

        self.assertDictEqual(
            groups[1].model_dump(),
            {
                "name": "group2",
                "comment": "Test group 2",
                "color": 1,
                "member": [{"name": "group1"}, {"name": "host1"}],
            },
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_group_create(self) -> None:
        self.httpx2_mock.post(
            "/api/v2/cmdb/firewall/addrgrp",
            json={
                "name": "group1",
                "comment": "",
                "color": 0,
                "member": [{"name": "host1"}],
            },
            params={"vdom": "root"},
        ).respond()

        group = FortigateAddressGroup(
            name="group1",
            member=[
                FortigateIpMaskAddress(
                    name="host1", subnet=ipaddress.IPv4Network("10.0.0.0/24")
                )
            ],
        )
        self.fw.create_address_group(group)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_group_update(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/addrgrp",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "group1",
                        "comment": "",
                        "color": 0,
                        "member": [{"name": "host1"}],
                    },
                ]
            },
        )

        groups = self.fw.get_address_groups()
        self.assertEqual(len(groups), 1)

        group = groups[0]
        group.comment = "test"
        group.color = 1

        self.httpx2_mock.put(
            "/api/v2/cmdb/firewall/addrgrp/group1",
            json={
                "name": "group1",
                "comment": "test",
                "color": 1,
                "member": [{"name": "host1"}],
            },
            params={"vdom": "root"},
        ).respond()

        self.fw.update_address_group(group)

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_address_group_delete(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/firewall/addrgrp",
            params={"vdom": "root"},
        ).respond(
            json={
                "results": [
                    {
                        "name": "group1",
                        "comment": "",
                        "color": 0,
                        "member": [{"name": "host1"}],
                    },
                ]
            },
        )

        groups = self.fw.get_address_groups()
        self.assertEqual(len(groups), 1)

        group = groups[0]

        self.httpx2_mock.delete(
            "/api/v2/cmdb/firewall/addrgrp/group1",
            params={"vdom": "root"},
        ).respond()

        self.fw.delete_address_group(group)
