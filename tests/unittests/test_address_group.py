import ipaddress

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
