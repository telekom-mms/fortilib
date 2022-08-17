from fortilib import get_by
from fortilib.exceptions import (
    AddressTypeMismatchException,
    InterfaceMismatchException,
)
from fortilib.policy import (
    FortigatePolicy,
    FortigatePolicyAction,
    FortigatePolicyLogTraffic,
)
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_policy_create(self):
        policy = FortigatePolicy()

        policy.add_source_interface(
            get_by("name", "port4", self.fw.interfaces)
        )
        policy.add_destination_interface(
            get_by("name", "port5", self.fw.interfaces)
        )

        policy.service.append(get_by("name", "HTTP", self.fw.services))

        policy.add_source_address(
            get_by(
                "name",
                "NET_199.40.1.0_24",
                self.fw.addresses,
            )
        )
        policy.add_destination_address(
            get_by(
                "name",
                "NET_198.141.216.0_22",
                self.fw.addresses,
            )
        )

        policy.action = FortigatePolicyAction.DENY
        policy.logtraffic = FortigatePolicyLogTraffic.UTM
        policy.comment = "Kommentar"

        self.fw.create_firewall_policy(policy)

        self.fw.fortigate.create_firewall_policy.assert_called_once()
        self.fw.fortigate.create_firewall_policy.assert_called_with(
            0,
            {
                "policyid": 0,
                "name": "",
                "action": "deny",
                "nat": "disable",
                "ippool": "disable",
                "srcintf": [
                    {"name": "port4"},
                ],
                "dstintf": [
                    {"name": "port5"},
                ],
                "srcaddr": [
                    {"name": "NET_199.40.1.0_24"},
                ],
                "dstaddr": [
                    {"name": "NET_198.141.216.0_22"},
                ],
                "service": [
                    {"name": "HTTP"},
                ],
                "poolname": [],
                "schedule": "always",
                "logtraffic": "utm",
                "comments": "Kommentar",
            },
        )
        self.assertTrue(policy in self.fw.policies)

    def test_firewall_base_policy_update(self):
        policy: FortigatePolicy = get_by("policyid", 35, self.fw.policies)

        self.assertIsInstance(policy, FortigatePolicy)

        policy.add_destination_address(
            get_by("name", "FQDN_aadcdn.msauth.net", self.fw.addresses)
        )

        self.fw.update_firewall_policy(policy)

        self.fw.fortigate.update_firewall_policy.assert_called_once()
        self.fw.fortigate.update_firewall_policy.assert_called_with(
            35,
            {
                "policyid": 35,
                "name": "policy 1",
                "action": "accept",
                "srcintf": [
                    {
                        "name": "port4",
                    }
                ],
                "dstintf": [
                    {
                        "name": "port5",
                    }
                ],
                "srcaddr": [
                    {
                        "name": "NET_199.40.1.0_24",
                    }
                ],
                "dstaddr": [
                    {"name": "FQDN_aadcdn.msauth.net"},
                    {"name": "NET_198.141.216.0_22"},
                    {"name": "RANGE_10.188.128.106-108"},
                ],
                "service": [
                    {
                        "name": "HTTP",
                    }
                ],
                "nat": "enable",
                "ippool": "enable",
                "poolname": [
                    {"name": "Post_DynCom-SNAT"},
                ],
                "schedule": "always",
                "logtraffic": "all",
                "comments": "rgi 20141120 2014102270001675",
            },
        )

    def test_firewall_base_policy_update_wrong_address_interface(self):
        policy: FortigatePolicy = get_by("policyid", 35, self.fw.policies)

        self.assertIsInstance(policy, FortigatePolicy)

        with self.assertRaises(InterfaceMismatchException):
            policy.add_destination_address(
                get_by("name", "FQDN_golem.de", self.fw.addresses)
            )

    def test_firewall_base_policy_update_add_wrong_interface(self):
        policy = FortigatePolicy()

        policy.service.append(get_by("name", "HTTP", self.fw.services))

        policy.add_source_address(
            get_by(
                "name",
                "NET_199.40.1.0_24",
                self.fw.addresses,
            )
        )
        policy.add_destination_address(
            get_by(
                "name",
                "FQDN_golem.de",
                self.fw.addresses,
            )
        )

        policy.add_source_interface(
            get_by("name", "port4", self.fw.interfaces)
        )

        with self.assertRaises(InterfaceMismatchException):
            policy.add_destination_interface(
                get_by("name", "port5", self.fw.interfaces)
            )

    def test_firewall_base_policy_remove_address(self):
        policy: FortigatePolicy = get_by("policyid", 35, self.fw.policies)

        self.assertEqual(1, len(policy.srcaddr))
        self.assertEqual(2, len(policy.dstaddr))

        policy.remove_source_address(
            get_by("name", "NET_199.40.1.0_24", self.fw.addresses)
        )
        policy.remove_destination_address(
            get_by("name", "NET_198.141.216.0_22", self.fw.addresses)
        )

        self.assertEqual(0, len(policy.srcaddr))
        self.assertEqual(1, len(policy.dstaddr))

        self.assertEqual(
            get_by("name", "RANGE_10.188.128.106-108", self.fw.addresses),
            policy.dstaddr[0],
        )

    def test_firewall_base_policy_remove_interfaces(self):
        policy: FortigatePolicy = get_by("policyid", 35, self.fw.policies)

        self.assertEqual(1, len(policy.srcintf))
        self.assertEqual(1, len(policy.dstintf))

        policy.remove_source_interface(
            get_by("name", "port4", self.fw.interfaces)
        )
        policy.remove_destination_interface(
            get_by("name", "port5", self.fw.interfaces)
        )

        self.assertEqual(0, len(policy.srcintf))
        self.assertEqual(0, len(policy.dstintf))

    def test_firewall_base_policy_update_multiple_interface(self):
        policy = FortigatePolicy()

        policy.service.append(get_by("name", "HTTP", self.fw.services))

        policy.add_source_interface(
            get_by("name", "port4", self.fw.interfaces)
        )

        policy.add_source_interface(
            get_by("name", "port5", self.fw.interfaces)
        )

        policy.add_destination_interface(
            get_by("name", "port5", self.fw.interfaces)
        )

        with self.assertRaises(InterfaceMismatchException):
            policy.add_source_address(
                get_by(
                    "name",
                    "FQDN_golem.de",
                    self.fw.addresses,
                )
            )

    def test_firewall_base_policy_vip_address_mixed_address(self):
        policy = FortigatePolicy()

        policy.service.append(get_by("name", "HTTP", self.fw.services))

        policy.add_source_interface(
            get_by("name", "port4", self.fw.interfaces)
        )

        policy.add_destination_interface(
            get_by("name", "port5", self.fw.interfaces)
        )

        policy.add_source_address(
            get_by(
                "name",
                "NET_199.40.1.0_24",
                self.fw.addresses,
            )
        )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_source_address(
                get_by(
                    "name",
                    "vip_test",
                    self.fw.vips,
                )
            )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_source_address(
                get_by(
                    "name",
                    "vip group 1",
                    self.fw.vip_groups,
                )
            )

    def test_firewall_base_policy_vip_address_mixed_vip(self):
        policy = FortigatePolicy()

        policy.service.append(get_by("name", "HTTP", self.fw.services))

        policy.add_source_interface(
            get_by("name", "port4", self.fw.interfaces)
        )

        policy.add_destination_interface(
            get_by("name", "port5", self.fw.interfaces)
        )

        policy.add_source_address(
            get_by(
                "name",
                "vip_test",
                self.fw.vips,
            )
        )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_source_address(
                get_by(
                    "name",
                    "NET_199.40.1.0_24",
                    self.fw.addresses,
                )
            )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_source_address(
                get_by(
                    "name",
                    "test group 1",
                    self.fw.address_groups,
                )
            )

    def test_firewall_base_policy_delete(self):
        policy: FortigatePolicy = get_by("policyid", 35, self.fw.policies)

        self.fw.delete_firewall_policy(policy)
        self.fw.fortigate.delete_firewall_policy.assert_called_once()
        self.fw.fortigate.delete_firewall_policy.assert_called_with(35)
        self.assertTrue(policy not in self.fw.policies)
