from unittest.mock import MagicMock

from fortilib import get_by
from fortilib.policy import FortigatePolicy
from tests import FortigateTest
from tests.test_data import (
    data_policy_missing_address,
    data_policy_missing_interface,
    data_policy_missing_ippool,
    data_policy_missing_service,
)


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_policy(self):
        policy: FortigatePolicy = get_by("name", "policy 1", self.fw.policies)
        self.assertEqual(len(self.fw.policies), 2)
        self.assertEqual(
            policy.render(),
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
            {
                "policyid": 107,
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
                    {"name": "NET_198.141.216.0_22"},
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

    def test_firewall_base_policy_missing_interface(self):
        self.fw.fortigate.get_firewall_policies = MagicMock(
            return_value=data_policy_missing_interface.policies
        )

        with self.assertRaises(Exception) as ex:
            self.fw.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "no interface found with name port1010",
        )

    def test_firewall_base_policy_missing_address(self):
        self.fw.fortigate.get_firewall_policies = MagicMock(
            return_value=data_policy_missing_address.policies
        )

        with self.assertRaises(Exception) as ex:
            self.fw.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "address (or vip or group) missing_object not found",
        )

    def test_firewall_base_policy_missing_service(self):
        self.fw.fortigate.get_firewall_policies = MagicMock(
            return_value=data_policy_missing_service.policies
        )

        with self.assertRaises(Exception) as ex:
            self.fw.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "service with name missing_object not found",
        )

    def test_firewall_base_policy_missing_ippool(self):
        self.fw.fortigate.get_firewall_policies = MagicMock(
            return_value=data_policy_missing_ippool.policies
        )

        with self.assertRaises(Exception) as ex:
            self.fw.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "ippool with name missing_object not found",
        )
