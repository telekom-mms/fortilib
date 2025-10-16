from unittest.mock import MagicMock

from fortilib import get_by
from fortilib.proxypolicy import FortigateProxyPolicy, FortiproxyPolicy
from tests import FortigateTest, FortiproxyTest
from tests.test_data import (
    data_policy_missing_address,
    data_policy_missing_interface,
    data_policy_missing_service,
)


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_proxy_policy(self):
        policy: FortigateProxyPolicy = get_by(
            "name", "policy 129", self.fw.proxy_policies
        )
        self.assertEqual(len(self.fw.proxy_policies), 1)
        self.assertEqual(
            policy.render(),
            {
                "policyid": 129,
                "name": "policy 129",
                "proxy": "transparent-web",
                "srcintf": [
                    {
                        "name": "port2",
                    }
                ],
                "dstintf": [
                    {
                        "name": "port1",
                    }
                ],
                "srcaddr": [
                    {
                        "name": "NET_172.16.240.120_29",
                    }
                ],
                "dstaddr": [
                    {
                        "name": "http.kali.org",
                    }
                ],
                "service": [
                    {
                        "name": "proxy_https",
                    }
                ],
                "action": "accept",
                "status": "enable",
                "schedule": "always",
                "logtraffic": "all",
                "utm-status": "enable",
                "profile-type": "group",
                "profile-group": "proxy_log",
                "comments": "[Pentest] [unknown] [#2]",
            },
        )

    def test_firewall_base_proxy_policy_missing_interface(self):
        self.fw.fortigate.get_firewall_proxy_policies = MagicMock(
            return_value=data_policy_missing_interface.proxy_policies
        )

        with self.assertRaises(Exception) as ex:
            self.fw.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "no interface found with name port0815",
        )

    def test_firewall_base_proxy_policy_missing_address(self):
        self.fw.fortigate.get_firewall_proxy_policies = MagicMock(
            return_value=data_policy_missing_address.proxy_policies
        )

        with self.assertRaises(Exception) as ex:
            self.fw.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "address (or vip or group) missing_object not found",
        )

    def test_firewall_base_proxy_policy_missing_service(self):
        self.fw.fortigate.get_firewall_proxy_policies = MagicMock(
            return_value=data_policy_missing_service.proxy_policies
        )

        with self.assertRaises(Exception) as ex:
            self.fw.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "service with name missing_object not found",
        )

class TestFortilibFortiProxy(FortiproxyTest):
    def test_fortiproxy_firewall_proxy_base_policy(self):
        policy: FortiproxyPolicy = get_by(
            "name", "policy 815", self.prx.policies
        )
        self.assertEqual(len(self.prx.policies), 1)
        self.assertEqual(
            policy.render(),
            {
                "policyid": 815,
                "name": "policy 815",
                "type": "transparent",
                "srcintf": [
                    {
                        "name": "port2",
                    }
                ],
                "dstintf": [
                    {
                        "name": "port1",
                    }
                ],
                "srcaddr": [
                    {
                        "name": "NET_172.16.240.120_29",
                    }
                ],
                "dstaddr": [
                    {
                        "name": "http.kali.org",
                    }
                ],
                "service": [
                    {
                        "name": "proxy_https",
                    }
                ],
                "action": "accept",
                "status": "enable",
                'schedule': {'q_origin_key': 'always'},
                "logtraffic": "all",
                "utm-status": "enable",
                "profile-type": "group",
                "profile-group": {"q_origin_key": "proxy_log"},
                "comments": "this is a comment",
            },
        )

    def test_fortiproxy_firewall_base_proxy_policy_missing_interface(self):
        self.prx.fortigate.get_firewall_policies = MagicMock(
            return_value=data_policy_missing_interface.forti_proxy_policies
        )

        with self.assertRaises(Exception) as ex:
            self.prx.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "no interface found with name port0815",
        )

    def test_fortiproxy_firewall_base_proxy_policy_missing_address(self):
        self.prx.fortigate.get_firewall_policies = MagicMock(
            return_value=data_policy_missing_address.forti_proxy_policies
        )

        with self.assertRaises(Exception) as ex:
            self.prx.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "address (or vip or group) missing_object not found",
        )

    def test_fortiproxy_firewall_base_proxy_policy_missing_service(self):
        self.prx.fortigate.get_firewall_policies = MagicMock(
            return_value=data_policy_missing_service.forti_proxy_policies
        )

        with self.assertRaises(Exception) as ex:
            self.prx.get_all_objects()

        self.assertEqual(
            str(ex.exception),
            "service with name missing_object not found",
        )
