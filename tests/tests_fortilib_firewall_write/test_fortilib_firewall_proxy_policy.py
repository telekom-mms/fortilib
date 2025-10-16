from fortilib import get_by
from fortilib.exceptions import (
    AddressTypeMismatchException,
    InterfaceMismatchException,
)
from fortilib.proxypolicy import FortigateProxyPolicy, FortiproxyPolicy
from tests import FortigateTest, FortiproxyTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_proxy_policy_create(self):
        policy = FortigateProxyPolicy()
        policy.name = "test proxypolicy"
        policy.policyid = 7
        policy.profile_type = "single"
        policy.profile_group = "g-default"

        policy.add_source_interface(
            get_by("name", "port2", self.fw.interfaces)
        )
        policy.add_destination_interface(
            get_by("name", "port1", self.fw.interfaces)
        )

        policy.service.append(get_by("name", "proxy_https", self.fw.services))

        policy.add_source_address(
            get_by(
                "name",
                "NET_172.16.240.120_29",
                self.fw.addresses,
            )
        )

        policy.add_destination_address(
            get_by(
                "name",
                "http.kali.org",
                self.fw.proxy_addresses,
            )
        )

        policy.comment = "Kommentar"

        self.fw.create_firewall_proxy_policy(policy)

        self.fw.fortigate.create_firewall_proxy_policies.assert_called_once()
        self.fw.fortigate.create_firewall_proxy_policies.assert_called_with(
            7,
            {
                "policyid": 7,
                "name": "test proxypolicy",
                "proxy": "transparent-web",
                "srcintf": [
                    {"name": "port2"},
                ],
                "dstintf": [
                    {"name": "port1"},
                ],
                "srcaddr": [
                    {"name": "NET_172.16.240.120_29"},
                ],
                "dstaddr": [
                    {"name": "http.kali.org"},
                ],
                "service": [
                    {"name": "proxy_https"},
                ],
                "action": "accept",
                "status": "enable",
                "schedule": "always",
                "logtraffic": "all",
                "utm-status": "enable",
                "profile-type": "single",
                "profile-group": "g-default",
                "comments": "Kommentar",
            },
        )
        self.assertTrue(policy in self.fw.proxy_policies)

    def test_firewall_base_proxy_policy_update(self):
        policy: FortigateProxyPolicy = get_by(
            "policyid", 129, self.fw.proxy_policies
        )

        self.assertIsInstance(policy, FortigateProxyPolicy)

        policy.add_destination_address(
            get_by("name", "FQDN_aadcdn.msauth.net", self.fw.addresses)
        )

        self.fw.update_firewall_proxy_policy(policy)

        self.fw.fortigate.update_firewall_proxy_policies.assert_called_once()
        self.fw.fortigate.update_firewall_proxy_policies.assert_called_with(
            129,
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
                    {"name": "FQDN_aadcdn.msauth.net"},
                    {"name": "http.kali.org"},
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

    def test_firewall_base_proxy_policy_delete(self):
        policy: FortigateProxyPolicy = get_by(
            "policyid", 129, self.fw.proxy_policies
        )

        self.fw.delete_firewall_proxy_policy(policy)
        self.fw.fortigate.delete_firewall_proxy_policies.assert_called_once()
        self.fw.fortigate.delete_firewall_proxy_policies.assert_called_with(
            129
        )
        self.assertTrue(policy not in self.fw.policies)

    def test_firewall_base_proxy_policy_update_wrong_address_interface(self):
        policy: FortigateProxyPolicy = get_by(
            "policyid", 129, self.fw.proxy_policies
        )

        self.assertIsInstance(policy, FortigateProxyPolicy)

        with self.assertRaises(InterfaceMismatchException):
            policy.add_destination_address(
                get_by("name", "FQDN_golem.de", self.fw.all_addresses)
            )

    def test_firewall_base_proxy_policy_update_wrong_source_address(self):
        policy: FortigateProxyPolicy = get_by(
            "policyid", 129, self.fw.proxy_policies
        )

        self.assertIsInstance(policy, FortigateProxyPolicy)

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_source_address(
                get_by("name", "http.kali.org", self.fw.all_addresses)
            )

    def test_firewall_base_proxy_policy_update_add_wrong_interface(self):
        policy = FortigateProxyPolicy()

        policy.service.append(get_by("name", "proxy-https", self.fw.services))

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
                "http.kali.org",
                self.fw.all_addresses,
            )
        )

        policy.add_destination_interface(
            get_by("name", "port2", self.fw.interfaces)
        )

        with self.assertRaises(InterfaceMismatchException):
            policy.add_source_interface(
                get_by("name", "port1", self.fw.interfaces)
            )

    def test_firewall_base_proxy_policy_remove_address(self):
        policy: FortigateProxyPolicy = get_by(
            "policyid", 129, self.fw.proxy_policies
        )

        self.assertEqual(1, len(policy.srcaddr))
        self.assertEqual(1, len(policy.dstaddr))

        policy.remove_source_address(
            get_by("name", "NET_172.16.240.120_29", self.fw.addresses)
        )

        self.assertEqual(0, len(policy.srcaddr))

        self.assertEqual(
            get_by("name", "http.kali.org", self.fw.all_addresses),
            policy.dstaddr[0],
        )

    def test_firewall_base_proxy_policy_remove_interfaces(self):
        policy: FortigateProxyPolicy = get_by(
            "policyid", 129, self.fw.proxy_policies
        )

        self.assertEqual(1, len(policy.srcintf))
        self.assertEqual(1, len(policy.dstintf))

        policy.remove_source_interface(
            get_by("name", "port2", self.fw.interfaces)
        )
        policy.remove_destination_interface(
            get_by("name", "port1", self.fw.interfaces)
        )

        self.assertEqual(0, len(policy.srcintf))
        self.assertEqual(0, len(policy.dstintf))

    def test_firewall_base_proxy_policy_update_multiple_interface(self):
        policy = FortigateProxyPolicy()

        policy.service.append(get_by("name", "proxy-https", self.fw.services))

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

    def test_firewall_base_proxy_policy_vip_address_mixed_address(self):
        policy = FortigateProxyPolicy()

        policy.service.append(get_by("name", "proxy-https", self.fw.services))

        policy.add_source_interface(
            get_by("name", "port4", self.fw.interfaces)
        )

        policy.add_destination_interface(
            get_by("name", "port4", self.fw.interfaces)
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

        policy.add_destination_address(
            get_by(
                "name",
                "http.kali.org",
                self.fw.all_addresses,
            )
        )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_destination_address(
                get_by(
                    "name",
                    "vip_test_2",
                    self.fw.vips,
                )
            )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_destination_address(
                get_by(
                    "name",
                    "vip group 2",
                    self.fw.vip_groups,
                )
            )

    def test_firewall_base_policy_vip_address_mixed_vip(self):
        policy = FortigateProxyPolicy()

        policy.service.append(get_by("name", "proxy-https", self.fw.services))

        policy.add_source_interface(
            get_by("name", "port2", self.fw.interfaces)
        )

        policy.add_destination_interface(
            get_by("name", "port4", self.fw.interfaces)
        )

        policy.add_destination_address(
            get_by(
                "name",
                "vip_test",
                self.fw.vips,
            )
        )

        policy.add_destination_address(
            get_by(
                "name",
                "http.kali.org",
                self.fw.all_addresses,
            )
        )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_destination_address(
                get_by(
                    "name",
                    "test group 1",
                    self.fw.address_groups,
                )
            )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_destination_address(
                get_by(
                    "name",
                    "NET_172.16.240.120_29",
                    self.fw.all_addresses,
                )
            )

class TestFortilibFirewall(FortiproxyTest):
    def test_fortiproxy_firewall_base_proxy_policy_create(self):
        policy = FortiproxyPolicy()
        policy.name = "test proxypolicy"
        policy.policyid = 7
        policy.profile_type = "single"
        policy.profile_group = "g-default"

        policy.add_source_interface(
            get_by("name", "port2", self.prx.interfaces)
        )
        policy.add_destination_interface(
            get_by("name", "port1", self.prx.interfaces)
        )

        policy.service.append(get_by("name", "proxy_https", self.prx.services))

        policy.add_source_address(
            get_by(
                "name",
                "NET_172.16.240.120_29",
                self.prx.addresses,
            )
        )

        policy.add_destination_address(
            get_by(
                "name",
                "http.kali.org",
                self.prx.proxy_addresses,
            )
        )

        policy.comment = "Kommentar"

        self.prx.create_firewall_policy(policy)

        self.prx.fortigate.create_firewall_policy.assert_called_once()
        self.prx.fortigate.create_firewall_policy.assert_called_with(
            7,
            {
                "policyid": 7,
                "name": "test proxypolicy",
                "type": "transparent",
                "srcintf": [
                    {"name": "port2"},
                ],
                "dstintf": [
                    {"name": "port1"},
                ],
                "srcaddr": [
                    {"name": "NET_172.16.240.120_29"},
                ],
                "dstaddr": [
                    {"name": "http.kali.org"},
                ],
                "service": [
                    {"name": "proxy_https"},
                ],
                "action": "accept",
                "status": "enable",
                "schedule": "always",
                "logtraffic": "all",
                "utm-status": "enable",
                "profile-type": "single",
                "profile-group": "g-default",
                "comments": "Kommentar",
            },
        )
        self.assertTrue(policy in self.prx.policies)

    def test_fortiproxy_firewall_base_proxy_policy_update(self):
        policy: FortiproxyPolicy = get_by(
            "policyid", 815, self.prx.policies
        )

        self.assertIsInstance(policy, FortiproxyPolicy)

        policy.add_destination_address(
            get_by("name", "FQDN_aadcdn.msauth.net", self.prx.addresses)
        )

        self.prx.update_firewall_policy(policy)

        self.prx.fortigate.update_firewall_policy.assert_called_once()
        print(policy)
        self.prx.fortigate.update_firewall_policy.assert_called_with(
            815,
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
                    {"name": "FQDN_aadcdn.msauth.net"},
                    {"name": "http.kali.org"},
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

    def test_fortiproxy_firewall_base_proxy_policy_delete(self):
        policy: FortiproxyPolicy = get_by(
            "policyid", 815, self.prx.policies
        )

        self.prx.delete_firewall_policy(policy)
        self.prx.fortigate.delete_firewall_policy.assert_called_once()
        self.prx.fortigate.delete_firewall_policy.assert_called_with(
            815
        )
        self.assertTrue(policy not in self.prx.policies)

    def test_fortiproxy_firewall_base_proxy_policy_update_wrong_address_interface(self):
        policy: FortiproxyPolicy = get_by(
            "policyid", 815, self.prx.policies
        )

        self.assertIsInstance(policy, FortiproxyPolicy)

        with self.assertRaises(InterfaceMismatchException):
            policy.add_destination_address(
                get_by("name", "FQDN_golem.de", self.prx.all_addresses)
            )

    def test_fortiproxy_firewall_base_proxy_policy_update_wrong_source_address(self):
        policy: FortiproxyPolicy = get_by(
            "policyid", 815, self.prx.policies
        )

        self.assertIsInstance(policy, FortiproxyPolicy)

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_source_address(
                get_by("name", "http.kali.org", self.prx.all_addresses)
            )

    def test_fortiproxy_firewall_base_proxy_policy_update_add_wrong_interface(self):
        policy = FortiproxyPolicy()

        policy.service.append(get_by("name", "proxy-https", self.prx.services))

        policy.add_source_address(
            get_by(
                "name",
                "NET_199.40.1.0_24",
                self.prx.addresses,
            )
        )
        policy.add_destination_address(
            get_by(
                "name",
                "http.kali.org",
                self.prx.all_addresses,
            )
        )

        policy.add_destination_interface(
            get_by("name", "port2", self.prx.interfaces)
        )

        with self.assertRaises(InterfaceMismatchException):
            policy.add_source_interface(
                get_by("name", "port1", self.prx.interfaces)
            )

    def test_fortiproxy_firewall_base_proxy_policy_remove_address(self):
        policy: FortiproxyPolicy = get_by(
            "policyid", 815, self.prx.policies
        )

        self.assertEqual(1, len(policy.srcaddr))
        self.assertEqual(1, len(policy.dstaddr))

        policy.remove_source_address(
            get_by("name", "NET_172.16.240.120_29", self.prx.addresses)
        )

        self.assertEqual(0, len(policy.srcaddr))

        self.assertEqual(
            get_by("name", "http.kali.org", self.prx.all_addresses),
            policy.dstaddr[0],
        )

    def test_fortiproxy_firewall_base_proxy_policy_remove_interfaces(self):
        policy: FortiproxyPolicy = get_by(
            "policyid", 815, self.prx.policies
        )

        self.assertEqual(1, len(policy.srcintf))
        self.assertEqual(1, len(policy.dstintf))

        policy.remove_source_interface(
            get_by("name", "port2", self.prx.interfaces)
        )
        policy.remove_destination_interface(
            get_by("name", "port1", self.prx.interfaces)
        )

        self.assertEqual(0, len(policy.srcintf))
        self.assertEqual(0, len(policy.dstintf))

    def test_fortiproxy_firewall_base_proxy_policy_update_multiple_interface(self):
        policy = FortiproxyPolicy()

        policy.service.append(get_by("name", "proxy-https", self.prx.services))

        policy.add_source_interface(
            get_by("name", "port4", self.prx.interfaces)
        )

        policy.add_source_interface(
            get_by("name", "port5", self.prx.interfaces)
        )

        policy.add_destination_interface(
            get_by("name", "port5", self.prx.interfaces)
        )

        with self.assertRaises(InterfaceMismatchException):
            policy.add_source_address(
                get_by(
                    "name",
                    "FQDN_golem.de",
                    self.prx.addresses,
                )
            )

    def test_fortiproxy_firewall_base_proxy_policy_vip_address_mixed_address(self):
        policy = FortiproxyPolicy()

        policy.service.append(get_by("name", "proxy-https", self.prx.services))

        policy.add_source_interface(
            get_by("name", "port4", self.prx.interfaces)
        )

        policy.add_destination_interface(
            get_by("name", "port4", self.prx.interfaces)
        )

        policy.add_source_address(
            get_by(
                "name",
                "NET_199.40.1.0_24",
                self.prx.addresses,
            )
        )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_source_address(
                get_by(
                    "name",
                    "vip_test",
                    self.prx.vips,
                )
            )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_source_address(
                get_by(
                    "name",
                    "vip group 1",
                    self.prx.vip_groups,
                )
            )

        policy.add_destination_address(
            get_by(
                "name",
                "http.kali.org",
                self.prx.all_addresses,
            )
        )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_destination_address(
                get_by(
                    "name",
                    "vip_test_2",
                    self.prx.vips,
                )
            )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_destination_address(
                get_by(
                    "name",
                    "vip group 2",
                    self.prx.vip_groups,
                )
            )

    def test_fortiproxy_firewall_base_policy_vip_address_mixed_vip(self):
        policy = FortiproxyPolicy()

        policy.service.append(get_by("name", "proxy-https", self.prx.services))

        policy.add_source_interface(
            get_by("name", "port2", self.prx.interfaces)
        )

        policy.add_destination_interface(
            get_by("name", "port4", self.prx.interfaces)
        )

        policy.add_destination_address(
            get_by(
                "name",
                "vip_test",
                self.prx.vips,
            )
        )

        policy.add_destination_address(
            get_by(
                "name",
                "http.kali.org",
                self.prx.all_addresses,
            )
        )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_destination_address(
                get_by(
                    "name",
                    "test group 1",
                    self.prx.address_groups,
                )
            )

        with self.assertRaises(AddressTypeMismatchException):
            policy.add_destination_address(
                get_by(
                    "name",
                    "NET_172.16.240.120_29",
                    self.prx.all_addresses,
                )
            )
