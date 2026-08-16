import ipaddress

import pytest

from fortilib import get_by
from fortilib.address import FortigateFQDNAddress, FortigateIpMaskAddress
from fortilib.address_group import FortigateAddressGroup
from tests.integration_tests import FortigateIntegrationTest


class TestIntegrationFirewallAddress(FortigateIntegrationTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.address1 = FortigateIpMaskAddress(
            name="test-ipmask",
            subnet=ipaddress.IPv4Network("10.0.0.0/24"),
        )
        cls.address2 = FortigateFQDNAddress(
            name="test-fqdn",
            fqdn="example.com",
        )

        cls.fw.create_address(cls.address1)
        cls.fw.create_address(cls.address2)

        cls.group1 = FortigateAddressGroup(
            name="test-group",
            member=[cls.address1, cls.address2],
        )

    @classmethod
    def tearDownClass(cls):
        cls.fw.delete_address(cls.address1)
        cls.fw.delete_address(cls.address2)

        super().tearDownClass()

    @pytest.mark.integration_test
    @pytest.mark.order(1)
    def test_create(self) -> None:
        self.fw.create_address_group(self.group1)

    @pytest.mark.integration_test
    @pytest.mark.order(2)
    def test_read(self) -> None:
        addresses = self.fw.get_addresses()
        groups = self.fw.get_address_groups()

        group = get_by(
            self.group1.identifier_name, self.group1.identifier, groups
        )
        group.resolve_member(addresses)

        self.assertTrue(isinstance(group, FortigateAddressGroup))
        self.assertDictEqual(
            group.model_dump(),
            self.group1.model_dump(),
        )

    @pytest.mark.integration_test
    @pytest.mark.order(3)
    def test_update(self) -> None:
        self.group1.member = [self.address1]
        self.fw.update_address_group(self.group1)

        self.test_read()

    @pytest.mark.integration_test
    @pytest.mark.order(4)
    def test_delete(self) -> None:
        self.fw.delete_address_group(self.group1)
