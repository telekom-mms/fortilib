import ipaddress

import pytest

from fortilib import get_by
from fortilib.address import (
    FortigateFQDNAddress,
    FortigateIpMaskAddress,
    FortigateIPRangeAddress,
)
from tests.integration_tests import FortigateIntegrationTest


class TestIntegrationFirewallAddress(FortigateIntegrationTest):
    def setUp(self):
        super().setUp()

        self.test_address_ipmask = FortigateIpMaskAddress(
            name="test-ipmask",
            subnet=ipaddress.IPv4Network("10.0.0.0/24"),
        )
        self.test_address_iprange = FortigateIPRangeAddress(
            name="test-iprange",
            start_ip=ipaddress.IPv4Address("10.0.0.1"),
            end_ip=ipaddress.IPv4Address("10.0.0.9"),
        )
        self.test_address_fqdn = FortigateFQDNAddress(
            name="test-fqdn",
            fqdn="example.com",
            interface=self.port1,
        )

    @pytest.mark.integration_test
    @pytest.mark.order(1)
    def test_create_address(self) -> None:
        self.fw.create_address(self.test_address_ipmask)
        self.fw.create_address(self.test_address_iprange)
        self.fw.create_address(self.test_address_fqdn)

    @pytest.mark.integration_test
    @pytest.mark.order(2)
    def test_read_address(self) -> None:
        addresses = self.fw.get_addresses()

        test_address_ipmask = get_by(
            "name",
            self.test_address_ipmask.identifier,
            addresses,
        )
        self.assertTrue(
            isinstance(test_address_ipmask, FortigateIpMaskAddress)
        )
        self.assertDictEqual(
            test_address_ipmask.model_dump(),
            self.test_address_ipmask.model_dump(),
        )

        test_address_iprange = get_by(
            "name",
            self.test_address_iprange.identifier,
            addresses,
        )
        self.assertTrue(
            isinstance(test_address_iprange, FortigateIPRangeAddress)
        )
        self.assertDictEqual(
            test_address_iprange.model_dump(),
            self.test_address_iprange.model_dump(),
        )

        test_address_fqdn = get_by(
            "name",
            self.test_address_fqdn.identifier,
            addresses,
        )
        self.assertTrue(isinstance(test_address_fqdn, FortigateFQDNAddress))
        self.assertDictEqual(
            test_address_fqdn.model_dump(), self.test_address_fqdn.model_dump()
        )

    @pytest.mark.integration_test
    @pytest.mark.order(3)
    def test_update_address(self) -> None:
        self.test_address_ipmask.subnet = ipaddress.IPv4Network("10.1.0.0/24")
        self.fw.update_address(self.test_address_ipmask)

        self.test_address_iprange.start_ip = ipaddress.IPv4Address("10.1.0.1")
        self.test_address_iprange.end_ip = ipaddress.IPv4Address("10.1.0.9")
        self.fw.update_address(self.test_address_iprange)

        self.test_address_fqdn.fqdn = "mtnu.de"
        self.fw.update_address(self.test_address_fqdn)

        self.test_read_address()

    @pytest.mark.integration_test
    @pytest.mark.order(4)
    def test_delete_address(self) -> None:
        self.fw.delete_address(self.test_address_ipmask)
        self.fw.delete_address(self.test_address_iprange)
        self.fw.delete_address(self.test_address_fqdn)
