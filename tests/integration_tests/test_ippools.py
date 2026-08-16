import ipaddress

import pytest

from fortilib import get_by
from fortilib.ippool import FortigateIPPoolOneToOne, FortigateIPPoolOverload
from tests.integration_tests import FortigateIntegrationTest


class TestIntegrationFirewallIPPool(FortigateIntegrationTest):
    def setUp(self):
        super().setUp()

        self.test_ippool_overload = FortigateIPPoolOverload(
            name="test-ippool-overload",
            comment="test-overload-comment",
            start_ip=ipaddress.IPv4Address("10.0.0.10"),
            end_ip=ipaddress.IPv4Address("10.0.0.20"),
        )
        self.test_ippool_one_to_one = FortigateIPPoolOneToOne(
            name="test-ippool-one-to-one",
            comment="test-one-to-one-comment",
            start_ip=ipaddress.IPv4Address("10.0.1.10"),
            end_ip=ipaddress.IPv4Address("10.0.1.20"),
        )

    @pytest.mark.integration_test
    @pytest.mark.order(1)
    def test_create(self) -> None:
        self.fw.create_ippool(self.test_ippool_overload)
        self.fw.create_ippool(self.test_ippool_one_to_one)

    @pytest.mark.integration_test
    @pytest.mark.order(2)
    def test_read(self) -> None:
        ippools = self.fw.get_ippools()

        test_ippool_overload = get_by(
            "name",
            self.test_ippool_overload.identifier,
            ippools,
        )
        self.assertTrue(
            isinstance(test_ippool_overload, FortigateIPPoolOverload)
        )
        self.assertDictEqual(
            test_ippool_overload.model_dump(),
            self.test_ippool_overload.model_dump(),
        )

        test_ippool_one_to_one = get_by(
            "name",
            self.test_ippool_one_to_one.identifier,
            ippools,
        )
        self.assertTrue(
            isinstance(test_ippool_one_to_one, FortigateIPPoolOneToOne)
        )
        self.assertDictEqual(
            test_ippool_one_to_one.model_dump(),
            self.test_ippool_one_to_one.model_dump(),
        )

    @pytest.mark.integration_test
    @pytest.mark.order(3)
    def test_update(self) -> None:
        self.test_ippool_overload.start_ip = ipaddress.IPv4Address("10.0.0.11")
        self.fw.update_ippool(self.test_ippool_overload)

        self.test_ippool_one_to_one.start_ip = ipaddress.IPv4Address(
            "10.0.1.11"
        )
        self.fw.update_ippool(self.test_ippool_one_to_one)

        self.test_read()

    @pytest.mark.integration_test
    @pytest.mark.order(4)
    def test_delete(self) -> None:
        self.fw.delete_ippool(self.test_ippool_overload)
        self.fw.delete_ippool(self.test_ippool_one_to_one)
