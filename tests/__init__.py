import unittest
from unittest import mock
from unittest.mock import MagicMock

from fortilib.firewall import FortigateFirewall
from fortilib.fortiproxy import Fortiproxy
from tests import data


def get_fw_mocked(mock_fw_api) -> FortigateFirewall:
    mock_fw_api.get_firewall_address = MagicMock(return_value=data.addresses)
    mock_fw_api.get_firewall_route_static = MagicMock(return_value=data.routes)
    mock_fw_api.get_firewall_interface = MagicMock(
        return_value=data.interfaces
    )
    mock_fw_api.get_firewall_address_group = MagicMock(
        return_value=data.address_groups
    )
    mock_fw_api.get_firewall_vip = MagicMock(return_value=data.vips)
    mock_fw_api.get_firewall_vip_group = MagicMock(
        return_value=data.vip_groups
    )
    mock_fw_api.get_firewall_service = MagicMock(return_value=data.services)
    mock_fw_api.get_firewall_service_groups = MagicMock(
        return_value=data.service_groups
    )
    mock_fw_api.get_firewall_ippool = MagicMock(return_value=data.ippools)
    mock_fw_api.get_firewall_policies = MagicMock(return_value=data.policies)
    mock_fw_api.get_firewall_proxy_policies = MagicMock(
        return_value=data.proxy_policies
    )
    mock_fw_api.get_firewall_proxy_address = MagicMock(
        return_value=data.proxy_addresses
    )
    mock_fw_api.get_firewall_proxy_address_group = MagicMock(
        return_value=data.proxy_address_groups
    )
    mock_fw_api.get_firewall_phase1_interface = MagicMock(
        return_value=data.phase1_interfaces
    )
    mock_fw_api.get_firewall_phase2_interface = MagicMock(
        return_value=data.phase2_interfaces
    )

    mock_fw_api.login = MagicMock()

    mock_fw_api.create_firewall_address = MagicMock()
    mock_fw_api.update_firewall_address = MagicMock()
    mock_fw_api.delete_firewall_address = MagicMock()

    mock_fw_api.create_firewall_address_group = MagicMock()
    mock_fw_api.update_firewall_address_group = MagicMock()
    mock_fw_api.delete_firewall_address_group = MagicMock()

    mock_fw_api.create_firewall_vip = MagicMock()
    mock_fw_api.update_firewall_vip = MagicMock()
    mock_fw_api.delete_firewall_vip = MagicMock()

    mock_fw_api.create_firewall_vip_group = MagicMock()
    mock_fw_api.update_firewall_vip_group = MagicMock()
    mock_fw_api.delete_firewall_vip_group = MagicMock()

    mock_fw_api.create_firewall_service = MagicMock()
    mock_fw_api.update_firewall_service = MagicMock()
    mock_fw_api.delete_firewall_service = MagicMock()

    mock_fw_api.create_firewall_service_group = MagicMock()
    mock_fw_api.update_firewall_service_group = MagicMock()
    mock_fw_api.delete_firewall_service_group = MagicMock()

    mock_fw_api.create_firewall_ippool = MagicMock()
    mock_fw_api.update_firewall_ippool = MagicMock()
    mock_fw_api.delete_firewall_ippool = MagicMock()

    mock_fw_api.create_firewall_route_static = MagicMock()
    mock_fw_api.update_firewall_route_static = MagicMock()
    mock_fw_api.delete_firewall_route_static = MagicMock()

    mock_fw_api.create_firewall_policy = MagicMock()
    mock_fw_api.update_firewall_policy = MagicMock()
    mock_fw_api.move_firewall_policy = MagicMock()
    mock_fw_api.delete_firewall_policy = MagicMock()

    mock_fw_api.create_firewall_proxy_address = MagicMock()
    mock_fw_api.update_firewall_proxy_address = MagicMock()
    mock_fw_api.delete_firewall_proxy_address = MagicMock()

    mock_fw_api.create_firewall_proxy_address_group = MagicMock()
    mock_fw_api.update_firewall_proxy_address_group = MagicMock()
    mock_fw_api.delete_firewall_proxy_address_group = MagicMock()

    mock_fw_api.create_firewall_proxy_policy = MagicMock()
    mock_fw_api.update_firewall_proxy_policy = MagicMock()
    mock_fw_api.delete_firewall_proxy_policy = MagicMock()

    mock_fw_api.create_firewall_phase1_interface = MagicMock()
    mock_fw_api.update_firewall_phase1_interface = MagicMock()
    mock_fw_api.delete_firewall_phase1_interface = MagicMock()

    mock_fw_api.create_firewall_phase2_interface = MagicMock()
    mock_fw_api.update_firewall_phase2_interface = MagicMock()
    mock_fw_api.delete_firewall_phase2_interface = MagicMock()

    fw = FortigateFirewall("test", mock_fw_api)
    fw.login()

    return fw

def get_prx_mocked(mock_prx_api) -> Fortiproxy:
    mock_prx_api.get_firewall_address = MagicMock(return_value=data.addresses)
    mock_prx_api.get_firewall_route_static = MagicMock(return_value=data.routes)
    mock_prx_api.get_firewall_interface = MagicMock(
        return_value=data.interfaces
    )
    mock_prx_api.get_firewall_address_group = MagicMock(
        return_value=data.address_groups
    )
    mock_prx_api.get_firewall_vip = MagicMock(return_value=data.vips)
    mock_prx_api.get_firewall_vip_group = MagicMock(
        return_value=data.vip_groups
    )
    mock_prx_api.get_firewall_service = MagicMock(return_value=data.services)
    mock_prx_api.get_firewall_service_groups = MagicMock(
        return_value=data.service_groups
    )
    mock_prx_api.get_firewall_ippool = MagicMock(return_value=data.ippools)
    mock_prx_api.get_firewall_policies = MagicMock(return_value=data.forti_proxy_policies)
    mock_prx_api.get_firewall_proxy_address = MagicMock(
        return_value=data.proxy_addresses
    )
    mock_prx_api.get_firewall_proxy_address_group = MagicMock(
        return_value=data.proxy_address_groups
    )

    mock_prx_api.login = MagicMock()

    mock_prx_api.create_firewall_address = MagicMock()
    mock_prx_api.update_firewall_address = MagicMock()
    mock_prx_api.delete_firewall_address = MagicMock()

    mock_prx_api.create_firewall_address_group = MagicMock()
    mock_prx_api.update_firewall_address_group = MagicMock()
    mock_prx_api.delete_firewall_address_group = MagicMock()

    mock_prx_api.create_firewall_vip = MagicMock()
    mock_prx_api.update_firewall_vip = MagicMock()
    mock_prx_api.delete_firewall_vip = MagicMock()

    mock_prx_api.create_firewall_vip_group = MagicMock()
    mock_prx_api.update_firewall_vip_group = MagicMock()
    mock_prx_api.delete_firewall_vip_group = MagicMock()

    mock_prx_api.create_firewall_service = MagicMock()
    mock_prx_api.update_firewall_service = MagicMock()
    mock_prx_api.delete_firewall_service = MagicMock()

    mock_prx_api.create_firewall_service_group = MagicMock()
    mock_prx_api.update_firewall_service_group = MagicMock()
    mock_prx_api.delete_firewall_service_group = MagicMock()

    mock_prx_api.create_firewall_ippool = MagicMock()
    mock_prx_api.update_firewall_ippool = MagicMock()
    mock_prx_api.delete_firewall_ippool = MagicMock()

    mock_prx_api.create_firewall_route_static = MagicMock()
    mock_prx_api.update_firewall_route_static = MagicMock()
    mock_prx_api.delete_firewall_route_static = MagicMock()

    mock_prx_api.create_firewall_policy = MagicMock()
    mock_prx_api.update_firewall_policy = MagicMock()
    mock_prx_api.move_firewall_policy = MagicMock()
    mock_prx_api.delete_firewall_policy = MagicMock()

    mock_prx_api.create_firewall_proxy_address = MagicMock()
    mock_prx_api.update_firewall_proxy_address = MagicMock()
    mock_prx_api.delete_firewall_proxy_address = MagicMock()

    mock_prx_api.create_firewall_proxy_address_group = MagicMock()
    mock_prx_api.update_firewall_proxy_address_group = MagicMock()
    mock_prx_api.delete_firewall_proxy_address_group = MagicMock()

    prx = Fortiproxy("test_prx", mock_prx_api)
    prx.login()

    return prx

class FortigateTest(unittest.TestCase):
    @mock.patch("fortilib.fortigateapi.FortigateFirewallApi")
    def setUp(self, mock_fw_api):
        self.fw = get_fw_mocked(mock_fw_api)
        self.fw.get_all_objects()

class FortiproxyTest(unittest.TestCase):
    @mock.patch("fortilib.fortigateapi.FortigateFirewallApi")
    def setUp(self, mock_prx_api):
        self.prx = get_prx_mocked(mock_prx_api)
        self.prx.get_all_objects()
