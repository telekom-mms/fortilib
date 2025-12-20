from fortilib.firewall import FortigateFirewall
from fortilib.fortigateapi import (
    FortiGateApiPolicyDirection,
    FortigateFirewallApi,
)
from fortilib.proxypolicy import FortiproxyPolicy


class Fortiproxy(FortigateFirewall):
    """Fortigate Firewall object.
    Representation of all firewall objects.

    :param fortigateapi: Fortigate API object (:class:`fortilib.fortigateapi.FortigateFirewallApi`) for API Querys
    :ivar name: Name of fortigate firewall
    :ivar fortigate: Fortigate API object (:class:`fortilib.fortigateapi.FortigateFirewallApi`) for API Querys
    :ivar interfaces: list of :class:`fortilib.interface.FortigateInterface` (default: [])
    :ivar static_routes: list of :class:`fortilib.routes.FortigateStaticRoute` (default: [])
    :ivar addresses: list of :class:`fortilib.address.FortigateAddress` (default: [])
    :ivar address_groups: list of :class:`fortilib.addressgroup.FortigateAddressGroup` (default: [])
    :ivar vips: list of :class:`fortilib.vip.FortigateVIP` (default: [])
    :ivar vip_groups: list of :class:`fortilib.vipgroup.FortigateVIPGroup` (default: [])
    :ivar services: list of :class:`fortilib.service.FortigateService` (default: [])
    :ivar service_groups: list of :class:`fortilib.servicegroup.FortigateServiceGroup` (default: [])
    :ivar ippools: list of :class:`fortilib.ippool.FortigateIPPool` (default: [])
    :ivar policies: list of :class:`fortilib.policy.FortigatePolicy` (default: [])
    :ivar proxy_addresses: list of :class:`fortilib.proxyaddresses.FortigateProxyAddress` (default: [])
    :ivar proxy_address_groups: list of :class:`fortilib.proxyaddressgroup.FortigateProxyAddressGroup` (default: [])
    :ivar proxy_policies: None
    :ivar all_addresses: list of :class:`fortilib.proxyaddresses.FortigateProxyAddress` and :class:`fortilib.address.FortigateAddress` (default: [])
    :ivar phase1_interfaces: None
    :ivar phase2_interfaces: None
    """

    def __init__(self, name: str, fortigateapi: FortigateFirewallApi):
        super().__init__(name, fortigateapi)

        self.policies: list[FortiproxyPolicy] = []

        self.proxy_policies = None
        self.phase1_interfaces = None
        self.phase2_interfaces = None

    def get_all_objects(self):
        """Query Fortiproxy API for all firewall objects of the following list.

        - Interfaces
        - Static Routes
        - Addresses
        - Address Groups
        - VIPs
        - VIP Groups
        - Services
        - Service Groups
        - IPPools
        - Policies
        - Proxy Addresses
        - Proxy Address Groups
        - Addresses and Proxy Addresses
        """
        self.interfaces = self.get_interfaces()
        self.static_routes = self.get_static_routes()
        self.addresses = self.get_addresses()
        self.address_groups = self.get_address_groups()
        self.resolve_address_groups()
        self.proxy_addresses = self.get_proxy_addresses()
        self.proxy_address_groups = self.get_proxy_address_groups()
        self.resolve_proxy_address_groups()
        self.vips = self.get_vips()
        self.vip_groups = self.get_vip_groups()
        self.resolve_vip_groups()
        self.services = self.get_services()
        self.service_groups = self.get_service_groups()
        self.resolve_service_groups()
        self.ippools = self.get_ippools()
        self.policies = self.get_policies()
        self.all_addresses = self.get_all_addresses()

    def get_policies(self) -> list[FortiproxyPolicy]:
        """Query Fortiproxy API for policies
        :obj:`fortilib.policy.FortigatePolicy` and create list.
        """
        policies: list[FortiproxyPolicy] = []
        for raw in self.fortigate.get_firewall_policies():
            policy = FortiproxyPolicy.from_dict(raw)

            policy.find_interfaces(self.interfaces)
            policy.find_addresses(
                [
                    self.addresses,
                    self.address_groups,
                    self.vips,
                    self.vip_groups,
                    self.proxy_addresses,
                    self.proxy_address_groups,
                ]
            )
            policy.find_services([self.services, self.service_groups])

            policies.append(policy)

        return policies

    def create_firewall_policy(self, policy: FortiproxyPolicy):
        """Create policy on fortigate with given :obj:`fortilib.proxypolicy.FortiproxyPolicy`."""
        status = self.fortigate.create_firewall_policy(
            int(policy.policyid), policy.render()
        )

        policy.policyid = status["mkey"]

        self.policies.append(policy)
        return status

    def update_firewall_policy(self, policy: FortiproxyPolicy):
        """Update policy on fortiproxy with given :obj:`fortilib.proxypolicy.FortiproxyPolicy`."""
        return self.fortigate.update_firewall_policy(
            policy.policyid, policy.render()
        )

    def delete_firewall_policy(self, policy: FortiproxyPolicy):
        """Delete policy on fortiproxy with given :obj:`fortilib.proxypolicy.FortiproxyPolicy`."""
        status = self.fortigate.delete_firewall_policy(policy.policyid)
        self.policies.remove(policy)
        return status

    def move_firewall_policy(
        self,
        policy: FortiproxyPolicy,
        move_direction: FortiGateApiPolicyDirection,
        move_identifier_policy: FortiproxyPolicy,
    ):
        """move policy on fortiproxy to another position with given :obj:`fortilib.proxypolicy.FortiproxyPolicy`, :obj:`fortilib.fortigateapi.FortiGateApiPolicyDirection` and :obj:`fortilib.policy.FortigatePolicy`."""

        return self.fortigate.move_firewall_policy(
            policy.policyid,
            move_direction,
            move_identifier_policy.policyid,
        )

    def get_proxy_policies(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.get_proxy_policies.__name__}",
            obj=Fortiproxy,
            name=f"{self.get_proxy_policies.__name__}",
        )

    def update_firewall_proxy_policy(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.update_firewall_proxy_policy.__name__}",
            obj=Fortiproxy,
            name=f"{self.update_firewall_proxy_policy.__name__}",
        )

    def delete_firewall_proxy_policy(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.delete_firewall_proxy_policy.__name__}",
            obj=Fortiproxy,
            name=f"{self.delete_firewall_proxy_policy.__name__}",
        )

    def move_firewall_proxy_policy(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.move_firewall_proxy_policy.__name__}",
            obj=Fortiproxy,
            name=f"{self.move_firewall_proxy_policy.__name__}",
        )

    def get_phase1_interfaces(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.get_phase1_interfaces.__name__}",
            obj=Fortiproxy,
            name=f"{self.get_phase1_interfaces.__name__}",
        )

    def create_firewall_phase1_interface(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.create_firewall_phase1_interface.__name__}",
            obj=Fortiproxy,
            name=f"{self.create_firewall_phase1_interface.__name__}",
        )

    def update_firewall_phase1_interface(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.update_firewall_phase1_interface.__name__}",
            obj=Fortiproxy,
            name=f"{self.update_firewall_phase1_interface.__name__}",
        )

    def delete_firewall_phase1_interface(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.delete_firewall_phase1_interface.__name__}",
            obj=Fortiproxy,
            name=f"{self.delete_firewall_phase1_interface.__name__}",
        )

    def get_phase2_interfaces(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.get_phase2_interfaces.__name__}",
            obj=Fortiproxy,
            name=f"{self.get_phase2_interfaces.__name__}",
        )

    def create_firewall_phase2_interface(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.create_firewall_phase2_interface.__name__}",
            obj=Fortiproxy,
            name=f"{self.create_firewall_phase2_interface.__name__}",
        )

    def update_firewall_phase2_interface(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.update_firewall_phase2_interface.__name__}",
            obj=Fortiproxy,
            name=f"{self.update_firewall_phase2_interface.__name__}",
        )

    def delete_firewall_phase2_interface(self):
        raise AttributeError(
            f"{Fortiproxy} has no Method {self.delete_firewall_phase2_interface.__name__}",
            obj=Fortiproxy,
            name=f"{self.delete_firewall_phase2_interface.__name__}",
        )
