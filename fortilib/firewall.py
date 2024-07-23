from typing import (
    List,
    Union,
)

from fortilib.address import (
    FortigateAddress,
    FortigateFQDN,
    FortigateIpMask,
    FortigateIpRange,
)
from fortilib.addressgroup import FortigateAddressGroup
from fortilib.base import FortigateNamedObject
from fortilib.fortigateapi import (
    FortiGateApiPolicyDirection,
    FortigateFirewallApi,
)
from fortilib.interface import FortigateInterface
from fortilib.ippool import FortigateIPPool
from fortilib.policy import FortigatePolicy
from fortilib.proxyaddress import (
    FortigateProxyAddress,
    FortigateProxyAddressHostRegex,
    FortigateProxyAddressURL,
)
from fortilib.proxyaddressgroup import FortigateProxyAddressGroup
from fortilib.proxypolicy import FortigateProxyPolicy
from fortilib.routes import FortigateStaticRoute
from fortilib.service import (
    FortigateICMP6Service,
    FortigateICMPService,
    FortigateIPService,
    FortigateProxyService,
    FortigateService,
    FortigateTCPUDPService,
)
from fortilib.servicegroup import FortigateServiceGroup
from fortilib.vip import FortigateVIP
from fortilib.vipgroup import FortigateVIPGroup


class FortigateFirewall:
    """Fortigate Firewall object.
    Representation of all firewall objects.

    :param fortigateapi: Fortigate API object (:class:`fortilib.fortigateapi.FortigateFirewallApi`) for API Querys
    :ivar name: Name of fortigate firewall
    :ivar fortigate: Fortigate API object (:class:`fortilib.fortigateapi.FortigateFirewallApi`) for API Querys
    :ivar interfaces: List of :class:`fortilib.interface.FortigateInterface` (default: [])
    :ivar static_routes: List of :class:`fortilib.routes.FortigateStaticRoute` (default: [])
    :ivar addresses: List of :class:`fortilib.address.FortigateAddress` (default: [])
    :ivar address_groups: List of :class:`fortilib.addressgroup.FortigateAddressGroup` (default: [])
    :ivar vips: List of :class:`fortilib.vip.FortigateVIP` (default: [])
    :ivar vip_groups: List of :class:`fortilib.vipgroup.FortigateVIPGroup` (default: [])
    :ivar services: List of :class:`fortilib.service.FortigateService` (default: [])
    :ivar service_groups: List of :class:`fortilib.servicegroup.FortigateServiceGroup` (default: [])
    :ivar ippools: List of :class:`fortilib.ippool.FortigateIPPool` (default: [])
    :ivar policies: List of :class:`fortilib.policy.FortigatePolicy` (default: [])
    :ivar proxy_addresses: List of :class:`fortilib.proxyaddresses.FortigateProxyAddress` (default: [])
    :ivar proxy_address_groups: List of :class:`fortilib.proxyaddressgroup.FortigateProxyAddressGroup` (default: [])
    :ivar proxy_policies: List of :class:`fortilib.proxypolicies.FortigateProxyPolicy` (default: [])
    :ivar all_addresses: List of :class:`fortilib.proxyaddresses.FortigateProxyAddress` and :class:`fortilib.address.FortigateAddress` (default: [])
    """

    def __init__(self, name: str, fortigateapi: FortigateFirewallApi):
        self.name = name
        self.fortigate = fortigateapi

        self.interfaces: List[FortigateInterface] = []
        self.static_routes: List[FortigateStaticRoute] = []
        self.addresses: List[FortigateAddress] = []
        self.address_groups: List[FortigateAddressGroup] = []
        self.vips: List[FortigateVIP] = []
        self.vip_groups: List[FortigateVIPGroup] = []
        self.services: List[FortigateService] = []
        self.service_groups: List[FortigateServiceGroup] = []
        self.ippools: List[FortigateIPPool] = []
        self.policies: List[FortigatePolicy] = []
        self.proxy_addresses: List[FortigateProxyAddress] = []
        self.proxy_address_groups: List[FortigateProxyAddressGroup] = []
        self.proxy_policies: List[FortigateProxyPolicy] = []
        self.all_addresses: List[
            Union[FortigateAddress, FortigateProxyAddress]
        ]

    def login(self):
        """Login into Fortigate API with :meth:`fortilib.fortigateapi.FortigateFirewallApi.login`."""
        self.fortigate.login()

    def logout(self):
        """Logout from Fortigate API with :meth:`fortilib.fortigateapi.FortigateFirewallApi.logout`."""
        self.fortigate.logout()

    def __repr__(self):
        return f"{self.name}"

    def get_all_objects(self):
        """Query Fortigate API for all firewall objects of the following list.

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
        - Proxy Policies
        - Addresses and Proxy Addresses
        """
        self.interfaces = self.get_interfaces()
        self.static_routes = self.get_static_routes()
        self.addresses = self.get_addresses()
        self.address_groups = self.get_address_groups()
        self.resolve_address_groups()
        self.vips = self.get_vips()
        self.vip_groups = self.get_vip_groups()
        self.resolve_vip_groups()
        self.services = self.get_services()
        self.service_groups = self.get_service_groups()
        self.resolve_service_groups()
        self.ippools = self.get_ippools()
        self.policies = self.get_policies()
        self.proxy_addresses = self.get_proxy_addresses()
        self.proxy_address_groups = self.get_proxy_address_groups()
        self.resolve_proxy_address_groups()
        self.proxy_policies = self.get_proxy_policies()
        self.all_addresses = self.get_all_addresses()

    def get_addresses(self) -> List[FortigateAddress]:
        """Query Fortigate API for addresses
        :class:`fortilib.address.FortigateAddress` and
        create list with items of the following classes.

            - General Address :class:`fortilib.address.FortigateAddress`
            - IP Mask :class:`fortilib.address.FortigateIpMask`
            - IP Range :class:`fortilib.address.FortigateIpRange`
            - FQDN :class:`fortilib.address.FortigateFQDN`
        """
        addresses: List[FortigateAddress] = []
        for raw in self.fortigate.get_firewall_address():
            address = FortigateAddress.from_dict(raw)
            if raw["type"] == "ipmask":
                address = FortigateIpMask.from_dict(raw)
            elif raw["type"] == "iprange":
                address = FortigateIpRange.from_dict(raw)
            elif raw["type"] == "fqdn":
                address = FortigateFQDN.from_dict(raw)

            address.find_interface(self.interfaces)
            addresses.append(address)

        return addresses

    def get_address_groups(self) -> List[FortigateAddressGroup]:
        """Query Fortigate API for address groups
        :class:`fortilib.addressgroup.FortigateAddressGroup` and create list.

        .. warning:: Before further use of address groups execute :func:`resolve_address_groups`.
        """
        groups: List[FortigateAddressGroup] = []
        for raw in self.fortigate.get_firewall_address_group():
            group = FortigateAddressGroup.from_dict(raw)

            groups.append(group)
        return groups

    def resolve_address_groups(self):
        """Resolve addresses in address groups.

        Needed to get the correct relations out of the raw `object_data`
        of :class:`fortilib.base.FortigateObject`.
        """
        for group in self.address_groups:
            group.member.clear()
            group.find_member([self.addresses, self.address_groups])

    def get_vips(self) -> List[FortigateVIP]:
        """Query Fortigate API for vips
        :class:`fortilib.vip.FortigateVIP` and create list.
        """
        vips: List[FortigateVIP] = []
        for raw in self.fortigate.get_firewall_vip():
            vip = FortigateVIP.from_dict(raw)
            vip.find_interface(self.interfaces)
            vips.append(vip)

        return vips

    def get_vip_groups(self) -> List[FortigateVIPGroup]:
        """Query Fortigate API for vip groups and create list.

        .. warning:: Before further use of vip groups execute :func:`resolve_vip_groups`.
        """
        groups: List[FortigateVIPGroup] = []
        for raw in self.fortigate.get_firewall_vip_group():
            group = FortigateVIPGroup.from_dict(raw)
            group.find_interface(self.interfaces)

            groups.append(group)

        return groups

    def resolve_vip_groups(self):
        """Resolve vips in vip groups.

        Needed to get the correct relations out of the raw `object_data`
        of :class:`fortilib.base.FortigateObject`.
        """
        for group in self.vip_groups:
            group.member.clear()
            group.find_member([self.vips, self.vip_groups])

    def get_static_routes(self) -> List[FortigateStaticRoute]:
        """Query Fortigate API for static routes
        :class:`fortilib.routes.FortigateStaticRoute` and create list.
        """
        routes: List[FortigateStaticRoute] = []
        for raw in self.fortigate.get_firewall_route_static():
            route = FortigateStaticRoute.from_dict(raw)
            route.find_interface(self.interfaces)

            routes.append(route)

        return routes

    def get_interfaces(self) -> List[FortigateInterface]:
        """Query Fortigate API for interfaces
        :class:`fortilib.interface.FortigateInterface` and create list.
        """
        interfaces: List[FortigateInterface] = [
            FortigateInterface.from_dict({"name": "any"})
        ]
        for raw in self.fortigate.get_firewall_interface():
            interface = FortigateInterface.from_dict(raw)
            interfaces.append(interface)

        return interfaces

    def get_services(self) -> List[FortigateService]:
        """Query Fortigate API for vips :class:`fortilib.service.FortigateService` and
        create list with items of the following classes.

            - General Service :class:`fortilib.service.FortigateService`
            - ICMPv4 Service :class:`fortilib.service.FortigateICMPService`
            - ICMPv6 Service :class:`fortilib.service.FortigateICMP6Service`
            - TCP/UDP Service :class:`fortilib.service.FortigateTCPUDPService`
            - IP Service :class:`fortilib.service.FortigateIPService`
        """
        services: List[FortigateService] = []
        for raw in self.fortigate.get_firewall_service():
            service = FortigateService.from_dict(raw)

            if raw["protocol"] == "ICMP":
                service = FortigateICMPService.from_dict(raw)
            if raw["protocol"] == "ICMP6":
                service = FortigateICMP6Service.from_dict(raw)
            elif raw["protocol"] in "TCP/UDP/SCTP":
                service = FortigateTCPUDPService.from_dict(raw)
            elif raw["protocol"] == "IP":
                service = FortigateIPService.from_dict(raw)
            elif raw["protocol"] == "ALL":
                service = FortigateProxyService.from_dict(raw)

            services.append(service)

        return services

    def get_service_groups(self) -> List[FortigateServiceGroup]:
        """Query Fortigate API for service groups
        :obj:`fortilib.servicegroup.FortigateServiceGroup` and create list.

        .. warning:: Before further use of service groups execute :func:`resolve_service_groups`.
        """
        groups: List[FortigateServiceGroup] = []
        for raw in self.fortigate.get_firewall_service_groups():
            group = FortigateServiceGroup.from_dict(raw)

            groups.append(group)

        return groups

    def resolve_service_groups(self):
        """Resolve services in service groups.

        Needed to get the correct relations out of the raw `object_data`
        of :class:`fortilib.base.FortigateObject`.
        """
        for group in self.service_groups:
            group.member.clear()
            group.find_member([self.services, self.service_groups])

    def get_ippools(self) -> List[FortigateIPPool]:
        """Query Fortigate API for ip pools
        :obj:`fortilib.ippool.FortigateIPPool` and create list.
        """
        ippools: List[FortigateIPPool] = []
        for raw in self.fortigate.get_firewall_ippool():
            ippool = FortigateIPPool.from_dict(raw)

            ippools.append(ippool)

        return ippools

    def create_firewall_ippool(self, pool: FortigateIPPool):
        """Create ip pool on fortigate with given :obj:`fortilib.ippool.FortigateIPPool`."""
        status = self.fortigate.create_firewall_ippool(
            pool.name, pool.render()
        )
        self.ippools.append(pool)
        return status

    def update_firewall_ippool(self, pool: FortigateIPPool):
        """Update ip pool on fortigate with given :obj:`fortilib.ippool.FortigateIPPool`."""
        return self.fortigate.update_firewall_ippool(pool.name, pool.render())

    def delete_firewall_ippool(self, pool: FortigateIPPool):
        """Delete ip pool on fortigate with given :obj:`fortilib.ippool.FortigateIPPool`."""
        status = self.fortigate.delete_firewall_ippool(pool.name)
        self.ippools.remove(pool)
        return status

    def get_policies(self) -> List[FortigatePolicy]:
        """Query Fortigate API for policies
        :obj:`fortilib.policy.FortigatePolicy` and create list.
        """
        policies: List[FortigatePolicy] = []
        for raw in self.fortigate.get_firewall_policies():
            policy = FortigatePolicy.from_dict(raw)

            policy.find_interfaces(self.interfaces)
            policy.find_addresses(
                [
                    self.addresses,
                    self.address_groups,
                    self.vips,
                    self.vip_groups,
                ]
            )
            policy.find_services([self.services, self.service_groups])
            policy.find_ippools(self.ippools)

            policies.append(policy)

        return policies

    def create_firewall_address(self, address: FortigateAddress):
        """Create address on fortigate
        with given :obj:`fortilib.address.FortigateAddress`.
        """
        status = self.fortigate.create_firewall_address(
            address.name,
            address.render(),
        )
        self.addresses.append(address)
        return status

    def update_firewall_address(self, address: FortigateAddress):
        """Update address on fortigate
        with given :obj:`fortilib.address.FortigateAddress`.
        """
        return self.fortigate.update_firewall_address(
            address.name,
            address.render(),
        )

    def delete_firewall_address(self, address: FortigateAddress):
        """Delete address on fortigate
        with given :obj:`fortilib.address.FortigateAddress`.
        """
        status = self.fortigate.delete_firewall_address(address.name)
        self.addresses.remove(address)
        return status

    def create_firewall_address_group(self, group: FortigateAddressGroup):
        """Create address group on fortigate
        with given :obj:`fortilib.addressgroup.FortigateAddressGroup`.
        """
        status = self.fortigate.create_firewall_address_group(
            group.name, group.render()
        )
        self.address_groups.append(group)
        return status

    def update_firewall_address_group(self, group: FortigateAddressGroup):
        """Update address group on fortigate
        with given :obj:`fortilib.addressgroup.FortigateAddressGroup`.
        """
        return self.fortigate.update_firewall_address_group(
            group.name, group.render()
        )

    def delete_firewall_address_group(self, group: FortigateAddressGroup):
        """Delete address group on fortigate
        with given :obj:`fortilib.addressgroup.FortigateAddressGroup`.
        """
        status = self.fortigate.delete_firewall_address_group(group.name)
        self.address_groups.remove(group)
        return status

    def create_firewall_vip(self, vip: FortigateVIP):
        """Create vip on fortigate with given :obj:`fortilib.vip.FortigateVIP`."""
        status = self.fortigate.create_firewall_vip(
            vip.name,
            vip.render(),
        )
        self.vips.append(vip)
        return status

    def update_firewall_vip(self, vip: FortigateVIP):
        """Update vip on fortigate with given :obj:`fortilib.vip.FortigateVIP`."""
        return self.fortigate.update_firewall_vip(
            vip.name,
            vip.render(),
        )

    def delete_firewall_vip(self, vip: FortigateVIP):
        """Delete vip on fortigate with given :obj:`fortilib.vip.FortigateVIP`."""
        status = self.fortigate.delete_firewall_vip(vip.name)
        self.vips.remove(vip)
        return status

    def create_firewall_vip_group(self, vip_group: FortigateVIPGroup):
        """Create vip group on fortigate with given :obj:`fortilib.vipgroup.FortigateVIPGroup`."""
        status = self.fortigate.create_firewall_vip_group(
            vip_group.name, vip_group.render()
        )
        self.vip_groups.append(vip_group)
        return status

    def update_firewall_vip_group(self, vip_group: FortigateVIPGroup):
        """Update vip group on fortigate with given :obj:`fortilib.vipgroup.FortigateVIPGroup`."""
        return self.fortigate.update_firewall_vip_group(
            vip_group.name, vip_group.render()
        )

    def delete_firewall_vip_group(self, vip_group: FortigateVIPGroup):
        """Delete vip group on fortigate with given :obj:`fortilib.vipgroup.FortigateVIPGroup`."""
        status = self.fortigate.delete_firewall_vip_group(vip_group.name)
        self.vip_groups.remove(vip_group)
        return status

    def create_firewall_service(self, service: FortigateService):
        """Create service on fortigate with given :obj:`fortilib.service.FortigateService`."""
        status = self.fortigate.create_firewall_service(
            service.name, service.render()
        )
        self.services.append(service)
        return status

    def update_firewall_service(self, service: FortigateService):
        """Update service on fortigate with given :obj:`fortilib.service.FortigateService`."""
        return self.fortigate.update_firewall_service(
            service.name, service.render()
        )

    def delete_firewall_service(self, service: FortigateService):
        """Delete service on fortigate with given :obj:`fortilib.service.FortigateService`."""
        status = self.fortigate.delete_firewall_service(service.name)
        self.services.remove(service)
        return status

    def create_firewall_service_group(self, group: FortigateServiceGroup):
        """Create service group on fortigate with given :obj:`fortilib.servicegroup.FortigateServiceGroup`."""
        status = self.fortigate.create_firewall_service_group(
            group.name, group.render()
        )
        self.service_groups.append(group)
        return status

    def update_firewall_service_group(self, group: FortigateServiceGroup):
        """Update service group on fortigate with given :obj:`fortilib.servicegroup.FortigateServiceGroup`."""
        return self.fortigate.update_firewall_service_group(
            group.name, group.render()
        )

    def delete_firewall_service_group(self, group: FortigateServiceGroup):
        """Delete service group on fortigate with given :obj:`fortilib.servicegroup.FortigateServiceGroup`."""
        status = self.fortigate.delete_firewall_service_group(group.name)
        self.service_groups.remove(group)
        return status

    def create_firewall_route_static(self, route: FortigateStaticRoute):
        """Create static route on fortigate with given :obj:`fortilib.routes.FortigateStaticRoute`."""
        status = self.fortigate.create_firewall_route_static(
            str(route.seq_num), route.render()
        )
        self.static_routes.append(route)
        return status

    def update_firewall_route_static(self, route: FortigateStaticRoute):
        """Update static route on fortigate with given :obj:`fortilib.routes.FortigateStaticRoute`."""
        return self.fortigate.update_firewall_route_static(
            str(route.seq_num), route.render()
        )

    def delete_firewall_route_static(self, route: FortigateStaticRoute):
        """Delete static route on fortigate with given :obj:`fortilib.routes.FortigateStaticRoute`."""
        status = self.fortigate.delete_firewall_route_static(
            str(route.seq_num)
        )
        self.static_routes.remove(route)
        return status

    def get_next_free_static_route_seq_number(self) -> int:
        """Get next free sequence number of static routes.
        Is used to reference static routes on the fortigate like an id.
        """
        max_route: FortigateStaticRoute = max(
            self.static_routes, key=lambda route: route.seq_num
        )
        return max_route.seq_num + 1

    def create_firewall_policy(self, policy: FortigatePolicy):
        """Create policy on fortigate with given :obj:`fortilib.policy.FortigatePolicy`."""
        status = self.fortigate.create_firewall_policy(
            int(policy.policyid), policy.render()
        )

        policy.policyid = status["mkey"]

        self.policies.append(policy)
        return status

    def update_firewall_policy(self, policy: FortigatePolicy):
        """Update policy on fortigate with given :obj:`fortilib.policy.FortigatePolicy`."""
        return self.fortigate.update_firewall_policy(
            policy.policyid, policy.render()
        )

    def move_firewall_policy(
        self,
        policy: FortigatePolicy,
        move_direction: FortiGateApiPolicyDirection,
        move_identifier_policy: FortigatePolicy,
    ):
        """move policy on fortigate to another position with given :obj:`fortilib.policy.FortigatePolicy`, :obj:`fortilib.fortigateapi.FortiGateApiPolicyDirection` and :obj:`fortilib.policy.FortigatePolicy`."""

        return self.fortigate.move_firewall_policy(
            policy.policyid,
            move_direction,
            move_identifier_policy.policyid,
        )

    def move_firewall_proxy_policy(
        self,
        policy: FortigateProxyPolicy,
        move_direction: FortiGateApiPolicyDirection,
        move_identifier_policy: FortigateProxyPolicy,
    ):
        """move proxy-policy on fortigate to another position with given :obj:`fortilib.policy.FortigatePolicy`, :obj:`fortilib.fortigateapi.FortiGateApiPolicyDirection` and :obj:`fortilib.policy.FortigateProxyPolicy`."""

        return self.fortigate.move_firewall_proxy_policy(
            policy.policyid,
            move_direction,
            move_identifier_policy.policyid,
        )

    def delete_firewall_policy(self, policy: FortigatePolicy):
        """Delete policy on fortigate with given :obj:`fortilib.policy.FortigatePolicy`."""
        status = self.fortigate.delete_firewall_policy(policy.policyid)
        self.policies.remove(policy)
        return status

    def get_proxy_addresses(self) -> List[FortigateProxyAddress]:
        """Query Fortigate API for proxy addresses
        :class:`fortilib.proxyaddress.FortigateProxyAddress` and
        create list with items of the following classes.

            - General Proxy Address :class:`fortilib.proxyaddress.FortigateProxyAddress`
            - Host Regex :class:`fortilib.proxyaddress.FortigateProxyAddressHostRegex`
            - URL :class:`fortilib.proxyaddress.FortigateProxyAddressURL`
        """
        addresses: List[FortigateProxyAddress] = []
        for raw in self.fortigate.get_firewall_proxy_address():
            address = FortigateProxyAddress.from_dict(raw)
            if raw["type"] == "host-regex":
                address = FortigateProxyAddressHostRegex.from_dict(raw)
            if raw["type"] == "url":
                address = FortigateProxyAddressURL.from_dict(raw)
            addresses.append(address)

        return addresses

    def get_proxy_address_groups(self) -> List[FortigateProxyAddressGroup]:
        """Query Fortigate API for proxy address groups
        :class:`fortilib.proxyaddressgroup.FortigateProxyAddressGroup` and create list.

        .. warning:: Before further use of proxy address groups execute :func:`resolve_proxy_address_groups`.
        """
        groups: List[FortigateProxyAddressGroup] = []
        for raw in self.fortigate.get_firewall_proxy_address_group():
            group = FortigateProxyAddressGroup.from_dict(raw)

            groups.append(group)
        return groups

    def resolve_proxy_address_groups(self):
        """Resolve proxy addresses in proxy address groups.

        Needed to get the correct relations out of the raw `object_data`
        of :class:`fortilib.base.FortigateObject`.
        """
        for group in self.proxy_address_groups:
            group.member.clear()
            group.find_member(
                [self.proxy_addresses, self.proxy_address_groups]
            )

    def get_all_addresses(
        self,
    ) -> List[Union[FortigateProxyAddress, FortigateAddress]]:
        """Create list with items of the following classes

        - General Address :class:`fortilib.address.FortigateAddress`
        - IP Mask :class:`fortilib.address.FortigateIpMask`
        - IP Range :class:`fortilib.address.FortigateIpRange`
        - FQDN :class:`fortilib.address.FortigateFQDN`
        - General Proxy Address :class:`fortilib.proxyaddress.FortigateProxyAddress`
        - Host Regex :class:`fortilib.proxyaddress.FortigateProxyAddressHostRegex`
        - URL :class:`fortilib.address.FortigateProxyAddressURL`
        """
        addresses: List[Union[FortigateAddress, FortigateProxyAddress]] = (
            self.addresses + self.proxy_addresses
        )
        return addresses

    def create_firewall_proxy_address(self, address: FortigateProxyAddress):
        """Create proxy address on fortigate with given :obj:`fortilib.proxyaddress.FortigateProxyAddress`."""
        status = self.fortigate.create_firewall_proxy_address(
            address.name,
            address.render(),
        )
        self.proxy_addresses.append(address)
        return status

    def update_firewall_proxy_address(self, address: FortigateProxyAddress):
        """Update proxy address on fortigate with given :obj:`fortilib.proxyaddress.FortigateProxyAddress`."""
        return self.fortigate.update_firewall_proxy_address(
            address.name,
            address.render(),
        )

    def delete_firewall_proxy_address(self, address: FortigateProxyAddress):
        """Delete proxy address on fortigate with given :obj:`fortilib.proxyaddress.FortigateProxyAddress`."""
        status = self.fortigate.delete_firewall_proxy_address(address.name)
        self.proxy_addresses.remove(address)
        return status

    def create_firewall_proxy_address_group(
        self, group: FortigateProxyAddressGroup
    ):
        """Create proxy address group on fortigate
        with given :obj:`fortilib.proxyaddressgroup.FortigateProxyAddressGroup`.
        """
        status = self.fortigate.create_firewall_proxy_address_group(
            group.name, group.render()
        )
        self.proxy_address_groups.append(group)
        return status

    def update_firewall_proxy_address_group(
        self, group: FortigateProxyAddressGroup
    ):
        """Update proxy address group on fortigate
        with given :obj:`fortilib.proxyaddressgroup.FortigateProxyAddressGroup`.
        """
        return self.fortigate.update_firewall_proxy_address_group(
            group.name, group.render()
        )

    def delete_firewall_proxy_address_group(
        self, group: FortigateProxyAddressGroup
    ):
        """Delete proxy address group on fortigate
        with given :obj:`fortilib.proxyaddressgroup.FortigateProxyAddressGroup`.
        """
        status = self.fortigate.delete_firewall_proxy_address_group(group.name)
        self.proxy_address_groups.remove(group)
        return status

    def get_proxy_policies(self) -> List[FortigateProxyPolicy]:
        """Query Fortigate API for policies
        :obj:`fortilib.proxypolicy.FortigateProxyPolicy` and create list.
        """
        policies: List[FortigateProxyPolicy] = []
        for raw in self.fortigate.get_firewall_proxy_policies():
            policy = FortigateProxyPolicy.from_dict(raw)

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

    def create_firewall_proxy_policy(self, policy: FortigateProxyPolicy):
        """Create policy on fortigate with given :obj:`fortilib.proxypolicy.FortigateProxyPolicy`."""
        status = self.fortigate.create_firewall_proxy_policies(
            int(policy.policyid), policy.render()
        )

        policy.policyid = status["mkey"]

        self.proxy_policies.append(policy)
        return status

    def update_firewall_proxy_policy(self, policy: FortigateProxyPolicy):
        """Update policy on fortigate with given :obj:`fortilib.proxypolicy.FortigateProxyPolicy`."""
        return self.fortigate.update_firewall_proxy_policies(
            policy.policyid, policy.render()
        )

    def delete_firewall_proxy_policy(self, policy: FortigateProxyPolicy):
        """Delete proxy-policy on fortigate with given :obj:`fortilib.proxypolicy.FortigateProxyPolicy`."""
        status = self.fortigate.delete_firewall_proxy_policies(policy.policyid)
        self.proxy_policies.remove(policy)
        return status

    def get_object_by_name(
        self, name: str, fortigate_objects: List[FortigateNamedObject]
    ) -> FortigateNamedObject:
        for fortigate_object in fortigate_objects:
            if fortigate_object.name == name:
                return fortigate_object

    def get_policy_list_by_destination_name(
        self, address_name: str
    ) -> List[FortigatePolicy]:
        found_policies: List[FortigatePolicy] = []
        for policy in self.policies:
            for destination in policy.dstaddr:
                if address_name == destination.name:
                    found_policies.append(policy)

        return found_policies
