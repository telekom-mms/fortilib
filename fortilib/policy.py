from enum import Enum
from typing import (
    Dict,
    List,
    Union,
)

from fortilib import (
    get_by,
    get_fortigate_member_array,
)
from fortilib.address import FortigateAddress
from fortilib.base import FortigateNamedObject
from fortilib.exceptions import (
    AddressTypeMismatchException,
    InterfaceMismatchException,
)
from fortilib.interface import FortigateInterface
from fortilib.ippool import FortigateIPPool
from fortilib.service import FortigateService
from fortilib.servicegroup import FortigateServiceGroup
from fortilib.vip import FortigateVIP
from fortilib.vipgroup import FortigateVIPGroup


class FortigatePolicyAction(Enum):
    ACCEPT = "accept"
    DENY = "deny"


class FortigatePolicyLogTraffic(Enum):
    DISABLE = "disable"
    UTM = "utm"
    ALL = "all"


class FortigatePolicy(FortigateNamedObject):
    def __init__(self):
        super().__init__()

        self.policyid: int = 0
        self.action: FortigatePolicyAction = FortigatePolicyAction.ACCEPT

        self.srcintf: List[FortigateInterface] = []
        self.dstintf: List[FortigateInterface] = []

        self.srcaddr: List[FortigateAddress] = []
        self.dstaddr: List[FortigateAddress] = []

        self.service: List[FortigateService] = []

        self.nat: str = "disable"
        self.ippool: str = "disable"
        self.poolname: List[FortigateIPPool] = []
        self.schedule: str = "always"
        self.logtraffic: FortigatePolicyLogTraffic = (
            FortigatePolicyLogTraffic.ALL
        )

    def __eq__(self, other):
        if isinstance(other, FortigatePolicy):
            return (
                self.policyid == other.policyid
                and self.name == other.name
                and self.srcintf == other.srcintf
                and self.dstintf == other.dstintf
                and self.srcaddr == other.srcaddr
                and self.dstaddr == other.dstaddr
                and self.service == other.service
            )

        return False

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.policyid = object_data["policyid"]
        self.action = FortigatePolicyAction[object_data["action"].upper()]
        self.nat = object_data["nat"]
        self.ippool = object_data["ippool"]

        self.schedule = object_data["schedule"]

        if "logtraffic" in object_data:
            self.logtraffic = FortigatePolicyLogTraffic[
                object_data["logtraffic"].upper()
            ]

        self.comment = object_data["comments"]

    def find_interfaces(self, interfaces: List[FortigateInterface]):
        self.srcintf = self.find_interface_for(
            self.object_data["srcintf"],
            interfaces,
        )
        self.dstintf = self.find_interface_for(
            self.object_data["dstintf"],
            interfaces,
        )

    @staticmethod
    def find_interface_for(
        interface_arr: List[Dict],
        all_interfaces: List[FortigateInterface],
    ) -> List[FortigateInterface]:
        interfaces: List[FortigateInterface] = []
        for interface_dict in interface_arr:
            interface = get_by("name", interface_dict["name"], all_interfaces)
            if interface is None:
                raise Exception(
                    f"no interface found "
                    f"with name {interface_dict['name']}"
                )
            interfaces.append(interface)

        return interfaces

    def find_addresses(self, addresses: List[List[FortigateAddress]]):
        self.srcaddr = self.find_addresses_for(
            self.object_data["srcaddr"],
            addresses,
        )
        self.dstaddr = self.find_addresses_for(
            self.object_data["dstaddr"],
            addresses,
        )

    @staticmethod
    def find_addresses_for(
        address_arr: List[Dict], all_addresses: List[List[FortigateAddress]]
    ) -> List[FortigateAddress]:
        addresses: List[FortigateAddress] = []
        for address_dict in address_arr:
            address = None
            for search_list in all_addresses:
                address = get_by("name", address_dict["name"], search_list)
                if address is not None:
                    break

            if address is None:
                raise Exception(
                    f"address (or vip or group) "
                    f"{address_dict['name']} not found"
                )

            addresses.append(address)

        return addresses

    def find_services(
        self,
        all_services: List[
            Union[List[FortigateService], List[FortigateServiceGroup]]
        ],
    ):
        for service_dict in self.object_data["service"]:
            service = None
            for search_list in all_services:
                service = get_by("name", service_dict["name"], search_list)
                if service is not None:
                    break
            if service is None:
                raise Exception(
                    f"service with name {service_dict['name']} not found"
                )

            self.service.append(service)

    def find_ippools(self, all_ippools: List[FortigateIPPool]):
        for ippool_dict in self.object_data["poolname"]:
            ippool = get_by("name", ippool_dict["name"], all_ippools)
            if ippool is None:
                raise Exception(
                    f"ippool with name {ippool_dict['name']} " f"not found"
                )

            self.poolname.append(ippool)

    def add_source_interface(self, interface: FortigateInterface):
        if self.check_addresses_interface(interface, self.srcaddr):
            self.srcintf.append(interface)

    def add_destination_interface(self, interface: FortigateInterface):
        if self.check_addresses_interface(interface, self.dstaddr):
            self.dstintf.append(interface)

    def check_addresses_interface(
        self, interface: FortigateInterface, addresses: List[FortigateAddress]
    ) -> bool:
        for address in addresses:
            if address.interface and address.interface != interface:
                raise InterfaceMismatchException(
                    f"""
                    inteface mismatch between interface {interface.name} and
                     {address.name} ({address.interface.name}) in
                     policy {self.policyid} {self.name}
                """
                )
        return True

    def remove_source_interface(self, interface: FortigateInterface):
        self.srcintf.remove(interface)

    def remove_destination_interface(self, interface: FortigateInterface):
        self.dstintf.remove(interface)

    def add_source_address(self, address: FortigateAddress):
        if self.check_interface_address(
            address, self.srcintf
        ) and self.check_address_type(address, self.srcaddr):
            self.srcaddr.append(address)

    def add_destination_address(self, address: FortigateAddress):
        if self.check_interface_address(
            address, self.dstintf
        ) and self.check_address_type(address, self.dstaddr):
            self.dstaddr.append(address)

    def check_interface_address(
        self, address: FortigateAddress, interfaces: List[FortigateInterface]
    ) -> bool:
        # policy hat mehr als 1 interface, aber addressobject hat ein interface
        # fest gesetzt
        if address.interface and len(interfaces) > 1:
            raise InterfaceMismatchException(
                f"""
            only interface any is allowed on address {address.name} because
            policy {self.policyid} {self.name} has multiple interfaces
            """
            )

        # ein interface, weicht das von dem von der addresse ab?
        if address.interface and len(interfaces) == 1:
            for interface in interfaces:
                if interface != address.interface:
                    raise InterfaceMismatchException(
                        f"""
                    inteface mismatch between interface {interface.name} and
                    {address.name} ({address.interface.name}) in
                    policy {self.policyid} {self.name}
                    """
                    )
        return True

    def check_address_type(
        self,
        address: FortigateAddress,
        existing_addresses: List[FortigateAddress],
    ) -> bool:

        # bisher keine addressen? dann ists ok
        if len(existing_addresses) < 1:
            return True

        vip_tuple = (FortigateVIP, FortigateVIPGroup)

        if (
            isinstance(address, vip_tuple)
            and not isinstance(existing_addresses[0], vip_tuple)
        ) or (
            not isinstance(address, vip_tuple)
            and isinstance(existing_addresses[0], vip_tuple)
        ):
            raise AddressTypeMismatchException(
                f"addresses and address groups"
                f" can not be mixed with vip "
                f"and vip groups in policy "
                f"{self.policyid} {self.name}"
            )

        return True

    def remove_source_address(self, address: FortigateAddress):
        self.srcaddr.remove(address)

    def remove_destination_address(self, address: FortigateAddress):
        self.dstaddr.remove(address)

    def render(self) -> dict:
        return {
            "policyid": self.policyid,
            "name": self.name,
            "action": self.action.value,
            "nat": self.nat,
            "ippool": self.ippool,
            "srcintf": get_fortigate_member_array(self.srcintf),
            "dstintf": get_fortigate_member_array(self.dstintf),
            "srcaddr": get_fortigate_member_array(self.srcaddr),
            "dstaddr": get_fortigate_member_array(self.dstaddr),
            "service": get_fortigate_member_array(self.service),
            "poolname": get_fortigate_member_array(self.poolname),
            "schedule": self.schedule,
            "logtraffic": self.logtraffic.value,
            "comments": self.comment,
        }
