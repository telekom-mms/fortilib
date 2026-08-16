import httpx2

from fortilib.address import (
    FortigateAddress,
    FortigateFQDNAddress,
    FortigateIpMaskAddress,
    FortigateIPRangeAddress,
)
from fortilib.address_group import FortigateAddressGroup
from fortilib.base import FortigateObject
from fortilib.interface import FortigateInterface
from fortilib.ippool import (
    FortigateIPPool,
    FortigateIPPoolOneToOne,
    FortigateIPPoolOverload,
)


class APIException(Exception):
    """Fortigate Base API Exception extends :py:class:`Exception`."""

    def __init__(self, response: httpx2.Response) -> None:
        self.response = response
        super().__init__(self.message())

    def message(self):
        """Return formatted exception message with response code and detailed error description."""
        forti_error_msg: str = self.response.text
        if "cli_error" in forti_error_msg:
            forti_error_msg = self.response.json()["cli_error"]
        return repr(
            f"Response Code: {self.response.status_code} - {forti_error_msg}"
        )


class FortigateFirewall:
    API_URL_ADDRESSES: str = "/api/v2/cmdb/firewall/address"
    API_URL_ADDRESS_GROUPS: str = "/api/v2/cmdb/firewall/addrgrp"
    API_URL_INTERFACES: str = "/api/v2/cmdb/firewall/interface"
    API_URL_IPPOOLS: str = "/api/v2/cmdb/firewall/ippool"

    def __init__(
        self,
        url: str,
        vdom: str,
        access_token: str,
        timeout: int = 10,
        verify_tls: bool = True,
    ) -> None:
        self.client = httpx2.Client(
            base_url=url,
            timeout=timeout,
            headers={"Authorization": f"Bearer {access_token}"},
            params={"vdom": vdom},
            verify=verify_tls,
        )

    def __check_response(self, response: httpx2.Response) -> None:
        if not response.is_success:
            raise APIException(response)

    def __get(
        self,
        url: str,
    ) -> list[dict]:
        response = self.client.get(url)
        self.__check_response(response)
        data = response.json()
        return data.get("results", [])

    def __create(self, url: str, obj: FortigateObject) -> None:
        response = self.client.post(url, json=obj.model_dump())
        self.__check_response(response)

    def __update(self, url: str, obj: FortigateObject) -> None:
        response = self.client.put(
            f"{url}/{obj.identifier}", json=obj.model_dump()
        )
        self.__check_response(response)

    def __delete(self, url: str, obj: FortigateObject) -> None:
        response = self.client.delete(f"{url}/{obj.identifier}")
        self.__check_response(response)

    def get_interfaces(self) -> list[FortigateInterface]:
        results = self.__get("/api/v2/cmdb/system/interface")

        return [FortigateInterface(**result) for result in results]

    def get_addresses(self) -> list[FortigateAddress]:
        addresses: list[FortigateAddress] = []
        for address_dict in self.__get(self.API_URL_ADDRESSES):
            match address_dict.get("type"):
                case "ipmask":
                    address = FortigateIpMaskAddress(**address_dict)
                case "fqdn":
                    address = FortigateFQDNAddress(**address_dict)
                case "iprange":
                    address = FortigateIPRangeAddress(**address_dict)
                case _:
                    address = FortigateAddress(**address_dict)
            addresses.append(address)

        return addresses

    def create_address(self, address: FortigateAddress) -> None:
        self.__create(self.API_URL_ADDRESSES, address)

    def update_address(self, address: FortigateAddress) -> None:
        self.__update(self.API_URL_ADDRESSES, address)

    def delete_address(self, address: FortigateAddress) -> None:
        self.__delete(self.API_URL_ADDRESSES, address)

    def get_address_groups(self) -> list[FortigateAddressGroup]:
        return [
            FortigateAddressGroup(**result)
            for result in self.__get(self.API_URL_ADDRESS_GROUPS)
        ]

    def create_address_group(self, group: FortigateAddressGroup) -> None:
        self.__create(self.API_URL_ADDRESS_GROUPS, group)

    def update_address_group(self, group: FortigateAddressGroup) -> None:
        self.__update(self.API_URL_ADDRESS_GROUPS, group)

    def delete_address_group(self, group: FortigateAddressGroup) -> None:
        self.__delete(self.API_URL_ADDRESS_GROUPS, group)

    def get_ippools(self) -> list[FortigateIPPool]:
        pools: list[FortigateIPPool] = []
        for pool_dict in self.__get(self.API_URL_IPPOOLS):
            match pool_dict.get("type"):
                case "overload":
                    ippool = FortigateIPPoolOverload(**pool_dict)
                case "one-to-one":
                    ippool = FortigateIPPoolOneToOne(**pool_dict)
                case _:
                    ippool = FortigateIPPool(**pool_dict)
            pools.append(ippool)

        return pools

    def create_ippool(self, ippool: FortigateIPPool) -> None:
        self.__create(self.API_URL_IPPOOLS, ippool)

    def update_ippool(self, ippool: FortigateIPPool) -> None:
        self.__update(self.API_URL_IPPOOLS, ippool)

    def delete_ippool(self, ippool: FortigateIPPool) -> None:
        self.__delete(self.API_URL_IPPOOLS, ippool)
