import urllib.parse
from enum import Enum
from typing import (
    Dict,
    List,
    Optional,
    Union,
)

import httpx

from fortilib.exceptions import (
    APIException,
    BadRequestExeption,
    FailedDependencyException,
    ForbiddenException,
    InternalErrorException,
    MethodNotAllowedException,
    NotAuthorizedException,
    ObjectAlreadyExitsException,
    RequestEntityTooLargeException,
    ResourceNotFoundException,
    TooManyRequestsException,
)


class FortiGateApiPolicyDirection(Enum):
    BEFORE = "before"
    AFTER = "after"


class FortigateFirewallApi:
    """Fortigate Firewall API object.

    :ivar ipaddr: IP address of fortigate firewall
    :ivar username: Login User
    :ivar password: Login Password
    :ivar vdom: Set default vdom that is used for all api calls.
    :ivar timeout: Set timeout for api calls. (default: 10)
    """

    def __init__(
        self,
        ipaddr: str,
        vdom: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 10,
        read_only: bool = False,
        access_token: Optional[str] = None,
        port: int = 443,
    ):
        self.ipaddr = ipaddr
        self.username = username
        self.password = password
        self.access_token = access_token
        self.vdom = vdom
        self.timeout = timeout
        self.read_only: bool = read_only
        self.port = port

        self.fortigate: FortiGateApi

    def login(self):
        """Login into Fortigate API via :meth:`fortilib.fortigateapi.FortigateFirewallApi.login`."""
        self.fortigate = FortiGateApi(
            ipaddr=self.ipaddr,
            username=self.username,
            password=self.password,
            access_token=self.access_token,
            vdom=self.vdom,
            timeout=self.timeout,
            read_only=self.read_only,
            port=str(self.port),
        )
        self.fortigate.login()

    def logout(self):
        """Logout from Fortigate API via :meth:`fortilib.fortigateapi.FortigateFirewallApi.logout`."""
        self.fortigate.logout()

    def get_firewall_address(self):
        """Get addresses via Fortigate API"""
        return self.fortigate.get_firewall_address()

    def create_firewall_address(self, address_name: str, address_object: Dict):
        """Create address via Fortigate API

        :param address_name: Name of address on firewall
        :param address_object: Dict representation of address
        """
        return self.fortigate.create_firewall_address(
            address_name, address_object
        )

    def update_firewall_address(self, address_name: str, address_object: Dict):
        """Update address via Fortigate API

        :param address_name: Name of address on firewall
        :param address_object: Dict representation of address
        """
        return self.fortigate.update_firewall_address(
            address_name, address_object
        )

    def delete_firewall_address(self, address_name: str):
        """Delete address via Fortigate API

        :param address_name: Name of address on firewall
        """
        return self.fortigate.delete_firewall_address(address_name)

    def get_firewall_address_group(self):
        """Get address groups via Fortigate API"""
        return self.fortigate.get_address_group()

    def create_firewall_address_group(
        self, group_name: str, group_object: Dict
    ):
        """Create address group via Fortigate API

        :param group_name: Name of address group on firewall
        :param group_object: Dict representation of address group
        """
        return self.fortigate.create_address_group(
            group_name,
            group_object,
        )

    def update_firewall_address_group(
        self, group_name: str, group_object: Dict
    ):
        """Update address group via Fortigate API

        :param group_name: Name of address group on firewall
        :param group_object: Dict representation of address group
        """
        return self.fortigate.update_address_group(
            group_name,
            group_object,
        )

    def delete_firewall_address_group(self, group_name: str):
        """Delete address group via Fortigate API

        :param group_name: Name of address group on firewall
        """
        return self.fortigate.delete_address_group(group_name)

    def get_firewall_vip(self):
        """Get vips via Fortigate API"""
        return self.fortigate.get_firewall_vip()

    def create_firewall_vip(self, vip_name: str, vip_object: Dict):
        """Create vip via Fortigate API

        :param vip_name: Name of vip on firewall
        :param vip_object: Dict representation of vip
        """
        return self.fortigate.create_firewall_vip(vip_name, vip_object)

    def update_firewall_vip(self, vip_name: str, vip_object: Dict):
        """Update vip via Fortigate API

        :param vip_name: Name of vip on firewall
        :param vip_object: Dict representation of vip
        """
        return self.fortigate.update_firewall_vip(vip_name, vip_object)

    def delete_firewall_vip(self, vip_name: str):
        """Delete vip via Fortigate API

        :param vip_name: Name of vip on firewall
        """
        return self.fortigate.delete_firewall_vip(vip_name)

    def get_firewall_vip_group(self):
        """Get vip groups via Fortigate API"""
        return self.fortigate.get_firewall_vip_group()

    def create_firewall_vip_group(
        self, vip_group_name: str, vip_group_object: Dict
    ):
        """Create vip group via Fortigate API

        :param vip_group_name: Name of vip group on firewall
        :param vip_group_object: Dict representation of vip group
        """
        return self.fortigate.create_firewall_vip_group(
            vip_group_name, vip_group_object
        )

    def update_firewall_vip_group(
        self, vip_group_name: str, vip_group_object: Dict
    ):
        """Update vip group via Fortigate API

        :param vip_group_name: Name of vip group on firewall
        :param vip_group_object: Dict representation of vip group
        """
        return self.fortigate.update_firewall_vip_group(
            vip_group_name, vip_group_object
        )

    def delete_firewall_vip_group(self, vip_group_name: str):
        """Delete vip group via Fortigate API

        :param vip_group_name: Name of vip group on firewall
        :param vip_group_object: Dict representation of vip group
        """
        return self.fortigate.delete_firewall_vip_group(vip_group_name)

    def get_firewall_interface(self):
        """Get interfaces via Fortigate API"""
        return self.fortigate.get_firewall_interface()

    def get_firewall_route_static(self):
        """Get static routes via Fortigate API"""
        return self.fortigate.get_firewall_route_static()

    def create_firewall_route_static(self, seq_num: str, route_object: Dict):
        """Create static route via Fortigate API

        :param seq_num: Sequence number of static route on firewall
        :param route_object: Dict representation of static route
        """
        return self.fortigate.create_firewall_route_static(
            seq_num, route_object
        )

    def update_firewall_route_static(self, seq_num: str, route_object: Dict):
        """Update static route via Fortigate API

        :param seq_num: Sequence number of static route on firewall
        :param route_object: Dict representation of static route
        """
        return self.fortigate.update_firewall_route_static(
            seq_num, route_object
        )

    def delete_firewall_route_static(self, seq_num: str):
        """Delete static route via Fortigate API

        :param seq_num: Sequence number of static route on firewall
        """
        return self.fortigate.delete_firewall_route_static(seq_num)

    def get_firewall_service(self):
        """Get services via Fortigate API"""
        return self.fortigate.get_firewall_service()

    def create_firewall_service(self, service_name: str, service_object: Dict):
        """Create service via Fortigate API

        :param service_name: Name of service on firewall
        :param service_object: Dict representation of service
        """
        return self.fortigate.create_firewall_service(
            service_name, service_object
        )

    def update_firewall_service(self, service_name: str, service_object: Dict):
        """Update service via Fortigate API

        :param service_name: Name of service on firewall
        :param service_object: Dict representation of service
        """
        return self.fortigate.update_firewall_service(
            service_name, service_object
        )

    def delete_firewall_service(self, service_name: str):
        """Delete service via Fortigate API

        :param service_name: Name of service on firewall
        """
        return self.fortigate.delete_firewall_service(service_name)

    def create_firewall_service_group(
        self, group_name: str, group_object: Dict
    ):
        """Create service group via Fortigate API

        :param group_name: Name of service group on firewall
        :param group_object: Dict representation of service group
        """
        return self.fortigate.create_service_group(group_name, group_object)

    def update_firewall_service_group(
        self, group_name: str, group_object: Dict
    ):
        """Update service group via Fortigate API

        :param group_name: Name of service group on firewall
        :param group_object: Dict representation of service group
        """
        return self.fortigate.update_service_group(group_name, group_object)

    def delete_firewall_service_group(self, group_name: str):
        """Delete service group via Fortigate API

        :param group_name: Name of service group on firewall
        """
        return self.fortigate.delete_service_group(group_name)

    def get_firewall_service_groups(self):
        """Get service groups via Fortigate API"""
        return self.fortigate.get_service_group()

    def get_firewall_ippool(self):
        """Get ip pools via Fortigate API"""
        return self.fortigate.get_firewall_ippool()

    def create_firewall_ippool(self, pool_name: str, pool_object: Dict):
        """Create ip pool via Fortigate API

        :param pool_name: Name of ip pool on firewall
        :param pool_object: Dict representation of ip pool
        """
        return self.fortigate.create_firewall_ippool(pool_name, pool_object)

    def update_firewall_ippool(self, pool_name: str, pool_object: Dict):
        """Update ip pool via Fortigate API

        :param pool_name: Name of ip pool on firewall
        :param pool_object: Dict representation of ip pool
        """
        return self.fortigate.update_firewall_ippool(pool_name, pool_object)

    def delete_firewall_ippool(self, pool_name: str):
        """Delete ip pool via Fortigate API

        :param pool_name: Name of ip pool on firewall
        """
        return self.fortigate.delete_firewall_ippool(pool_name)

    def get_firewall_policies(self):
        """Get policies via Fortigate API"""
        return self.fortigate.get_firewall_policy()

    def create_firewall_policy(self, policy_id: int, policy_object: Dict):
        """Create policy via Fortigate API

        :param policy_id: Name of policy on firewall
        :param policy_object: Dict representation of policy
        """
        return self.fortigate.create_firewall_policy(
            str(policy_id), policy_object
        )

    def update_firewall_policy(self, policy_id: int, policy_object: Dict):
        """Update policy via Fortigate API

        :param policy_id: Name of policy on firewall
        :param policy_object: Dict representation of policy
        """
        return self.fortigate.update_firewall_policy(
            str(policy_id), policy_object
        )

    def move_firewall_policy(
        self,
        policy_id: int,
        move_direction: FortiGateApiPolicyDirection,
        move_identifier: int,
    ):
        """Update position of policy via Fortigate API

        :param policy_id: ID of policy on firewall
        :param move_direction: direction after or before another policy
        :param move_identifier: ID of policy on firewall, where policy should move before or after
        """

        return self.fortigate.move_firewall_policy(
            str(policy_id),
            move_direction,
            str(move_identifier),
        )

    def move_firewall_proxy_policy(
        self,
        proxy_policy_id: int,
        move_direction: FortiGateApiPolicyDirection,
        move_identifier: int,
    ):
        """Update position of proxy-policy via Fortigate API

        :param proxy_policy_id: ID of proxy-policy on firewall
        :param move_direction: direction after or before another policy
        :param move_identifier: ID of policy on firewall, where policy schulde move before or after
        """

        return self.fortigate.move_firewall_proxy_policy(
            str(proxy_policy_id),
            move_direction,
            str(move_identifier),
        )

    def delete_firewall_policy(self, policy_id: int):
        """Delete policy via Fortigate API

        :param policy_id: Name of policy on firewall
        """
        return self.fortigate.delete_firewall_policy(str(policy_id))

    def get_firewall_proxy_address(self):
        """Get proxy addresses via Fortigate API"""
        return self.fortigate.get_firewall_proxy_address()

    def create_firewall_proxy_address(
        self, address_name: str, address_object: Dict
    ):
        """Create proxy address via Fortigate API

        :param address_name: Name of proxy address on firewall
        :param address_object: Dict representation of proxy address
        """
        return self.fortigate.create_firewall_proxy_address(
            address_name, address_object
        )

    def update_firewall_proxy_address(
        self, address_name: str, address_object: Dict
    ):
        """Update proxy address via Fortigate API

        :param address_name: Name of proxy address on firewall
        :param address_object: Dict representation of proxy address
        """
        return self.fortigate.update_firewall_proxy_address(
            address_name, address_object
        )

    def delete_firewall_proxy_address(self, address_name: str):
        """Delete proxy address via Fortigate API

        :param address_name: Name of proxy address on firewall
        """
        return self.fortigate.delete_firewall_proxy_address(address_name)

    def get_firewall_proxy_policies(self):
        """Get proxy policies via Fortigate API"""
        return self.fortigate.get_firewall_proxy_policy()

    def get_firewall_proxy_address_group(self):
        """Get proxy address groups via Fortigate API"""
        return self.fortigate.get_firewall_proxy_address_group()

    def create_firewall_proxy_address_group(
        self, group_name: str, group_object: Dict
    ):
        """Create proxy address group via Fortigate API

        :param group_name: Name of address group on firewall
        :param group_object: Dict representation of address group
        """
        return self.fortigate.create_proxy_address_group(
            group_name,
            group_object,
        )

    def update_firewall_proxy_address_group(
        self, group_name: str, group_object: Dict
    ):
        """Update proxy address group via Fortigate API

        :param group_name: Name of address group on firewall
        :param group_object: Dict representation of address group
        """
        return self.fortigate.update_proxy_address_group(
            group_name,
            group_object,
        )

    def delete_firewall_proxy_address_group(self, group_name: str):
        """Delete proxy address group via Fortigate API

        :param group_name: Name of proxy address group on firewall
        """
        return self.fortigate.delete_proxy_address_group(group_name)

    def create_firewall_proxy_policies(
        self, policy_id: int, proxy_policy_object: Dict
    ):
        """Create proxy policy via Fortigate API

        :param policy_id: Name of proxy policy on firewall
        :param proxy_policy_object: Dict representation of proxy policy
        """
        return self.fortigate.create_firewall_proxy_policy(
            str(policy_id), proxy_policy_object
        )

    def update_firewall_proxy_policies(
        self, policy_id: int, proxy_policy_object: Dict
    ):
        """Update policy via Fortigate API

        :param policy_id: Name of proxy policy on firewall
        :param proxy_policy_object: Dict representation of proxy policy
        """
        return self.fortigate.update_firewall_proxy_policy(
            str(policy_id), proxy_policy_object
        )

    def delete_firewall_proxy_policies(self, policy_id: int):
        """Delete proxy policy via Fortigate API

        :param policy_id: Name of proxy policy on firewall
        """
        return self.fortigate.delete_firewall_proxy_policy(str(policy_id))


class FortiGateQueryType(Enum):
    GET = 1
    PUT = 2
    POST = 3
    DELETE = 4


class FortiGateOperation:
    def __init__(
        self,
        url: str,
        query_type: FortiGateQueryType,
        identifier: str,
        data: Dict,
    ):
        self.url: str = url
        self.query_type: FortiGateQueryType = query_type
        self.identifier: str = identifier
        self.data: Dict = data

    def __repr__(self):
        return (
            f"{self.query_type.name} {self.url} {self.identifier} {self.data}"
        )


class FortiGateApi:
    ENDPOINT_FIREWALL_INTERFACE = "api/v2/cmdb/system/interface/"
    ENDPOINT_FIREWALL_IPPOOL = "api/v2/cmdb/firewall/ippool/"
    ENDPOINT_FIREWALL_VIP = "api/v2/cmdb/firewall/vip/"
    ENDPOINT_FIREWALL_VIP_GROUP = "api/v2/cmdb/firewall/vipgrp/"
    ENDPOINT_FIREWALL_POLICY = "api/v2/cmdb/firewall/policy/"
    ENDPOINT_FIREWALL_ADDRESS = "api/v2/cmdb/firewall/address/"
    ENDPOINT_FIREWALL_ADDRESS_GROUP = "api/v2/cmdb/firewall/addrgrp/"
    ENDPOINT_FIREWALL_SERVICE = "api/v2/cmdb/firewall.service/custom/"
    ENDPOINT_FIREWALL_SERVICE_GROUP = "api/v2/cmdb/firewall.service/group/"
    ENDPOINT_IPSEC_VPN = "api/v2/cmdb/vpn.ipsec/"
    ENDPOINT_IPSEC_VPN_MONITOR = "api/v2/monitor/vpn/ipsec/"
    ENDPOINT_STATIC_ROUTE = "api/v2/cmdb/router/static/"
    ENDPOINT_FIREWALL_PROXY_ADDRESS = "api/v2/cmdb/firewall/proxy-address/"
    ENDPOINT_FIREWALL_PROXY_ADDRESS_GROUP = (
        "api/v2/cmdb/firewall/proxy-addrgrp/"
    )
    ENDPOINT_FIREWALL_PROXY_POLICY = "api/v2/cmdb/firewall/proxy-policy/"

    def __init__(
        self,
        ipaddr: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        access_token: Optional[str] = None,
        timeout: int = 10,
        vdom: str = "root",
        port: str = "443",
        read_only: bool = False,
    ):
        if not any([username, password, access_token]):
            raise InternalErrorException("No Login Method given!")

        self.ipaddr: str = ipaddr
        self.username: str = username
        self.password: str = password
        self.access_token: str = access_token
        self.port: str = port
        self.urlbase: str = f"https://{self.ipaddr}:{self.port}/"
        self.timeout: int = timeout
        self.vdom: str = vdom
        self.read_only: bool = read_only

        self.client: httpx.Client = None
        self.operations: List[FortiGateOperation] = []

    def login(self):
        """Login via Username or Access Token.
        Get CSRF Token and use it for active session.
        """
        self.client = httpx.Client(verify=False, timeout=self.timeout)

        # access token? then use is
        if self.access_token:
            self.login_with_access_token()
        else:  # no token? then use username and password login
            self.login_with_username()

        # Check whether login was successful
        login_check = self.client.get(self.urlbase + "api/v2/cmdb/system/vdom")
        self.check_response_code(login_check)

    def login_with_username(self):
        """Login via Fortigate API.
        Get CSRF Token and use it for active session.
        """
        url = self.urlbase + "logincheck"
        response = self.client.post(
            url,
            data={"username": self.username, "secretkey": self.password},
        )

        self.check_response_code(response)

        # Get CSRF token from cookies, add to headers
        if "ccsrftoken" in response.cookies:
            csrftoken = response.cookies["ccsrftoken"][1:-1]
            self.client.headers.update({"X-CSRFTOKEN": csrftoken})

    def login_with_access_token(self):
        self.client.headers.update(
            {"Authorization": f"Bearer {self.access_token}"}
        )

    def logout(self):
        """Logout via Fortigate API.
        Logout the active session.
        """

        if not self.access_token:
            url = self.urlbase + "logout"
            self.client.get(url)

    def does_exist(self, object_url: str) -> bool:
        response = self.client.get(
            object_url,
            params=f"vdom={self.vdom}",
        )
        if response.status_code == 200:
            return True
        return False

    def get(self, url):
        return self.client.get(
            url,
            params=f"vdom={self.vdom}",
        )

    def put(self, url, data: Dict):
        return self.client.put(
            url,
            json=data,
            params=f"vdom={self.vdom}",
        )

    def post(self, url, data: Dict):
        return self.client.post(
            url,
            json=data,
            params=f"vdom={self.vdom}",
        )

    def delete(self, url):
        return self.client.delete(
            url,
            params=f"vdom={self.vdom}",
        )

    def check_response_code(self, response: httpx.Response):
        if response.status_code == 200:
            return
        elif response.status_code >= 300 and response.status_code < 400:
            return
        elif response.status_code == 400:
            raise BadRequestExeption(response)
        elif response.status_code == 401:
            raise NotAuthorizedException(response)
        elif response.status_code == 403:
            raise ForbiddenException(response)
        elif response.status_code == 404:
            raise ResourceNotFoundException(response)
        elif response.status_code == 405:
            raise MethodNotAllowedException(response)
        elif response.status_code == 413:
            raise RequestEntityTooLargeException(response)
        elif response.status_code == 424:
            raise FailedDependencyException(response)
        elif response.status_code == 429:
            raise TooManyRequestsException(response)
        elif response.status_code == 500:
            raise InternalErrorException(response)
        else:
            raise APIException(response)

    def query_api_get(
        self, uri: str, specific=False, filters=False
    ) -> Union[dict, int]:
        api_url = self.urlbase + uri
        if specific:
            api_url += specific
        if filters:
            api_url += "?filter=" + filters

        self.operations.append(
            FortiGateOperation(api_url, FortiGateQueryType.GET, "", "")
        )

        result = self.get(api_url)
        self.check_response_code(result)
        return result.json()["results"]

    def query_api_create(
        self, uri: str, identifier: str, data: Dict
    ) -> Union[dict, int]:
        api_url = self.urlbase + uri
        if self.does_exist(api_url + identifier):
            raise ObjectAlreadyExitsException(
                f"object {identifier} " f"already exists"
            )

        self.operations.append(
            FortiGateOperation(
                api_url, FortiGateQueryType.POST, identifier, data
            )
        )
        if self.read_only:
            return {}
        result = self.post(api_url, data)
        self.check_response_code(result)
        return result.json()

    def query_api_update(
        self,
        uri: str,
        identifier: str,
        data: Dict,
    ) -> Union[dict, int]:
        api_url = self.urlbase + uri
        self.operations.append(
            FortiGateOperation(
                api_url, FortiGateQueryType.PUT, identifier, data
            )
        )

        if self.read_only:
            return {}

        result = self.put(f"{api_url}/{identifier}", data)
        self.check_response_code(result)
        return result.json()

    def query_api_move(
        self,
        uri: str,
        identifier: str,
        move_direction: FortiGateApiPolicyDirection = None,
        move_identifier: str = None,
    ) -> Union[dict, int]:
        api_url = self.urlbase + uri
        move_url = f"{api_url}/{identifier}?action=move&{move_direction.value}={move_identifier}"
        self.operations.append(
            FortiGateOperation(
                move_url, FortiGateQueryType.PUT, identifier, ""
            )
        )

        if self.read_only:
            return {}

        result = self.put(
            move_url,
            None,
        )
        self.check_response_code(result)
        return result.json()

    def query_api_delete(self, uri: str, identifier: str) -> Union[dict, int]:
        api_url = self.urlbase + uri

        self.operations.append(
            FortiGateOperation(
                api_url, FortiGateQueryType.DELETE, identifier, ""
            )
        )

        if self.read_only:
            return {}

        result = self.delete(f"{api_url}/{identifier}")
        self.check_response_code(result)
        return result.json()

    # Firewall Route Methods
    def get_firewall_route_static(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_STATIC_ROUTE, specific, filters
        )

    def create_firewall_route_static(self, seq_num: str, data: Dict):
        return self.query_api_create(
            FortiGateApi.ENDPOINT_STATIC_ROUTE, seq_num, data
        )

    def update_firewall_route_static(self, seq_num: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_STATIC_ROUTE, seq_num, data
        )

    def delete_firewall_route_static(self, seq_num: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_STATIC_ROUTE, seq_num
        )

    # Firewall Interface Methods
    def get_firewall_interface(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_INTERFACE, specific, filters
        )

    def get_ipsec_vpn(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_IPSEC_VPN, specific, filters
        )

    # Firewall Address Methods
    def get_ipsec_vpn_monitor(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_IPSEC_VPN_MONITOR, specific, filters
        )

    def get_firewall_vip(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_VIP, specific, filters
        )

    def get_firewall_vip_group(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_VIP_GROUP, specific, filters
        )

    def get_firewall_ippool(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_IPPOOL, specific, filters
        )

    def get_firewall_policy(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_POLICY, specific, filters
        )

    def get_firewall_address(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_ADDRESS, specific, filters
        )

    def get_address_group(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_ADDRESS_GROUP, specific, filters
        )

    def get_firewall_service(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_SERVICE, specific, filters
        )

    def get_service_group(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_SERVICE_GROUP, specific, filters
        )

    def get_firewall_proxy_address(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_ADDRESS, specific, filters
        )

    def get_firewall_proxy_address_group(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_ADDRESS_GROUP,
            specific,
            filters,
        )

    def get_firewall_proxy_policy(self, specific=False, filters=False):
        return self.query_api_get(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_POLICY, specific, filters
        )

    def create_firewall_ippool(self, pool_name: str, data: Dict):
        """Query Fortigate API to create ip pool.

        :param pool_name: Name of ip pool
        :param data: JSON object representation
        """
        return self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_IPPOOL, pool_name, data
        )

    def update_firewall_ippool(self, pool_name: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_IPPOOL, pool_name, data
        )

    def delete_firewall_ippool(self, pool_name: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_IPPOOL, pool_name
        )

    def create_firewall_vip(self, vip_name: str, data: Dict):
        return self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_VIP, vip_name, data
        )

    def update_firewall_vip(self, vip_name: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_VIP, vip_name, data
        )

    def delete_firewall_vip(self, vip_name: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_VIP, vip_name
        )

    def create_firewall_vip_group(self, vip_group_name: str, data: Dict):
        return self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_VIP_GROUP, vip_group_name, data
        )

    def update_firewall_vip_group(self, vip_group_name: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_VIP_GROUP, vip_group_name, data
        )

    def delete_firewall_vip_group(self, vip_group_name: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_VIP_GROUP, vip_group_name
        )

    def create_firewall_address(self, address_name: str, data: Dict):
        return self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_ADDRESS, address_name, data
        )

    def update_firewall_address(self, address_name: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_ADDRESS, address_name, data
        )

    def delete_firewall_address(self, address_name: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_ADDRESS, address_name
        )

    def create_address_group(self, group_name: str, data: Dict):
        return self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_ADDRESS_GROUP, group_name, data
        )

    def update_address_group(self, group_name: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_ADDRESS_GROUP, group_name, data
        )

    def delete_address_group(self, group_name: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_ADDRESS_GROUP, group_name
        )

    def create_firewall_service(self, service_name: str, data: Dict):
        return self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_SERVICE, service_name, data
        )

    def update_firewall_service(self, service_name: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_SERVICE, service_name, data
        )

    def delete_firewall_service(self, service_name: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_SERVICE, service_name
        )

    def create_service_group(self, group_name: str, data: Dict):
        return self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_SERVICE_GROUP, group_name, data
        )

    def update_service_group(self, group_name: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_SERVICE_GROUP, group_name, data
        )

    def delete_service_group(self, group_name: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_SERVICE_GROUP, group_name
        )

    def create_firewall_policy(self, policy_id: str, data: Dict):
        ret = self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_POLICY, policy_id, data
        )
        if self.read_only:
            return {"mkey": "99999999"}

        return ret

    def update_firewall_policy(self, policy_id: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_POLICY, policy_id, data
        )

    def move_firewall_policy(
        self,
        policy_id: str,
        move_direction: FortiGateApiPolicyDirection,
        move_identifier: str,
    ):
        return self.query_api_move(
            FortiGateApi.ENDPOINT_FIREWALL_POLICY,
            policy_id,
            move_direction,
            move_identifier,
        )

    def move_firewall_proxy_policy(
        self,
        proxy_policy_id: str,
        move_direction: FortiGateApiPolicyDirection,
        move_identifier: str,
    ):
        return self.query_api_move(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_POLICY,
            proxy_policy_id,
            move_direction,
            move_identifier,
        )

    def delete_firewall_policy(self, policy_id: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_POLICY, policy_id
        )

    def create_firewall_proxy_address(self, address_name: str, data: Dict):
        return self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_ADDRESS, address_name, data
        )

    def update_firewall_proxy_address(self, address_name: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_ADDRESS,
            urllib.parse.quote_plus(address_name),
            data,
        )

    def delete_firewall_proxy_address(self, address_name: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_ADDRESS,
            urllib.parse.quote_plus(address_name),
        )

    def create_firewall_proxy_policy(self, policy_id: str, data: Dict):
        ret = self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_POLICY, policy_id, data
        )
        if self.read_only:
            return {"mkey": "99999999"}

        return ret

    def update_firewall_proxy_policy(self, policy_id: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_POLICY, policy_id, data
        )

    def delete_firewall_proxy_policy(self, policy_id: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_POLICY, policy_id
        )

    def create_proxy_address_group(self, group_name: str, data: Dict):
        return self.query_api_create(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_ADDRESS_GROUP,
            group_name,
            data,
        )

    def update_proxy_address_group(self, group_name: str, data: Dict):
        return self.query_api_update(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_ADDRESS_GROUP,
            group_name,
            data,
        )

    def delete_proxy_address_group(self, group_name: str):
        return self.query_api_delete(
            FortiGateApi.ENDPOINT_FIREWALL_PROXY_ADDRESS_GROUP, group_name
        )

    def get_write_operations(self):
        filtered: List[FortiGateOperation] = []
        for operation in self.operations:
            if operation.query_type != FortiGateQueryType.GET:
                filtered.append(operation)

        return filtered
