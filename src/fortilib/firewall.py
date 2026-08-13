from typing import TypeVar

import httpx2

from fortilib.base import FortigateObject
from fortilib.interface import FortigateInterface

FortigateObjectT = TypeVar("FortigateObjectT", bound=FortigateObject)


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
    def __init__(
        self,
        url: str,
        vdom: str,
        access_token: str,
        timeout: int = 10,
    ) -> None:
        self.client = httpx2.Client(
            base_url=url,
            timeout=timeout,
            headers={"Authorization": f"Bearer {access_token}"},
            params={"vdom": vdom},
        )

    def __check_response(self, response: httpx2.Response) -> None:
        if not response.is_success:
            raise APIException(response)

    def __get(
        self,
        url: str,
        object_class: type[FortigateObjectT],
    ) -> list[FortigateObjectT]:
        response = self.client.get(url)
        self.__check_response(response)
        data = response.json()
        objects: list[FortigateObjectT] = []
        for item in data.get("results", []):
            obj = object_class(**item)
            objects.append(obj)
        return objects

    def __create(self, url: str, obj: FortigateObject) -> None:
        response = self.client.post(url, json=obj.model_dump())
        self.__check_response(response)

    def get_interfaces(self) -> list[FortigateInterface]:
        return self.__get("/api/v2/cmdb/system/interface", FortigateInterface)
