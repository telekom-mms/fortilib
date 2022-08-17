from typing import (
    List,
    Union,
)

from fortilib.address import FortigateAddress
from fortilib.base import FortigateNamedObject


class FortigateProxyAddress(FortigateNamedObject):
    def __init__(self):
        super().__init__()

    def populate(self, object_data: dict):
        super().populate(object_data)


class FortigateProxyAddressHostRegex(FortigateProxyAddress):
    def __init__(self):
        super().__init__()

        self.host_regex: str = None

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.host_regex = object_data["host-regex"]

    def render(self) -> dict:
        return {
            "name": self.name,
            "type": "host-regex",
            "host-regex": self.host_regex,
            "comment": self.comment,
        }


class FortigateProxyAddressURL(FortigateProxyAddress):
    def __init__(self):
        super().__init__()

        self.host: FortigateProxyAddressHostRegex = None
        self.path: str = None

    def populate(self, object_data: dict):
        super().populate(object_data)

        self.path = object_data["path"]

    def render(self) -> dict:
        return {
            "name": self.name,
            "type": "url",
            "host": self.host.name,
            "path": self.path,
            "comment": self.comment,
        }

    def find_host(
        self,
        hosts: List[Union[FortigateAddress, FortigateProxyAddressHostRegex]],
    ):
        for host in hosts:
            if host.name == self.object_data["host"] and isinstance(
                host, FortigateProxyAddressHostRegex
            ):
                self.host = host
                break
