from typing import List

from fortilib.mixins.group import FortigateGroupMixin
from fortilib.proxyaddress import FortigateProxyAddress


# todo: integration tests
class FortigateProxyAddressGroup(FortigateProxyAddress, FortigateGroupMixin):
    """Fortigate object for proxy address groups.

    :ivar member: Collection of proxy address objects of :class:`fortilib.proxyaddress.FortigateProxyAddress`
                    or :class:`fortilib.proxyaddressgroup.FortigateProxyAddressGroup`
    """

    def __init__(self):
        super().__init__()

        self.member: List[
            FortigateProxyAddress, FortigateProxyAddressGroup
        ] = []
        self.type: str = "dst"

    # TODO mabye not needed because super-element FortigateNamedObject implements it already -> delete?!
    def populate(self, object_data: dict):
        super().populate(object_data)
        self.type = object_data["type"]

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "Test_proxy_address_group",
                    "member":
                    {
                        "name": "Test_proxy_address",
                    },
                    "comment": "Test comment",
                    "type": "dst",
                }
        """

        members = []
        for member in sorted(self.member, key=lambda _member: _member.name):
            members.append(
                {
                    "name": member.name,
                }
            )
        return {
            "name": self.name,
            "member": members,
            "comment": self.comment,
            "type": self.type,
        }
