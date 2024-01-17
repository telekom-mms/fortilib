from typing import List

from fortilib.address import FortigateAddress
from fortilib.mixins.group import FortigateGroupMixin
from fortilib.mixins.interface import FortigateInterfaceMixin
from fortilib.vip import FortigateVIP


class FortigateVIPGroup(
    FortigateAddress, FortigateInterfaceMixin, FortigateGroupMixin
):
    """Fortigate object for VIP groups.

    :ivar member: Collection of vip objects of :class:`fortilib.vip.FortigateVIP`
    """

    def __init__(self):
        """
        :param member:
        """
        super().__init__()

        self.member: List[FortigateVIP, FortigateVIPGroup] = []

    def populate(self, object_data: dict):
        """Parse raw dict data to vip group object.

        :param object_data: raw dict of firewall object representation
        """
        super().populate(object_data)

        self.comment = object_data.get("comments", self.comment)

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "test_vip_group",
                    "member":
                    {
                        "name": "test_vip",
                    }
                    "interface": "any",
                    "comments": "Test comment",
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
            "interface": self.interface.name if self.interface else "any",
            "comments": self.comment,
            "color": self.color,
        }
