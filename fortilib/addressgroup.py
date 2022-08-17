from typing import List

from fortilib.address import FortigateAddress
from fortilib.mixins.group import FortigateGroupMixin


class FortigateAddressGroup(FortigateAddress, FortigateGroupMixin):
    """Fortigate object for address groups.

    :ivar member: Collection of address objects of :class:`fortilib.address.FortigateAddress`
    """

    def __init__(self):
        super().__init__()

        self.member: List[FortigateAddress, FortigateAddressGroup] = []

    # TODO mabye not need because super-element FortigateNamedObject implements it already -> delete?!
    def populate(self, object_data: dict):
        super().populate(object_data)

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "Test_address_group",
                    "member":
                    {
                        "name": "Test_address",
                    },
                    "comment": "Test comment",
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
            "color": self.color,
        }
