from typing import List

from fortilib.base import FortigateNamedObject
from fortilib.mixins.group import FortigateGroupMixin
from fortilib.service import FortigateService


class FortigateServiceGroup(FortigateNamedObject, FortigateGroupMixin):
    """Fortigate object for service groups.

    :ivar member: Collection of service objects of :class:`fortilib.service.FortigateService`
    """

    def __init__(self):
        super().__init__()

        self.member: List[FortigateService, FortigateServiceGroup] = []

    def populate(self, object_data: dict):
        """Parse raw dict data to service group object.

        :param object_data: raw dict of firewall object representation
        """

        super().populate(object_data)

        self.comment = object_data["comment"]

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        :example:
            .. code-block:: json

                {
                    "name": "HTTP_HTTPS",
                    "member": [
                        {
                            "name": "tcp-443",
                        },
                        {
                            "name": "tcp-80",
                        },
                    ],
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
        }
