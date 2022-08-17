from typing import List

from fortilib import get_by


class FortigateGroupMixin:
    def find_member(self, search_lists: List[List]):
        for member_raw in self.object_data["member"]:
            member = None
            for search_list in search_lists:
                member = get_by("name", member_raw["name"], search_list)
                if member is not None:
                    break

            if member is None:
                raise Exception(
                    f"group member '{member_raw['name']}' "
                    f"of group '{self.name}' not found"
                )

            self.member.append(member)
