__version__ = "1.0.4"

from typing import (
    Dict,
    List,
)


class FortilibSettings:
    strict_address_group_member_matching: bool = True


def get_by(attrname, attrvalue, haystack):
    for o in haystack:
        if attrvalue == getattr(o, attrname):
            return o
    return None


def get_fortigate_member_array(source: List, attrname="name") -> List[Dict]:
    ret = []
    for member in sorted(
        source, key=lambda _source: getattr(_source, attrname)
    ):
        ret.append(
            {
                "name": getattr(member, attrname),
            }
        )

    return ret
