__version__ = "0.1.3"

from typing import (
    Dict,
    List,
)


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
