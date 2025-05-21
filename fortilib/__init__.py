__version__ = "1.0.12"

from enum import StrEnum
from typing import (
    Dict,
    List,
)


class FortigateTCPUDPServiceProtocol(StrEnum):
    TCP_UDP_SCTP = "TCP/UDP/SCTP"
    TCP_UDP_UDP_Lite_SCTP = "TCP/UDP/UDP-Lite/SCTP"


class FortilibSettings:
    strict_address_group_member_matching: bool = True
    tcp_udp_service_protocol = FortigateTCPUDPServiceProtocol.TCP_UDP_SCTP


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


def remove_empty_dict_values(source: dict):
    return {k: v for k, v in source.items() if v}
