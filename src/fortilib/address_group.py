from __future__ import annotations

from typing import Annotated

from pydantic import BeforeValidator, PlainSerializer

from fortilib import FortigateMemberNotFoundError, get_by
from fortilib.address import FortigateAddress
from fortilib.base import (
    FortigateColoredObject,
    FortigateCommentedObject,
    FortigateNameIdentifiedObject,
    identifier_list_serializer,
)

type AddressGroupMemberType = FortigateAddress | FortigateAddressGroup


def address_group_member_deserializer(
    members: list[dict[str, str]] | list[AddressGroupMemberType],
) -> list[AddressGroupMemberType]:
    member_list: list[AddressGroupMemberType] = []
    for member in members:
        if isinstance(member, dict):
            if "name" in member:
                member_list.append(FortigateAddress(name=member["name"]))
        else:
            member_list.append(member)

    return member_list


class FortigateAddressGroup(
    FortigateNameIdentifiedObject,
    FortigateCommentedObject,
    FortigateColoredObject,
):
    member: Annotated[
        list[AddressGroupMemberType],
        PlainSerializer(identifier_list_serializer),
        BeforeValidator(address_group_member_deserializer),
    ]

    def resolve_member(
        self, search_list: list[AddressGroupMemberType]
    ) -> None:
        new_members: list[AddressGroupMemberType] = []

        for member in self.member:
            if found := get_by(
                member.identifier_name, member.identifier, search_list
            ):
                new_members.append(found)
            else:
                raise FortigateMemberNotFoundError(
                    f"Address group member {member.identifier} not found"
                )

        self.member = new_members
