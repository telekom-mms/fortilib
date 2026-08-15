from typing import ClassVar

from pydantic import BaseModel, ConfigDict


class FortigateObject(BaseModel):
    model_config = ConfigDict(
        serialize_by_alias=True, validate_by_name=True, validate_by_alias=True
    )

    identifier_name: ClassVar[str] = ""

    @property
    def identifier(self) -> str:
        return getattr(self, self.identifier_name)


class FortigateCommentedObject(FortigateObject):
    comment: str = ""


class FortigateNameIdentifiedObject(FortigateObject):
    identifier_name: ClassVar[str] = "name"

    name: str


class FortigateColoredObject(FortigateObject):
    color: int = 0


def identifier_list_serializer(
    obj: list[FortigateObject],
) -> list[dict[int | str, str]]:
    return [{o.identifier_name: o.identifier} for o in obj]
