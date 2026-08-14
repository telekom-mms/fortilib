from pydantic import BaseModel, ConfigDict


class FortigateObject(BaseModel):
    model_config = ConfigDict(
        serialize_by_alias=True, validate_by_name=True, validate_by_alias=True
    )


class FortigateCommentedObject(FortigateObject):
    comment: str = ""


class FortigateNamedObject(FortigateObject):
    name: str


class FortigateColoredObject(FortigateObject):
    color: int = 0
