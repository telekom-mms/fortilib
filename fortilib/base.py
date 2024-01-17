class FortigateObject:
    """Fortigate Base Object for all objects.

    :param object_data: raw dict of firewall object representation
    :param comment: comment of object
    """

    def __init__(self):
        self.object_data: dict = {}
        self.comment: str = ""

    @classmethod
    def from_dict(cls, object_data: dict):
        """Create fortigate class object direct with raw dict of firewall object representation.

        :param object_data: raw dict of firewall object representation
        """
        class_ = cls()
        class_.populate(object_data)

        return class_

    def populate(self, object_data: dict):
        """Parse raw dict data to fortigate base object.

        :param object_data: raw dict of firewall object representation
        """

        self.object_data = object_data
        self.comment = object_data.get("comment", self.comment)

    def render(self) -> dict:
        """Generate dict with all object arguments for fortigate api call.

        .. warning:: Not implemented!

        """
        raise Exception("not implemented")

    def __repr__(self) -> str:
        return str(self.render())


class FortigateNamedObject(FortigateObject):
    """Fortigate Base Named Object extends :class:`fortilib.base.FortigateObject` with a name.

    .. inheritance-diagram:: fortilib.base.FortigateNamedObject
        :top-classes: fortilib.base.FortigateObject

    :param name: name of object
    """

    def __init__(self):
        super().__init__()

        self.name: str = ""

    def populate(self, object_data: dict):
        """Generate dict with all object arguments for fortigate api call."""
        super().populate(object_data)
        self.name = object_data.get("name", self.name)

    def __eq__(self, other):
        if isinstance(other, FortigateNamedObject):
            return self.name == other.name
        return False
