from fortilib.interface import FortigateInterface


class FortigateInterfaceMixin:
    interface_attribute: str = "interface"

    def find_interface(self, interfaces: list[FortigateInterface]):
        if self.object_data.get(self.interface_attribute, "") in ("", "any"):
            return

        for interface in interfaces:
            if interface.name == self.object_data.get(
                self.interface_attribute
            ):
                self.interface = interface
                break
