from typing import List

from fortilib.interface import FortigateInterface


class FortigateInterfaceMixin:
    interface_attribute: str = "interface"

    def find_interface(self, interfaces: List[FortigateInterface]):
        if (
            self.interface_attribute not in self.object_data
            or self.object_data[self.interface_attribute] == ""
            or self.object_data[self.interface_attribute] == "any"
        ):
            return

        for interface in interfaces:
            if interface.name == self.object_data[self.interface_attribute]:
                self.interface = interface
                break
