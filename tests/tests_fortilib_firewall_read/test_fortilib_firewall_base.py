from fortilib.base import FortigateObject
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_base_object_no_render_def(self):
        object_ = FortigateObject()

        with self.assertRaises(Exception) as ex:
            object_.render()

        self.assertEqual(str(ex.exception), "not implemented")
