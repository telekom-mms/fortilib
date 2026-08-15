import unittest

from fortilib import get_by
from fortilib.firewall import FortigateFirewall
from fortilib.interface import FortigateInterface
from tests.integration_tests.settings import settings


class FortigateIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.fw = FortigateFirewall(
            url=settings.FORTIGATE_URL,
            vdom=settings.FORTIGATE_VDOM,
            access_token=settings.FORTIGATE_ACCESS_TOKEN,
            verify_tls=False,
        )

        interfaces = self.fw.get_interfaces()
        self.port1 = get_by("name", "port1", interfaces)

        self.assertTrue(isinstance(self.port1, FortigateInterface))
