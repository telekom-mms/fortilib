import unittest

from fortilib import get_by
from fortilib.firewall import FortigateFirewall
from tests.integration_tests.settings import settings


class FortigateIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fw = FortigateFirewall(
            url=settings.FORTIGATE_URL,
            vdom=settings.FORTIGATE_VDOM,
            access_token=settings.FORTIGATE_ACCESS_TOKEN,
            verify_tls=False,
        )

        interfaces = cls.fw.get_interfaces()
        cls.port1 = get_by("name", "port1", interfaces)
