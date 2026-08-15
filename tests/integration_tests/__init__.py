import unittest

from fortilib.firewall import FortigateFirewall
from tests.integration_tests.settings import settings


class FortigateIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.fw = FortigateFirewall(
            url=settings.FORTIGATE_URL,
            vdom=settings.FORTIGATE_VDOM,
            access_token=settings.FORTIGATE_ACCESS_TOKEN,
            verify_tls=False,
        )
