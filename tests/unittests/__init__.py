import unittest

import pytest
import respx

from fortilib.firewall import FortigateFirewall


class FortigateTest(unittest.TestCase):
    httpx2_mock: respx.Router

    @pytest.fixture(autouse=True)
    def _inject_httpx2_mock(self, request, httpx2_mock) -> None:
        if request.instance is not None:
            request.instance.httpx2_mock = httpx2_mock

    def setUp(self):
        self.fw = FortigateFirewall(
            url="https://example.com",
            vdom="root",
            access_token="test-token",
        )
