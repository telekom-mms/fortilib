import pytest

from fortilib.firewall import APIException
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    @pytest.mark.httpx2(base_url="https://example.com")
    def test_api_exception_plaintext(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/system/interface",
            params={"vdom": "root"},
        ).respond(
            text="Fortigate Error Message",
            status_code=500,
        )

        with self.assertRaises(APIException) as context:
            self.fw.get_interfaces()

        self.assertEqual(
            "'Response Code: 500 - Fortigate Error Message'",
            context.exception.message(),
        )

    @pytest.mark.httpx2(base_url="https://example.com")
    def test_api_exception_json(self) -> None:
        self.httpx2_mock.get(
            "/api/v2/cmdb/system/interface",
            params={"vdom": "root"},
        ).respond(
            json={"cli_error": "Fortigate Error Message"},
            status_code=500,
        )

        with self.assertRaises(APIException) as context:
            self.fw.get_interfaces()

        self.assertEqual(
            "'Response Code: 500 - Fortigate Error Message'",
            context.exception.message(),
        )
