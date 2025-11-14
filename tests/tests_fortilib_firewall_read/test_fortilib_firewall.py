from unittest.mock import Mock

from httpx import (
    Client,
    Response,
)

from fortilib.exceptions import APIException
from fortilib.fortigateapi import FortiGateApi
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_exceptions(self):
        """
        Test exception messaging.
        """

        the_response = Mock(spec=Response)

        the_response.text = ""
        the_response.json.return_value = {}
        the_response.status_code = 400

        with self.assertRaises(APIException) as cm:
            raise APIException(the_response)

        self.assertTrue("Response Code: 400 - " in str(cm.exception))

        the_response.text = '{"cli_error": "API broken"}'
        the_response.json.return_value = {"cli_error": "API broken"}
        the_response.status_code = 500

        with self.assertRaises(APIException) as cm:
            raise APIException(the_response)

        print(str(cm.exception))
        self.assertTrue("Response Code: 500 - API broken" in str(cm.exception))

    def test_query_api_get(self):
        response = Mock(spec=Response)

        response.json.return_value = {"results": "test result"}
        response.status_code = 200

        mock_session = Mock(spec=Client)
        mock_session.get.return_value = response
        fortigate_api = FortiGateApi("127.0.0.1", "test", "test")
        fortigate_api.client = mock_session

        result = fortigate_api.query_api_get(
            "api/v2/cmdb/firewall/policy/", "1/", filters="skip=1"
        )

        fortigate_api.client.get.assert_called_once_with(
            "https://127.0.0.1:443/api/v2/cmdb/firewall/policy/1/",
            params={"filter": "skip=1", "vdom": "root"},
        )
        self.assertEqual("test result", result)
