import unittest
from unittest.mock import Mock

from httpx import (
    Client,
    Response,
)

from fortilib.fortigateapi import FortiGateApi


class TestFortilibFirewall(unittest.TestCase):
    def test_get_firewall_system_status(self):
        response = Mock(spec=Response)
        status = {
            "http_method": "GET",
            "results": {
                "model_name": "FortiGate",
                "model_number": "100F",
                "model": "FG100F",
                "hostname": "test-fortigate-01",
                "log_disk_status": "not_available",
            },
            "vdom": "root",
            "path": "system",
            "name": "status",
            "status": "success",
            "serial": "FG100FTK123456789",
            "version": "v7.6.7",
            "build": 3704,
        }
        response.json.return_value = status
        response.status_code = 200

        mock_session = Mock(spec=Client)
        mock_session.get.return_value = response
        fortigate_api = FortiGateApi("127.0.0.1", "test", "test")
        fortigate_api.client = mock_session

        result = fortigate_api.get_firewall_system_status()

        mock_session.get.assert_called_once_with(
            "https://127.0.0.1:443/api/v2/monitor/system/status/",
            params={"vdom": "root"},
        )
        self.assertEqual(status, result)

    def test_get_firewall_system_interface_transceivers(self):
        response = Mock(spec=Response)
        transceivers_response = {
            "results": [
                {
                    "type": "SFP/SFP+/SFP28",
                    "vendor": "FORTINET",
                    "vendor_part_number": "FTLF8519P3BNLFTN",
                    "vendor_serial_number": "FABC123",
                    "interface": "port13",
                },
                {
                    "type": "SFP/SFP+/SFP28",
                    "vendor": "FORTINET",
                    "vendor_part_number": "FTLF8519P3BNLFTN",
                    "vendor_serial_number": "FABC124",
                    "interface": "port14",
                },
            ],
            "vdom": "root",
            "path": "system",
            "name": "interface",
            "action": "transceivers",
            "status": "success",
            "serial": "FG100FTK123456789",
            "version": "v7.6.7",
            "build": 3704,
        }
        response.json.return_value = transceivers_response
        response.status_code = 200

        mock_session = Mock(spec=Client)
        mock_session.get.return_value = response
        fortigate_api = FortiGateApi("127.0.0.1", "test", "test")
        fortigate_api.client = mock_session

        result = fortigate_api.get_firewall_system_interface_transceivers()

        mock_session.get.assert_called_once_with(
            "https://127.0.0.1:443/api/v2/monitor/system/interface/transceivers/",
            params={"vdom": "root"},
        )
        self.assertEqual(transceivers_response["results"], result)
