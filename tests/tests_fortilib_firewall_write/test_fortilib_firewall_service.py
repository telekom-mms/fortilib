from fortilib import get_by
from fortilib.service import FortigateTCPUDPService
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_service_create(self):
        service = FortigateTCPUDPService()
        service.name = "tcp-10000"
        service.tcp_portrange = "10000"
        service.comment = "Kommentar"

        self.fw.create_firewall_service(service)

        self.fw.fortigate.create_firewall_service.assert_called_once()
        self.fw.fortigate.create_firewall_service.assert_called_with(
            "tcp-10000",
            {
                "name": "tcp-10000",
                "protocol": "TCP/UDP/SCTP",
                "tcp-portrange": "10000",
                "udp-portrange": "",
                "visibility": "enable",
                "comment": "Kommentar",
            },
        )
        self.assertTrue(service in self.fw.services)

    def test_firewall_base_service_update(self):
        service: FortigateTCPUDPService = get_by(
            "name", "DNS", self.fw.services
        )

        self.assertEqual("", service.comment, "")
        self.assertEqual("53", service.tcp_portrange)
        self.assertEqual("53", service.udp_portrange)

        service.comment = "Kommentar nix"

        self.fw.update_firewall_service(service)

        self.fw.fortigate.update_firewall_service.assert_called_once()
        self.fw.fortigate.update_firewall_service.assert_called_with(
            "DNS",
            {
                "name": "DNS",
                "protocol": "TCP/UDP/SCTP",
                "tcp-portrange": "53",
                "udp-portrange": "53",
                "visibility": "enable",
                "comment": "Kommentar nix",
            },
        )

    def test_firewall_base_service_delete(self):
        service: FortigateTCPUDPService = get_by(
            "name", "DNS", self.fw.services
        )

        self.fw.delete_firewall_service(service)

        self.fw.fortigate.delete_firewall_service.assert_called_once()
        self.fw.fortigate.delete_firewall_service.assert_called_with(
            "DNS",
        )
        self.assertTrue(service not in self.fw.services)
