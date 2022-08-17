from fortilib import get_by
from fortilib.service import (
    FortigateICMP6Service,
    FortigateICMPService,
    FortigateIPService,
    FortigateProxyService,
    FortigateTCPUDPService,
)
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_services_tcp(self):
        service: FortigateTCPUDPService = get_by(
            "name", "DNS", self.fw.services
        )
        self.assertTrue(isinstance(service, FortigateTCPUDPService))
        self.assertEqual(len(self.fw.services), 7)
        self.assertEqual(
            service.render(),
            {
                "name": "DNS",
                "protocol": "TCP/UDP/SCTP",
                "tcp-portrange": "53",
                "udp-portrange": "53",
                "visibility": "enable",
                "comment": "",
            },
        )

    def test_firewall_base_services_icmp(self):
        service: FortigateICMPService = get_by(
            "name", "PING", self.fw.services
        )
        self.assertTrue(isinstance(service, FortigateICMPService))
        self.assertEqual(
            service.render(),
            {
                "name": "PING",
                "protocol": "ICMP",
                "icmptype": 8,
                "icmpcode": "",
                "comment": "",
            },
        )

    def test_firewall_base_services_icmp6(self):
        service: FortigateICMP6Service = get_by(
            "name", "ALL_ICMP6", self.fw.services
        )
        self.assertTrue(isinstance(service, FortigateICMP6Service))
        self.assertEqual(
            service.render(),
            {
                "name": "ALL_ICMP6",
                "protocol": "ICMP6",
                "icmptype": "",
                "comment": "",
            },
        )

    def test_firewall_base_services_ip(self):
        service: FortigateIPService = get_by("name", "GRE", self.fw.services)
        self.assertTrue(isinstance(service, FortigateIPService))
        self.assertEqual(
            service.render(),
            {
                "name": "GRE",
                "protocol": "IP",
                "protocol-number": 47,
                "comment": "",
            },
        )

    def test_firewall_base_services_all(self):
        service: FortigateProxyService = get_by(
            "name", "webproxy", self.fw.services
        )
        self.assertTrue(isinstance(service, FortigateProxyService))
        self.assertEqual(
            service.render(),
            {
                "name": "webproxy",
                "protocol": "ALL",
                "proxy": "enable",
                "tcp-portrange": "0-65535:0-65535",
                "comment": "",
            },
        )

    def test_firewall_base_services_proxy(self):
        service: FortigateProxyService = get_by(
            "name", "proxy_https", self.fw.services
        )
        self.assertTrue(isinstance(service, FortigateProxyService))
        self.assertEqual(
            service.render(),
            {
                "name": "proxy_https",
                "protocol": "ALL",
                "proxy": "enable",
                "tcp-portrange": "443",
                "comment": "",
            },
        )
