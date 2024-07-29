import ipaddress

from fortilib import get_by
from fortilib.phase2interface import FortigatePhase2Interface
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_phase2_interface_create(self):
        phase2_interface = FortigatePhase2Interface()
        phase2_interface.name = "vpn_phase2"
        phase2_interface.phase1_name = "vpn_phase1"
        phase2_interface.src_subnet = ipaddress.ip_network("10.0.0.0/8")
        phase2_interface.dst_subnet = ipaddress.ip_network("192.168.100.0/24")
        phase2_interface.dhgrp = "20"
        phase2_interface.proposal = "chacha20poly1305 aes256gcm"
        phase2_interface.keylife_seconds = 14400
        phase2_interface.keepalive = "enable"
        phase2_interface.comment = "test phase2"

        self.fw.create_firewall_phase2_interface(phase2_interface)

        self.fw.fortigate.create_firewall_phase2_interface.assert_called_once()
        self.fw.fortigate.create_firewall_phase2_interface.assert_called_with(
            phase2_interface.name,
            {
                "name": "vpn_phase2",
                "phase1name": "vpn_phase1",
                "dst-subnet": "192.168.100.0/24",
                "src-subnet": "10.0.0.0/8",
                "dhgrp": "20",
                "pfs": "enable",
                "replay": "enable",
                "keepalive": "enable",
                "auto-negotiate": "disable",
                "keylifeseconds": 14400,
                "keylifekbs": None,
                "keylife-type": "seconds",
                "proposal": "chacha20poly1305 aes256gcm",
                "comments": "test phase2",
            },
        )
        self.assertTrue(phase2_interface in self.fw.phase2_interfaces)

    def test_firewall_base_phase2_interface_update(self):
        phase2_interface: FortigatePhase2Interface = get_by(
            "name", "vpn_phase2", self.fw.phase2_interfaces
        )

        phase2_interface.dst_subnet = ipaddress.ip_network("192.168.200.0/24")

        self.fw.update_firewall_phase2_interface(phase2_interface)

        self.fw.fortigate.update_firewall_phase2_interface.assert_called_once()
        self.fw.fortigate.update_firewall_phase2_interface.assert_called_with(
            "vpn_phase2",
            {
                "name": "vpn_phase2",
                "phase1name": "vpn_phase1",
                "dst-subnet": "192.168.200.0/24",
                "src-subnet": "10.0.0.0/8",
                "dhgrp": "20",
                "pfs": "enable",
                "replay": "enable",
                "keepalive": "disable",
                "auto-negotiate": "enable",
                "keylifeseconds": 43200,
                "keylifekbs": 5120,
                "keylife-type": "seconds",
                "proposal": "chacha20poly1305 aes256gcm",
                "comments": "test phase2",
            },
        )

    def test_firewall_base_phase2_interface_delete(self):
        phase2_interface: FortigatePhase2Interface = get_by(
            "name", "vpn_phase2", self.fw.phase2_interfaces
        )

        self.fw.delete_firewall_phase2_interface(phase2_interface)

        self.fw.fortigate.delete_firewall_phase2_interface.assert_called_once()
        self.fw.fortigate.delete_firewall_phase2_interface.assert_called_with(
            "vpn_phase2",
        )
        self.assertTrue(phase2_interface not in self.fw.phase2_interfaces)
