import ipaddress

from fortilib import get_by
from fortilib.phase1interface import FortigatePhase1Interface
from tests import FortigateTest


class TestFortilibFirewall(FortigateTest):
    def test_firewall_base_phase1_interface_create(self):
        phase1_interface = FortigatePhase1Interface()
        phase1_interface.name = "vpn_phase1"
        phase1_interface.default_gw = ipaddress.ip_address("0.0.0.0")
        phase1_interface.remote_gw = ipaddress.ip_address("1.1.1.1")
        phase1_interface.dhgrp = "20"
        phase1_interface.dpd = "on-demand"
        phase1_interface.ike_version = "2"
        phase1_interface.psksecret = "123456"
        phase1_interface.proposal = (
            "chacha20poly1305-prfsha256 aes256gcm-prfsha384"
        )
        phase1_interface.keylife = 86400
        phase1_interface.keepalive = 10
        phase1_interface.nattraversal = "disable"
        phase1_interface.comment = "test phase1"
        phase1_interface.interface = get_by(
            "name", "port1", self.fw.interfaces
        )

        self.fw.create_firewall_phase1_interface(phase1_interface)

        self.fw.fortigate.create_firewall_phase1_interface.assert_called_once()
        self.fw.fortigate.create_firewall_phase1_interface.assert_called_with(
            phase1_interface.name,
            {
                "name": "vpn_phase1",
                "default-gw": "0.0.0.0",
                "dhgrp": "20",
                "dpd": "on-demand",
                "ike-version": "2",
                "interface": "port1",
                "keepalive": 10,
                "keylife": 86400,
                "localid": "",
                "nattraversal": "disable",
                "proposal": "chacha20poly1305-prfsha256 aes256gcm-prfsha384",
                "psksecret": "123456",
                "remote-gw": "1.1.1.1",
                "comments": "test phase1",
            },
        )
        self.assertTrue(phase1_interface in self.fw.phase1_interfaces)

    def test_firewall_base_phase1_interface_update(self):
        phase1_interface: FortigatePhase1Interface = get_by(
            "name", "vpn_phase1", self.fw.phase1_interfaces
        )

        phase1_interface.remote_gw = ipaddress.ip_address("2.2.2.2")

        self.fw.update_firewall_phase1_interface(phase1_interface)

        self.fw.fortigate.update_firewall_phase1_interface.assert_called_once()
        self.fw.fortigate.update_firewall_phase1_interface.assert_called_with(
            "vpn_phase1",
            {
                "name": "vpn_phase1",
                "default-gw": "0.0.0.0",
                "dhgrp": "20",
                "dpd": "on-demand",
                "ike-version": "2",
                "interface": "port1",
                "keepalive": 10,
                "keylife": 86400,
                "localid": "",
                "nattraversal": "disable",
                "proposal": "chacha20poly1305-prfsha256 aes256gcm-prfsha384",
                "psksecret": "123456",
                "remote-gw": "2.2.2.2",
                "comments": "test phase1",
            },
        )

    def test_firewall_base_phase1_interface_delete(self):
        phase1_interface: FortigatePhase1Interface = get_by(
            "name", "vpn_phase1", self.fw.phase1_interfaces
        )

        self.fw.delete_firewall_phase1_interface(phase1_interface)

        self.fw.fortigate.delete_firewall_phase1_interface.assert_called_once()
        self.fw.fortigate.delete_firewall_phase1_interface.assert_called_with(
            "vpn_phase1",
        )
        self.assertTrue(phase1_interface not in self.fw.phase1_interfaces)
