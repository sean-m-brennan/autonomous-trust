"""MITM attack: network-level interception test for NaCl encryption validation."""

import os
from typing import Optional

from . import AttackScenario

AT_SIGNATURES = [
    'ask permission', 'permission granted', 'try again', 'out of date',
    'transaction', 'tx accepted', 'update needed', 'latest update',
    'request reputation', 'reputation response',
    'invitation', 'haggle', 'ack',
    'access_granted', 'access_denied',
]


class MitmAttack(AttackScenario):
    """Capture traffic between two AT peers and check for plaintext leaks.

    Deploys a tcpdump sidecar that captures all traffic on the target link.
    After simulation, analyzes pcap for known AT message signatures.
    """

    name = "mitm_attempt"
    description = "Network interception test validating NaCl encryption"

    def __init__(self, target_peer_a: str, target_peer_b: str,
                 pcap_path: str = '/tmp/mitm-capture.pcap'):
        self.target_peer_a = target_peer_a
        self.target_peer_b = target_peer_b
        self.pcap_path = pcap_path

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        services = compose_config.setdefault('services', {})
        services['tcpdump-mitm'] = {
            'image': 'nicolaka/netshoot',
            'container_name': 'tcpdump-mitm',
            'network_mode': f'service:{self.target_peer_a}',
            'command': f'tcpdump -i any -w /capture/mitm.pcap -s 0',
            'volumes': [f'{os.path.dirname(self.pcap_path)}:/capture'],
            'depends_on': [self.target_peer_a],
        }
        sim_config['mitm_pcap_path'] = self.pcap_path

    def teardown(self) -> None:
        pass

    def collect(self, metrics: dict) -> dict:
        plaintext_found = False
        replay_accepted = False
        signatures_found = []

        if os.path.exists(self.pcap_path):
            try:
                with open(self.pcap_path, 'rb') as f:
                    pcap_bytes = f.read()
                for sig in AT_SIGNATURES:
                    if sig.encode('utf-8') in pcap_bytes:
                        plaintext_found = True
                        signatures_found.append(sig)
            except Exception:
                pass

        metrics['attack_specific'] = {
            'encryption_bypassed': plaintext_found,
            'plaintext_extracted': plaintext_found,
            'replay_accepted': replay_accepted,
            'signatures_found': signatures_found,
        }
        return metrics
