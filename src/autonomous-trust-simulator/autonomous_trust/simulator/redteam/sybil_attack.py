# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
"""Sybil attack: inject fabricated identities into the AT network."""

from . import AttackScenario


class SybilAttack(AttackScenario):
    """Spawns extra containers with fabricated identities.

    These attempt admission via identity voting. The AT identity
    system should reject unknown identities via voting.
    """

    name = "sybil_attack"
    description = "Fabricated identities attempting admission via voting"

    def __init__(self, num_sybil_nodes: int = 3, base_ip_offset: int = 30):
        self.num_sybil_nodes = num_sybil_nodes
        self.base_ip_offset = base_ip_offset

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        """Patch compose config to add Sybil node containers."""
        services = compose_config.setdefault('services', {})
        for i in range(self.num_sybil_nodes):
            node_name = f"sybil-{i + 1}"
            ip = f"10.27.3.{self.base_ip_offset + i}"
            services[node_name] = {
                'image': 'autonomous-trust-devel',
                'container_name': node_name,
                'hostname': node_name,
                'cap_add': ['NET_ADMIN'],
                'environment': {
                    'ROUTER': '10.27.3.1',
                    'AUTONOMOUS_TRUST_BACKEND': 'python',
                    'SYBIL_NODE': 'true',
                    'STARTUP_DELAY': str(i * 2),
                },
                'networks': {
                    'at-net': {'ipv4_address': ip},
                },
            }
        sim_config['sybil_node_count'] = self.num_sybil_nodes

    def teardown(self) -> None:
        pass

    def collect(self, metrics: dict) -> dict:
        metrics['attack_specific'] = {
            'sybil_identities_attempted': self.num_sybil_nodes,
            'sybil_identities_admitted': None,
            'identity_count_bounded': None,
        }
        return metrics
