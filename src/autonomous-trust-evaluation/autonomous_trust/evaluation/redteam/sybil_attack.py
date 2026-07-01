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

    Measurement (``collect``) uses a *distinct-identity bound check*: the
    admission layer must not grant access to more identities than the
    legitimate roster. Any identity admitted beyond ``expected_admitted``
    is counted as a Sybil that slipped past the gate. Sybil UUIDs are
    generated inside the attacker containers at runtime and are therefore
    not known to this scenario, so precise name matching is infeasible; the
    count bound is the observable invariant (cf. ISSUES.md §8.1).
    """

    name = "sybil_attack"
    description = "Fabricated identities attempting admission via voting"

    def __init__(self, num_sybil_nodes: int = 3, base_ip_offset: int = 30,
                 expected_admitted: int = None):
        self.num_sybil_nodes = num_sybil_nodes
        self.base_ip_offset = base_ip_offset
        # Number of legitimate identities expected to be admitted (the
        # honest topology size). When set, ``collect`` derives a pass/fail
        # bound; when None, the count-based metrics are reported as None.
        self.expected_admitted = expected_admitted

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
        # Distinct identities the mesh actually granted access to, as
        # observed by the metrics collector. Prefer the explicit id list
        # (added to the report so the bound is auditable) and fall back to
        # the count for older metrics payloads.
        admitted_ids = metrics.get('identity_admitted_ids')
        if admitted_ids is not None:
            total_admitted = len(admitted_ids)
        else:
            total_admitted = metrics.get('identity_peers_admitted')

        sybil_admitted = None
        bounded = None
        if total_admitted is not None and self.expected_admitted is not None:
            # Anything admitted beyond the legitimate roster got past the
            # admission gate and is, by definition, a Sybil.
            sybil_admitted = max(0, total_admitted - self.expected_admitted)
            bounded = sybil_admitted == 0

        metrics['attack_specific'] = {
            'sybil_identities_attempted': self.num_sybil_nodes,
            'expected_legitimate_admitted': self.expected_admitted,
            'total_identities_admitted': total_admitted,
            'sybil_identities_admitted': sybil_admitted,
            'identity_count_bounded': bounded,
        }
        return metrics
