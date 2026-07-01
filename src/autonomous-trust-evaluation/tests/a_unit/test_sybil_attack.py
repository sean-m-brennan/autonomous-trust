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

import pytest

try:
    from autonomous_trust.evaluation.redteam.sybil_attack import SybilAttack
    _has_redteam = True
except ImportError:
    _has_redteam = False

pytestmark = pytest.mark.skipif(not _has_redteam,
                                reason='redteam package not installed')


class TestSybilBoundCheck:
    """§8.1: collect() must report a real distinct-identity bound, not None."""

    def test_bounded_when_no_sybil_admitted(self):
        # Legitimate roster is 5; exactly 5 identities admitted -> bounded.
        atk = SybilAttack(num_sybil_nodes=3, expected_admitted=5)
        out = atk.collect({'identity_peers_admitted': 5,
                           'identity_admitted_ids': [f'id-{i}' for i in range(5)]})
        spec = out['attack_specific']
        assert spec['sybil_identities_attempted'] == 3
        assert spec['total_identities_admitted'] == 5
        assert spec['sybil_identities_admitted'] == 0
        assert spec['identity_count_bounded'] is True

    def test_unbounded_when_sybil_admitted(self):
        # 5 legitimate expected but 7 admitted -> 2 Sybils slipped in.
        atk = SybilAttack(num_sybil_nodes=3, expected_admitted=5)
        out = atk.collect({'identity_peers_admitted': 7,
                           'identity_admitted_ids': [f'id-{i}' for i in range(7)]})
        spec = out['attack_specific']
        assert spec['sybil_identities_admitted'] == 2
        assert spec['identity_count_bounded'] is False

    def test_id_list_preferred_over_count(self):
        # When both are present, the id list is authoritative.
        atk = SybilAttack(num_sybil_nodes=3, expected_admitted=2)
        out = atk.collect({'identity_peers_admitted': 99,
                           'identity_admitted_ids': ['a', 'b']})
        spec = out['attack_specific']
        assert spec['total_identities_admitted'] == 2
        assert spec['identity_count_bounded'] is True

    def test_none_when_expectation_unset(self):
        # No expected roster -> cannot judge; metrics are None (not fabricated).
        atk = SybilAttack(num_sybil_nodes=3)
        out = atk.collect({'identity_peers_admitted': 5})
        spec = out['attack_specific']
        assert spec['sybil_identities_admitted'] is None
        assert spec['identity_count_bounded'] is None

    def test_none_when_no_metrics(self):
        # CALDERA bridge path invokes collect({}); nothing observed.
        atk = SybilAttack(num_sybil_nodes=3, expected_admitted=5)
        out = atk.collect({})
        spec = out['attack_specific']
        assert spec['total_identities_admitted'] is None
        assert spec['identity_count_bounded'] is None


class TestSybilAssessment:
    """A breached bound must drive the harness verdict to FAIL."""

    def _harness(self):
        from autonomous_trust.evaluation.redteam.harness import RedTeamHarness
        return RedTeamHarness.__new__(RedTeamHarness)

    def test_admitted_sybil_fails(self):
        h = self._harness()
        metrics = {'attack_specific': {'identity_count_bounded': False}}
        assert h._assess_result({}, metrics) == 'FAIL'

    def test_bounded_passes(self):
        h = self._harness()
        metrics = {'attack_specific': {'identity_count_bounded': True}}
        assert h._assess_result({}, metrics) == 'PASS'
