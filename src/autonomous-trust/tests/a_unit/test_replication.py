# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
"""Unit tests for sampled replication (R+D.md §12.6).

The cross-runtime pin is the ``replication`` conformance protocol; these guard
the Python side's API and edge cases. The pinned draws and the committed root
are the same literals the C twin asserts, so a drift on either side shows up as
a unit-test failure before the corpus even runs.
"""

import pytest

from autonomous_trust.core.replication import (CORROBORATED, DISPUTE, OUTVOTED,
                                               SINGLE, ReplicationModel,
                                               ReplicationDeclarationError,
                                               adjudicate, bisect_adjudicate,
                                               commit_root, first_divergence,
                                               hash_chain, parse_replication,
                                               should_replicate, uniform_unit,
                                               verify)


class TestSampling:
    def test_the_draw_is_the_shared_stream(self):
        # the same seeds/draws the C twin pins
        assert uniform_unit(3) == pytest.approx(0.11345034205715454, abs=1e-15)
        assert uniform_unit(0) == pytest.approx(0.8833108082136426, abs=1e-15)

    def test_the_decision_is_a_strict_threshold(self):
        assert should_replicate(0.5, 3)[0] is True    # 0.113 < 0.5
        assert should_replicate(0.05, 3)[0] is False  # 0.113 >= 0.05
        # p=1 replicates the highest draw; p=0 none; equality does not replicate
        assert should_replicate(1.0, 0)[0] is True
        assert should_replicate(0.0, 3)[0] is False
        assert should_replicate(0.11345034205715454, 3)[0] is False

    def test_an_override_is_clamped_not_refused(self):
        assert should_replicate(2.0, 0)[0] is True
        assert should_replicate(-1.0, 3)[0] is False


class TestModel:
    def test_resolution_and_tolerance(self):
        m = parse_replication({'version': 1, 'default_prob': 0.05,
                               'capabilities': {'cmd': {'replicate_prob': 0.5,
                                                        'tolerance': 0.1}}})
        assert m.prob_for('cmd') == 0.5
        assert m.prob_for('other') == 0.05
        assert m.tolerance_for('cmd') == 0.1
        assert m.tolerance_for('other') == 0.0

    def test_a_bad_declaration_is_refused_on_load(self):
        with pytest.raises(ReplicationDeclarationError):
            parse_replication({'version': 1,
                               'capabilities': {'x': {'replicate_prob': 1.5}}})
        with pytest.raises(ReplicationDeclarationError):
            parse_replication({'version': 2})
        with pytest.raises(ReplicationDeclarationError):
            parse_replication({'version': 1,
                               'capabilities': {'x': {}}})  # missing prob

    def test_the_empty_model_samples_only_the_default(self):
        assert isinstance(ReplicationModel(), ReplicationModel)
        assert ReplicationModel().prob_for('anything') == pytest.approx(0.05)


class TestAdjudication:
    def test_a_strict_majority_is_required(self):
        assert adjudicate([('E', 42), ('R1', 42), ('R2', 7)]) == {
            'E': CORROBORATED, 'R1': CORROBORATED, 'R2': OUTVOTED}
        # two disagreeing: a dispute, nobody scored
        assert adjudicate([('E', 42), ('R1', 7)]) == {
            'E': DISPUTE, 'R1': DISPUTE}
        # a 2-2 split is a dispute
        assert set(adjudicate([('E', 1), ('R1', 1),
                               ('R2', 2), ('R3', 2)]).values()) == {DISPUTE}
        # fewer than two: nothing replicated
        assert adjudicate([('E', 42)]) == {'E': SINGLE}

    def test_tolerance_and_type_boundaries(self):
        # within tolerance agrees, outside does not
        assert adjudicate([('E', 20.0), ('R1', 20.05), ('R2', 20.2)],
                          tolerance=0.1) == {
            'E': CORROBORATED, 'R1': CORROBORATED, 'R2': OUTVOTED}
        # a number never agrees with a string
        assert adjudicate([('E', 42), ('R1', '42')]) == {
            'E': DISPUTE, 'R1': DISPUTE}

    def test_verify_maps_only_the_scored_verdicts(self):
        assert verify(CORROBORATED) == (0.9, 'replication')
        assert verify(OUTVOTED) == (0.1, 'replication')
        assert verify(DISPUTE) is None
        assert verify(SINGLE) is None


class TestBisection:
    def test_the_committed_root_is_the_merkle_chain(self):
        assert commit_root(['s0', 's1', 's2', 's3', 's4']) == (
            '4339f13f00492a5b54735f094c5ce6e70d7956e1a56fce6eed6c496fe4d955a6')
        assert commit_root([]) is None

    def test_first_divergence_is_monotonic_binary_search(self):
        a = hash_chain(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'])
        b = hash_chain(['a', 'b', 'c', 'd', 'e', 'Z', 'g', 'h'])
        assert first_divergence(a, b) == 5
        assert first_divergence(a, a) is None

    def test_the_game_convicts_the_cheater(self):
        ref = ['s0', 's1', 's2', 's3', 's4']
        k, v = bisect_adjudicate('A', ref, 'B',
                                 ['s0', 's1', 'X2', 'X3', 'X4'], ref)
        assert k == 2
        assert v == {'A': CORROBORATED, 'B': OUTVOTED}

    def test_both_wrong_is_not_a_tie(self):
        k, v = bisect_adjudicate('A', ['a', 'q', 'c'],
                                 'B', ['a', 'w', 'c'], ['a', 'b', 'c'])
        assert k == 1
        assert v == {'A': OUTVOTED, 'B': OUTVOTED}

    def test_a_length_divergence_is_localized_at_the_common_length(self):
        k, v = bisect_adjudicate('A', ['a', 'b', 'c', 'd'],
                                 'B', ['a', 'b', 'c'], ['a', 'b', 'c', 'd'])
        assert k == 3
        assert v == {'A': CORROBORATED, 'B': OUTVOTED}
