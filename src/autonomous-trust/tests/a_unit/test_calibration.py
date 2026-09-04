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
"""Conformal coverage audit (R+D.md §12.4).

The tail arithmetic is pinned against independently-computed values because
the whole layer rests on it and the conformance corpus can only see the
verdict it produces. The C twin's `calibration_test.c` pins the same numbers.
"""
import math

import pytest

from autonomous_trust.core.calibration import (
    ABSENT_SCORE, OVERCONFIDENT_SCORE, CalibrationAuditor,
    CalibrationDeclarationError, binomial_tail_log, covers, overconfident,
    parse_calibration,
)
from autonomous_trust.core.reputation import TX_CHANNEL_CALIBRATION

DECL = {
    'version': 1, 'min_samples': 8, 'audit_alpha': 0.05, 'max_outcomes': 64,
    'horizon_sec': 100.0,
    'capabilities': {'fc': {'quantity': 'q', 'min_coverage': 0.5}},
}
SET = {'coverage': 0.9, 'lo': [0.0], 'hi': [10.0]}


def _auditor(decl=None):
    return CalibrationAuditor(parse_calibration(decl or DECL))


class TestExactTest:
    def test_matches_closed_forms(self):
        # P(X <= 5 | n=10, p=1/2) = 638/1024, by symmetry of the binomial.
        assert math.exp(binomial_tail_log(5, 10, 0.5)) == pytest.approx(638 / 1024)
        assert math.exp(binomial_tail_log(0, 1, 0.9)) == pytest.approx(0.1)
        assert math.exp(binomial_tail_log(0, 3, 0.5)) == pytest.approx(0.125)
        assert binomial_tail_log(10, 10, 0.9) == 0.0
        assert binomial_tail_log(-1, 10, 0.9) == -math.inf

    def test_survives_underflow(self):
        """(1-p)^n underflows here; a naive recurrence would reject everyone."""
        value = binomial_tail_log(400, 512, 0.9)
        assert math.isfinite(value) and value < 0.0
        assert not overconfident(500, 512, 0.9, 0.05)

    def test_boundary_probabilities_are_not_nan(self):
        """p at 0 or 1 evaluates 0 * -inf in the general path."""
        assert binomial_tail_log(0, 5, 0.0) == 0.0
        assert binomial_tail_log(4, 5, 1.0) == -math.inf
        assert not math.isnan(binomial_tail_log(0, 5, 0.0))

    def test_is_one_sided(self):
        """An over-cautious peer is useless, not dishonest, and is left alone."""
        assert overconfident(4, 8, 0.9, 0.05)
        assert not overconfident(8, 8, 0.9, 0.05)
        assert not overconfident(100, 100, 0.9, 0.05)
        assert not overconfident(6, 8, 0.9, 0.05)   # tail 0.187

    def test_covers_is_componentwise(self):
        assert covers([0, 0, 0], [10, 10, 10], [5, 5, 5])
        assert not covers([0, 0, 0], [10, 10, 10], [5, 5, 50])
        assert not covers([0, 0, 0], [10, 10, 10], [5, 5])   # arity
        assert not covers([0.0], [10.0], [10.5])
        assert covers([0.0], [10.0], [10.5], tolerance=1.0)


class TestDeclaration:
    def test_empty_until_configured(self):
        assert not CalibrationAuditor().enabled

    def test_max_outcomes_below_min_samples_is_refused(self):
        """Otherwise the ring can never fill and the layer is silently inert."""
        with pytest.raises(CalibrationDeclarationError):
            parse_calibration({'version': 1, 'min_samples': 30,
                               'max_outcomes': 8})

    @pytest.mark.parametrize('bad', [
        {'version': 1, 'audit_alpha': 0.0},
        {'version': 1, 'capabilities': {'f': {}}},
        {'version': 1, 'capabilities': {'f': {'quantity': 'q',
                                              'min_coverage': 0.9,
                                              'max_coverage': 0.5}}},
        {'version': 1, 'capabilities': {'f': {'quantity': 'q',
                                              'horizon_sec': 0}}},
        {'version': 2},
    ])
    def test_incoherent_declarations_are_refused(self, bad):
        with pytest.raises(CalibrationDeclarationError):
            parse_calibration(bad)


class TestAudit:
    def _run(self, auditor, who, n, hit_every_other=False, all_hit=True):
        for i in range(n):
            auditor.assess('fc', SET, who, float(i))
            if hit_every_other:
                value = 5.0 if i % 2 == 0 else 99.0
            else:
                value = 5.0 if all_hit else 99.0
            auditor.resolve('q', value, float(i) + 0.5)

    def test_silent_below_min_samples(self):
        """Silence, not leniency: finite-sample validity is the whole point."""
        a = _auditor()
        self._run(a, 'B', 7, all_hit=False)
        assert a.assess('fc', SET, 'B', 100.0) is None

    def test_rejects_the_overconfident(self):
        a = _auditor()
        self._run(a, 'B', 8, hit_every_other=True)   # four hits in eight
        assert a.assess('fc', SET, 'B', 50.0) == (OVERCONFIDENT_SCORE,
                                                  TX_CHANNEL_CALIBRATION)

    def test_clears_the_honest(self):
        a = _auditor()
        self._run(a, 'H', 10)
        assert a.assess('fc', SET, 'H', 50.0) is None

    @pytest.mark.parametrize('prediction', [
        None,
        {'coverage': 0.01, 'lo': [0.0], 'hi': [10.0]},   # under the floor
        {'coverage': 0.9, 'lo': [9.0], 'hi': [1.0]},     # inverted
        {'coverage': 0.9, 'lo': [1.0, 2.0], 'hi': [5.0]},  # arity
        {'coverage': 'most', 'lo': [0.0], 'hi': [1.0]},
        {'coverage': 0.9, 'quantity': 'other', 'lo': [0.0], 'hi': [1.0]},
        'not-a-mapping',
    ])
    def test_unusable_sets_score_absent(self, prediction):
        a = _auditor()
        assert a.assess('fc', prediction, 'B', 0.0) == (ABSENT_SCORE,
                                                        TX_CHANNEL_CALIBRATION)

    def test_undeclared_capability_is_not_this_layers_business(self):
        assert _auditor().assess('other', SET, 'B', 0.0) is None

    def test_a_peer_cannot_resolve_its_own_prediction(self):
        """Otherwise the peer supplies the truth it is audited against."""
        from autonomous_trust.core.physics import parse_physics
        physics = parse_physics({'version': 1, 'quantities': {
            'q': {'capability': 'sensor.q', 'unit': ''}}})
        a = CalibrationAuditor(parse_calibration(DECL), physics_model=physics)
        a.assess('fc', SET, 'S', 1.0)
        assert a.settle('sensor.q', 5.0, 'S', 2.0) == 0
        assert a.settle('sensor.q', 5.0, 'R', 3.0) == 1
        assert a.settle('sensor.q', 5.0, 'R', 4.0) == 0

    def test_expired_predictions_are_dropped_not_missed(self):
        """Counting silence against a peer would let a quiet sensor convict it."""
        decl = dict(DECL, min_samples=1, capabilities={
            'fc': {'quantity': 'q', 'horizon_sec': 2.0, 'min_coverage': 0.5}})
        a = _auditor(decl)
        a.assess('fc', SET, 'E', 1.0)
        assert a.resolve('q', 99.0, 100.0) == 0
        assert a.assess('fc', SET, 'E', 101.0) is None

    def test_outcome_ring_slides(self):
        """A peer corrected long ago must be able to age out of the verdict."""
        decl = dict(DECL, min_samples=8, max_outcomes=8)
        a = _auditor(decl)
        self._run(a, 'B', 8, hit_every_other=True)
        assert a.assess('fc', SET, 'B', 50.0) is not None
        self._run(a, 'B', 8)          # eight clean resolutions push the old out
        assert a.assess('fc', SET, 'B', 60.0) is None
