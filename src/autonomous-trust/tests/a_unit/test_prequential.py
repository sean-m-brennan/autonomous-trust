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
"""Prequential competence (R+D.md §12.5).

The arithmetic is pinned here because the conformance corpus sees the
multiplier a whole sequence produced and not the interval score inside it --
and a layer whose two runtimes disagree by one weight step makes an EMA depend
on which implementation happened to be scoring. The C twin's
`prequential_test.c` pins the same numbers on the same sequences.
"""
import math

import pytest

from autonomous_trust.core.prequential import (
    MAX_LOSS, NEUTRAL_COMPETENCE, PrequentialDeclarationError,
    PrequentialEstimator, band_multiplier, hedge_bound, hedge_weights,
    interval_score, normalized_loss, parse_prequential, weight_round,
)

# Two capabilities forecasting ONE quantity, deliberately: the aggregate is a
# single interval, so the parse accepts them only when their alpha and scale
# agree, and the mixture adds their losses together. min_samples 2 keeps the
# sequences short enough to read.
DECL = {
    'version': 1, 'min_samples': 2, 'max_outcomes': 8, 'max_outstanding': 8,
    'horizon_sec': 10.0, 'eta': 1.0,
    'weight_band': {'min': 0.5, 'max': 2.0},
    'capabilities': {
        'F': {'quantity': 'q', 'scale': 10.0, 'alpha': 0.1,
              'horizon_sec': 10.0},
        'R': {'quantity': 'q', 'scale': 10.0, 'alpha': 0.1},
    },
}


def _estimator(decl=None):
    return PrequentialEstimator(parse_prequential(decl or DECL))


def _forecast(est, cap, peer, lo, hi, now):
    return est.observe(cap, {'lo': [lo], 'hi': [hi]}, peer, now)


def _sharp_and_vague(est):
    """A sharp forecaster and a vague one, both awake for four rounds."""
    for t, y in enumerate([5.0, 6.0, 4.0, 5.0]):
        now = float(t)
        _forecast(est, 'F', 'A', y - 0.5, y + 0.5, now)
        _forecast(est, 'F', 'B', y - 8.0, y + 8.0, now)
        est.resolve('q', y, now + 0.5)


class TestTheLoss:
    def test_splits_sharpness_from_the_miss(self):
        # Covered: the width alone, so a peer is charged for vagueness even
        # when it is right.
        assert interval_score((4.,), (6.,), (5.,), 0.1) == pytest.approx(2.0)
        # Missed high by 2 at alpha 0.1: 2 + (2/0.1)*2 = 42. The miss
        # dominates, which is the point of a proper rule.
        assert interval_score((4.,), (6.,), (8.,), 0.1) == pytest.approx(42.0)

    def test_tolerance_forgives_the_miss_and_not_the_width(self):
        # The tolerance models what is unknown about the OBSERVATION, so it
        # bears only on whether the value fell outside. Charging the widened
        # width would bill every peer on a coarsely measured quantity for our
        # instrument, and would put a floor of 2*tolerance/scale under a
        # perfect forecaster -- making band_max unreachable wherever a
        # tolerance is declared at all.
        assert interval_score((4.,), (6.,), (8.,), 0.1,
                              tolerance=2.0) == pytest.approx(2.0)

    def test_is_the_mean_over_components(self):
        # A 3-vector forecast must not be three times worse than a scalar
        # one, so the score is the MEAN: two components each scoring 2 give 2.
        assert interval_score((0., 10.), (2., 12.), (1., 11.),
                              0.1) == pytest.approx(2.0)
        # An arity mismatch is a shape the world contradicted; the caller
        # decides what that means.
        assert interval_score((0., 10.), (2., 12.), (1.,), 0.1) is None

    def test_normalized_loss_saturates(self):
        assert normalized_loss(2.0, 10.0) == pytest.approx(0.2)
        # Missing by 2.5 scales is not usefully worse than missing by 1:
        # Hedge needs a bounded loss, and "impossible" is the physics layer's
        # verdict to render.
        assert normalized_loss(25.0, 10.0) == pytest.approx(MAX_LOSS)
        assert normalized_loss(2.0, 0.0) == pytest.approx(MAX_LOSS)

    def test_band_multiplier_spans_exactly_the_declared_band(self):
        # A perfect record earns the top of the band and a saturated one the
        # bottom, and nothing reaches outside it -- which is what keeps the
        # operator's authored weight the anchor.
        assert band_multiplier(0.0, 0.5, 2.0) == pytest.approx(2.0)
        assert band_multiplier(1.0, 0.5, 2.0) == pytest.approx(0.5)
        assert band_multiplier(0.5, 0.5, 2.0) == pytest.approx(1.25)

    def test_weight_round_is_floor_of_x_plus_half(self):
        # THE cross-runtime trap: Python's round() is banker's (2.5 -> 2) and
        # C's lround is half-away-from-zero. floor(x + 0.5) is neither, it is
        # what both runtimes implement, and a band-mapped weight lands on .5
        # more often than anywhere else.
        assert weight_round(1.5) == 2
        assert weight_round(2.5) == 3
        assert round(2.5) == 2, 'the builtin this rule exists to avoid'
        assert weight_round(3.49) == 3
        # Floored at 1: the EMA folds a score in `weight` times.
        assert weight_round(0.4) == 1
        assert weight_round(-5.0) == 1


class TestHedge:
    def test_weights_survive_underflow(self):
        assert hedge_weights([3.0, 3.0], 1.0) == pytest.approx([0.5, 0.5])
        # exp(-800) is zero in a double, so a naive implementation normalizes
        # a table of zeros -- no aggregate at all, at exactly the run lengths
        # where the bound is worth having. The max-shift keeps the RATIO,
        # which is all the weights depend on.
        w = hedge_weights([800.0, 802.0], 1.0)
        assert w == pytest.approx([0.8807970779778823, 0.11920292202211755])
        assert sum(w) == pytest.approx(1.0)

    def test_bound_is_log_n_over_eta_plus_eta_t_over_eight(self):
        assert hedge_bound(2, 4, 1.0) == pytest.approx(math.log(2) + 0.5)
        assert hedge_bound(2, 4, 1.0) == pytest.approx(1.1931471805599454)
        # One expert has nothing to regret against.
        assert hedge_bound(1, 0, 1.0) == pytest.approx(0.0)


class TestDeclaration:
    def test_is_empty_until_configured(self):
        est = PrequentialEstimator()
        assert not est.enabled
        # Opt-in means EXACTLY the authored weight, not approximately it.
        assert est.competence('A', 'F') == NEUTRAL_COMPETENCE

    def test_rejects_a_ring_that_cannot_reach_the_threshold(self):
        # The layer would be silently inert -- the failure mode hardest to
        # notice, and the reason this is fatal at load.
        with pytest.raises(PrequentialDeclarationError):
            parse_prequential({'min_samples': 8, 'max_outcomes': 4,
                               'capabilities': {
                                   'F': {'quantity': 'q', 'scale': 1.0}}})

    def test_rejects_a_band_that_excludes_the_authored_weight(self):
        # 1.0 outside the band makes the operator's number unreachable, so it
        # would not be the anchor it is documented to be.
        with pytest.raises(PrequentialDeclarationError):
            parse_prequential({'weight_band': {'min': 1.5, 'max': 2.0},
                               'capabilities': {
                                   'F': {'quantity': 'q', 'scale': 1.0}}})

    def test_rejects_one_quantity_at_two_levels(self):
        # The mixture adds losses divided by different scales, and two peers
        # scored at different alphas are not being compared at all.
        for clash in ({'alpha': 0.2}, {'scale': 20.0}):
            decl = {'capabilities': {
                'F': {'quantity': 'q', 'scale': 10.0, 'alpha': 0.1},
                'G': dict({'quantity': 'q', 'scale': 10.0, 'alpha': 0.1},
                          **clash)}}
            with pytest.raises(PrequentialDeclarationError):
                parse_prequential(decl)
        # ...and the coherent version of the same declaration parses.
        model = parse_prequential(DECL)
        assert not model.empty
        assert model.forecasts('q')


class TestCompetence:
    def test_is_silent_below_min_samples(self):
        est = _estimator()
        _forecast(est, 'F', 'A', 4.5, 5.5, 0.0)
        est.resolve('q', 5.0, 0.5)
        # One resolution, min_samples 2: a layer whose failure mode is a
        # guess is worse than one that says nothing.
        assert est.competence('A', 'F') == NEUTRAL_COMPETENCE
        _forecast(est, 'F', 'A', 4.5, 5.5, 1.0)
        est.resolve('q', 5.0, 1.5)
        assert est.competence('A', 'F') > 1.0

    def test_rewards_sharpness_and_bounds_both_ends(self):
        est = _estimator()
        _sharp_and_vague(est)
        # A's mean loss is 0.1 (width 1 over scale 10, covered every round)
        # -> 2.0 - 1.5*0.1. B's forecasts are so wide they saturate -> the
        # floor of the band. The coverage audit (R+D.md §12.4) is REQUIRED to
        # forgive B, which never over-claimed; this is the layer that does not.
        assert est.competence('A', 'F') == pytest.approx(1.85)
        assert est.competence('B', 'F') == pytest.approx(0.5)

    def test_says_nothing_about_what_it_has_not_seen(self):
        est = _estimator()
        _sharp_and_vague(est)
        assert est.competence('Z', 'F') == NEUTRAL_COMPETENCE
        assert est.competence('A', 'X') == NEUTRAL_COMPETENCE
        assert est.competence(None, 'F') == NEUTRAL_COMPETENCE
        # Regional by capability as well as by quantity: A's record on F says
        # nothing about A on R, which has resolved nothing.
        assert est.competence('A', 'R') == NEUTRAL_COMPETENCE

    def test_a_peer_never_settles_its_own_forecast(self):
        est = _estimator()
        _forecast(est, 'F', 'A', 4.5, 5.5, 0.0)
        # A supplying the truth A is scored against is A grading itself.
        assert est.resolve('q', 5.0, 0.5, reporter='A') == 0
        assert est.resolve('q', 5.0, 0.5, reporter='B') == 1

    def test_expired_forecasts_are_dropped_not_scored(self):
        est = _estimator()
        _forecast(est, 'F', 'A', 4.5, 5.5, 0.0)
        # Past the 10-second horizon: a truth that arrived too late to be
        # about this forecast records no loss, rather than the maximum one.
        assert est.resolve('q', 5.0, 100.0) == 0
        assert est.competence('A', 'F') == NEUTRAL_COMPETENCE

    def test_an_unusable_forecast_records_nothing(self):
        est = _estimator()
        # "Declared predictive and attached nothing" is a fact about the
        # CLAIM, and the coverage audit already scores it. Scoring it here
        # too would double-count one omission -- and this layer has no
        # channel to score it on.
        assert not est.observe('F', None, 'A', 0.0)
        assert not _forecast(est, 'F', 'A', 6.0, 4.0, 0.0)   # inverted
        assert not est.observe('F', {'lo': [1.0]}, 'A', 0.0)  # no hi
        assert not _forecast(est, 'X', 'A', 4.0, 6.0, 0.0)    # undeclared

    def test_shape_mismatch_scores_the_worst_case(self):
        est = _estimator()
        # A 2-component forecast against a scalar observation: the forecast
        # committed to a shape the world contradicted, which is the WORST
        # case and not an absent one. If the call site ever stopped mapping
        # the None, this peer would come out at the TOP of the band.
        for t in range(3):
            est.observe('F', {'lo': [4.5, 4.5], 'hi': [5.5, 5.5]}, 'A',
                        float(t))
            est.resolve('q', 5.0, float(t) + 0.5)
        assert est.competence('A', 'F') == pytest.approx(0.5)

    def test_settle_reads_the_carried_result_forms(self):
        # The three shapes a `report results` payload carries, which is what
        # lets an ordinary later result close the loop with no application
        # involvement. `settle` takes the REPORTING capability and asks the
        # physics model which quantity it reports -- the same link the
        # coverage audit resolves through, and the reason `quantity` in a
        # prequential declaration is a reference to physics.json.
        from autonomous_trust.core.physics import parse_physics
        physics = parse_physics({'version': 1, 'quantities': {
            'q': {'capability': 'sensor.q', 'unit': ''}}})
        # A parsed payload, not text: this runtime receives a result object
        # where C receives the bytes off its wire, which is why the C twin's
        # `at_prequential_settle_result` takes a string and this does not.
        # Same split as the coverage audit's settle.
        for form in (5.0, [5.0], {'value': 5.0}, {'values': [5.0]}):
            est = PrequentialEstimator(parse_prequential(DECL),
                                       physics_model=physics)
            _forecast(est, 'F', 'A', 4.5, 5.5, 0.0)
            assert est.settle('sensor.q', form, 'B', 0.5) == 1
        # Prose settles nothing -- and neither does a bare numeral as text,
        # deliberately: a caller holding bytes has to parse them, so a
        # payload that only looks numeric cannot slip in as a measurement.
        for junk in ('warm', '5.0', None, True):
            est = PrequentialEstimator(parse_prequential(DECL),
                                       physics_model=physics)
            _forecast(est, 'F', 'A', 4.5, 5.5, 0.0)
            assert est.settle('sensor.q', junk, 'B', 0.5) == 0
        # A capability no physics declaration mentions resolves to no
        # quantity, so it settles nothing rather than guessing one.
        assert est.settle('other', '5.0', 'B', 0.5) == 0


class TestAggregate:
    def test_combine_is_the_weighted_endpoint_average(self):
        est = _estimator()
        # Two peers with no record yet weigh equally, so the aggregate of
        # [0,2] and [10,12] is [5,7] -- endpoint-wise, which is what makes
        # the raw interval score convex in the endpoints.
        _forecast(est, 'F', 'A', 0.0, 2.0, 0.0)
        _forecast(est, 'F', 'B', 10.0, 12.0, 0.0)
        agg = est.combine('q', 0.1)
        assert agg['lo'] == pytest.approx([5.0])
        assert agg['hi'] == pytest.approx([7.0])
        assert [c['weight'] for c in agg['contributors']] == pytest.approx(
            [0.5, 0.5])
        # Nothing outstanding is not an aggregate of nothing.
        est.reset()
        assert est.combine('q', 0.1) is None

    def test_regret_reports_the_realized_gap_and_the_bound(self):
        est = _estimator()
        _sharp_and_vague(est)
        r = est.regret('q')
        assert r['rounds'] == 4
        assert r['experts'] == 2
        assert r['mixture_loss'] == pytest.approx(1.2944874264992323)
        assert r['aggregate_loss'] == pytest.approx(1.8908123774987204)
        # Hedge's guarantee, MEASURED: the mixture's realized excess over each
        # peer's own loss on the rounds that peer was awake stays under the
        # bound. This is the one claim in AT that holds against arbitrary
        # adversarial peers at any sample size.
        for peer in r['peers'].values():
            assert peer['rounds'] == 4
            assert peer['bound'] == pytest.approx(1.1931471805599454)
            assert peer['realized'] < peer['bound']
        # The aggregate lost to the mixture here, and that is a property of
        # the BOUNDED loss rather than a defect: min(1, IS/scale) is not
        # convex, so once several awake forecasts saturate, averaging
        # endpoints can land outside the capped average of their scores.
        # Reported rather than papered over -- a reader who found the totals
        # crossed with no explanation would conclude the code was wrong.
        assert r['saturated_rounds'] > 0
        assert r['aggregate_loss'] > r['mixture_loss']
        # A quantity nothing has forecast has no regret to report.
        assert est.regret('other') is None

    def test_jensen_holds_where_nothing_saturates(self):
        # The inversion above is entirely the ceiling's doing. Where no awake
        # forecast saturates, the aggregate's loss is at most the mixture's,
        # which is the Jensen step the combine() guarantee rests on.
        est = _estimator()
        for t, y in enumerate([5.0, 5.2, 4.9, 5.1]):
            now = float(t)
            # A covers tightly; B's box is offset just enough to MISS low
            # every round, which is what makes the score strictly convex here
            # and the inequality strict. Two narrow boxes both covering
            # satisfy Jensen with EQUALITY, and then floating-point noise
            # decides the comparison -- which is no test at all.
            _forecast(est, 'F', 'A', y - 0.5, y + 0.5, now)
            _forecast(est, 'F', 'B', y + 0.2, y + 1.2, now)
            est.resolve('q', y, now + 0.5)
        r = est.regret('q')
        assert r['saturated_rounds'] == 0
        assert r['mixture_loss'] == pytest.approx(0.97712523010436758)
        assert r['aggregate_loss'] == pytest.approx(0.40000000000000002)
        assert r['aggregate_loss'] < r['mixture_loss']
