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
"""Physical consistency as a pre-statistical falsification layer (R+D.md §12.2).

The C twin's suite is ``src/c/test/physics_test.c`` and the cross-runtime pin
is the ``physics`` conformance protocol; this file covers the Python side and
the parts that only exist here (the ``$AT_PHYSICS`` loader and the wiring into
``score_task_result``).
"""

import json

import pytest

from autonomous_trust.core.physics import (
    CLEARED, IMPLICATED, IMPLICATED_SCORE, REFUTED, REFUTED_SCORE,
    PhysicsChecker, PhysicsDeclarationError, UnitError, diagnose,
    load_physics, minimal_hitting_sets, parse_physics, parse_unit,
    same_dimension)
from autonomous_trust.core.reputation import (TX_CHANNEL_PHYSICAL,
                                              TX_CHANNEL_SWARM_DISAGREEMENT)

DECLARATION = {
    'version': 1,
    'window_sec': 60.0,
    'quantities': {
        'sat.solar-power': {'capability': 'sat.solar', 'unit': 'W',
                            'min': 0.0, 'max': 2000.0, 'tolerance': 5.0,
                            'max_rate': 250.0},
        'sat.load-power': {'capability': 'sat.load', 'unit': 'W',
                           'min': 0.0, 'max': 2000.0},
        'sat.batt-rate': {'capability': 'sat.batt', 'unit': 'W',
                          'min': -2000.0, 'max': 2000.0},
        'sat.bus-temp': {'capability': 'sat.temp', 'unit': 'degC',
                         'min': -80.0, 'max': 120.0, 'max_rate': 2.0,
                         'tolerance': 1.0},
        'sat.position': {'capability': 'sat.pos', 'unit': 'm',
                         'components': 3, 'max_rate': 8000.0,
                         'max_accel': 50.0},
    },
    'relations': [
        {'name': 'power-balance',
         'terms': {'sat.solar-power': 1.0, 'sat.load-power': -1.0,
                   'sat.batt-rate': -1.0},
         'constant': 0.0, 'tolerance': 2.0, 'window_sec': 5.0},
    ],
}


@pytest.fixture
def checker():
    return PhysicsChecker(parse_physics(DECLARATION))


class TestUnits:
    """The axioms. physics.json says which quantity a capability reports; it
    never gets to say what a newton is, because an operator who could redefine
    the units could refute any peer by declaration."""

    @pytest.mark.parametrize('text,exponents', [
        ('m/s', (1, 0, -1, 0, 0, 0, 0)),
        ('kg*m/s^2', (1, 1, -2, 0, 0, 0, 0)),
        ('ug/m3', (-3, 1, 0, 0, 0, 0, 0)),   # m3 is m^3: no symbol ends in a digit
        ('1/s', (0, 0, -1, 0, 0, 0, 0)),
        ('', (0, 0, 0, 0, 0, 0, 0)),
        ('W', (2, 1, -3, 0, 0, 0, 0)),
    ])
    def test_grammar(self, text, exponents):
        assert parse_unit(text).exponents == exponents

    def test_dimensional_equality_ignores_scale(self):
        assert same_dimension('N', 'kg*m/s^2')
        assert same_dimension('W', 'J/s')
        # A prefix is a conversion, not a different dimension.
        assert same_dimension('km', 'm')
        assert parse_unit('km').to_si(2) == 2000.0
        assert not same_dimension('W', 'kg')

    def test_affine_units_convert_but_only_whole(self):
        assert parse_unit('degC').to_si(20) == pytest.approx(293.15)
        assert parse_unit('degF').to_si(32) == pytest.approx(273.15)
        assert parse_unit('degF').to_si(212) == pytest.approx(373.15)
        # Refused inside a compound expression: the offset does not distribute,
        # and dropping it silently would turn 20 degC into 20 K.
        with pytest.raises(UnitError, match='affine'):
            parse_unit('degC/s')

    def test_unknown_symbol_is_refused_not_guessed(self):
        with pytest.raises(UnitError, match='unknown symbol'):
            parse_unit('furlong')
        # Case-sensitive, as SI is: T is the tesla, t the tonne.
        assert not same_dimension('T', 't')
        # C is the coulomb; Celsius is degC.
        assert same_dimension('C', 'A*s')


class TestDeclaration:
    def test_bounds_convert_to_si_once(self):
        model = parse_physics(DECLARATION)
        temp = model.quantities['sat.bus-temp']
        assert temp.si_minimum == pytest.approx(193.15)
        assert temp.si_maximum == pytest.approx(393.15)
        # A rate is a difference per second: the offset cancels, or every
        # Celsius rate bound would gain 273.15 K/s.
        assert temp.si_max_rate == pytest.approx(2.0)
        assert temp.si_tolerance == pytest.approx(1.0)

    def test_relation_terms_must_share_a_dimension(self):
        bad = {'quantities': {'p': {'capability': 'c.p', 'unit': 'W'},
                              'k': {'capability': 'c.k', 'unit': 'K'}},
               'relations': [{'name': 'nonsense',
                              'terms': {'p': 1.0, 'k': 1.0}}]}
        with pytest.raises(PhysicsDeclarationError,
                           match='must share one dimension'):
            parse_physics(bad)

    def test_relation_terms_must_be_scalar(self):
        bad = {'quantities': {'a': {'capability': 'c.a', 'unit': 'm',
                                    'components': 3},
                              'b': {'capability': 'c.b', 'unit': 'm'}},
               'relations': [{'name': 'r', 'terms': {'a': 1.0, 'b': -1.0}}]}
        with pytest.raises(PhysicsDeclarationError, match='scalar quantities'):
            parse_physics(bad)

    @pytest.mark.parametrize('spec,match', [
        ({'quantities': {'a': {'unit': 'W'}}}, 'capability'),
        ({'quantities': {'a': {'capability': 'c', 'unit': 'W'},
                         'b': {'capability': 'c', 'unit': 'W'}}},
         'already reported'),
        ({'quantities': {'a': {'capability': 'c', 'unit': 'furlong'}}},
         'unknown symbol'),
        ({'quantities': {'a': {'capability': 'c', 'unit': 'W'}},
          'relations': [{'name': 'r', 'terms': {'missing': 1.0}}]},
         'undeclared quantity'),
        ({'quantities': {'a': {'capability': 'c', 'unit': 'W',
                               'min': 10, 'max': 1}}}, 'exceeds'),
    ])
    def test_malformed_declarations_are_refused(self, spec, match):
        with pytest.raises(PhysicsDeclarationError, match=match):
            parse_physics(spec)

    def test_unset_env_yields_the_empty_model(self, monkeypatch):
        # The layer is OPT-IN: a physical refutation is the hardest evidence
        # AT produces, and guessing at undeclared quantities would manufacture
        # it. See also test_score_task_result_is_inert_by_default.
        monkeypatch.delenv('AT_PHYSICS', raising=False)
        assert load_physics().empty

    def test_configured_path_that_does_not_parse_raises(self, tmp_path,
                                                        monkeypatch):
        # Never degrade silently to "check nothing": an operator who
        # configured the layer believes the claims are being verified.
        path = tmp_path / 'physics.json'
        path.write_text('{"quantities": {"a": {"capability": "c",'
                        ' "unit": "furlong"}}}')
        monkeypatch.setenv('AT_PHYSICS', str(path))
        with pytest.raises(PhysicsDeclarationError):
            load_physics()
        monkeypatch.setenv('AT_PHYSICS', str(tmp_path / 'absent.json'))
        with pytest.raises(PhysicsDeclarationError, match='not a file'):
            load_physics()

    def test_loads_from_a_file(self, tmp_path, monkeypatch):
        path = tmp_path / 'physics.json'
        path.write_text(json.dumps(DECLARATION))
        monkeypatch.setenv('AT_PHYSICS', str(path))
        model = load_physics()
        assert len(model.quantities) == 5
        assert [r.name for r in model.relations] == ['power-balance']


class TestSingleClaim:
    def test_undeclared_or_absent_says_nothing(self, checker):
        assert checker.check('other.thing', 42, subject='A', now=0.0) is None
        # An absent answer is not a FALSE claim.
        assert checker.check('sat.solar', None, subject='A', now=0.0) is None

    def test_passing_physics_earns_nothing(self, checker):
        # A claim inside the feasible set is merely NOT REFUTED. A good score
        # here would turn a falsification layer into a plausibility grade.
        assert checker.check('sat.solar', 500.0, subject='A', now=0.0) is None

    @pytest.mark.parametrize('result', [
        -5.0,                                   # below the declared minimum
        3000.0,                                 # above the declared maximum
        'lots',                                 # not a quantity at all
        {'value': 500, 'unit': 'kg'},           # kilograms of power
        {'value': 500, 'unit': 'furlong'},      # not in the table
        True,                                   # a bool is not a quantity
    ])
    def test_impossible_claims_are_refuted(self, checker, result):
        assert checker.check('sat.solar', result, subject='A',
                             now=0.0) == (REFUTED_SCORE, TX_CHANNEL_PHYSICAL)

    def test_a_prefix_converts(self, checker):
        # 0.5 kW is 500 W: in bounds, nothing to say.
        assert checker.check('sat.solar', {'value': 0.5, 'unit': 'kW'},
                             subject='A', now=0.0) is None

    def test_rate_is_measured_against_the_peers_own_last_claim(self, checker):
        assert checker.check('sat.temp', 20.0, subject='A', now=100.0) is None
        assert checker.check('sat.temp', 22.0, subject='A', now=101.0) is None
        # 58 degC/s against a declared 2: a conflict of size one, so refuted
        # outright rather than merely implicated.
        assert checker.check('sat.temp', 80.0, subject='A', now=102.0) \
            == (REFUTED_SCORE, TX_CHANNEL_PHYSICAL)

    def test_a_refuted_observation_is_not_stored(self, checker):
        # Load-bearing: the store feeds the conflict machinery, so admitting a
        # claim already known to be impossible would let one liar manufacture
        # conflicts against honest peers. A's latest is still 22, so 23 one
        # second later is a 1 degC/s change -- not the 57 degC/s drop that
        # storing the refuted 80 would have made it.
        checker.check('sat.temp', 20.0, subject='A', now=100.0)
        checker.check('sat.temp', 22.0, subject='A', now=101.0)
        assert checker.check('sat.temp', 80.0, subject='A', now=102.0) is not None
        assert checker.check('sat.temp', 23.0, subject='A', now=103.0) is None

    def test_out_of_order_claims_are_not_a_rate_violation(self, checker):
        # Clock skew and queue reordering are ordinary, and say nothing about
        # a rate.
        checker.check('sat.temp', 20.0, subject='A', now=100.0)
        assert checker.check('sat.temp', 90.0, subject='A', now=99.0) is None

    def test_vector_rate_uses_the_magnitude_bounds_are_componentwise(self, checker):
        assert checker.check('sat.pos', [0.0, 0.0, 0.0], subject='A',
                             now=300.0) is None
        assert checker.check('sat.pos', [1000.0, 0.0, 0.0], subject='A',
                             now=301.0) is None
        assert checker.check('sat.pos', [1e6, 0.0, 0.0], subject='A',
                             now=302.0) == (REFUTED_SCORE, TX_CHANNEL_PHYSICAL)

    def test_wrong_arity_is_refuted(self, checker):
        assert checker.check('sat.pos', [1.0, 2.0], subject='A',
                             now=0.0) == (REFUTED_SCORE, TX_CHANNEL_PHYSICAL)

    def test_unattributed_runs_only_the_identity_free_checks(self, checker):
        # A fan-out is not attributable to one peer. Filing several peers'
        # claims under one key would manufacture conflicts between a peer and
        # itself, so nothing is stored.
        assert checker.check('sat.solar', -5.0, subject=None, now=400.0) \
            == (REFUTED_SCORE, TX_CHANNEL_PHYSICAL)
        assert checker.check('sat.temp', 20.0, subject=None, now=400.0) is None
        assert checker.check('sat.temp', 119.0, subject=None, now=401.0) is None

    def test_a_result_may_name_its_own_quantity(self, checker):
        assert checker.check('anything', {'quantity': 'sat.solar-power',
                                          'value': -5.0},
                             subject='A', now=0.0) \
            == (REFUTED_SCORE, TX_CHANNEL_PHYSICAL)
        # But mislabelling is not an escape hatch: an unknown name falls back
        # to the capability's declaration.
        assert checker.check('sat.solar', {'quantity': 'nope', 'value': -5.0},
                             subject='A', now=1.0) \
            == (REFUTED_SCORE, TX_CHANNEL_PHYSICAL)


class TestDiagnosis:
    def test_minimal_hitting_sets(self):
        assert minimal_hitting_sets([0b1]) == [0b1]
        # {A,B} and {A,C} -> {A} AND {B,C}, subset-minimal, not just the
        # smallest.
        assert sorted(minimal_hitting_sets([0b011, 0b101])) == [0b001, 0b110]
        # A proper superset cannot constrain the answer and is pruned.
        assert sorted(minimal_hitting_sets([0b011, 0b111])) == [0b001, 0b010]
        # Nothing to explain: exactly one hitting set, the empty one.
        assert minimal_hitting_sets([]) == [0]

    def test_enumeration_overflow_narrows_rather_than_guesses(self):
        # Past the cap the verdict degrades to the singleton test, which can
        # turn a REFUTED into an IMPLICATED but never the reverse: an
        # overloaded window costs evidence rather than manufacturing it. The C
        # twin's array is the same size and degrades identically -- without
        # that agreement one runtime would hand back a full diagnosis and the
        # other the narrowed one.
        from autonomous_trust.core.physics.diagnose import MAX_DIAGNOSES
        wide = [[f'p{i}{j}' for j in range(8)] for i in range(8)]
        assert minimal_hitting_sets([sum(1 << (8 * i + j) for j in range(8))
                                     for i in range(8)]) is None
        assert diagnose(wide, 'p00') == IMPLICATED
        # A singleton conflict still refutes, even in the degraded path.
        assert diagnose(wide + [['p00']], 'p00') == REFUTED
        assert MAX_DIAGNOSES == 256

    def test_too_many_conflicts_also_narrows(self):
        from autonomous_trust.core.physics.diagnose import MAX_CONFLICTS
        many = [[f'a{i}', f'b{i}'] for i in range(MAX_CONFLICTS + 1)]
        assert diagnose(many, 'a0') == IMPLICATED
        assert diagnose(many + [['a0']], 'a0') == REFUTED

    @pytest.mark.parametrize('conflicts,subject,verdict', [
        ([['A']], 'A', REFUTED),
        ([['A', 'B']], 'A', IMPLICATED),
        ([['A', 'B'], ['A']], 'A', REFUTED),
        ([['A', 'B'], ['A']], 'B', CLEARED),
        ([['A', 'B'], ['A', 'C']], 'A', IMPLICATED),
        ([['B', 'C']], 'A', CLEARED),
        ([], 'A', CLEARED),
    ])
    def test_verdicts(self, conflicts, subject, verdict):
        assert diagnose(conflicts, subject) == verdict

    def test_disagreeing_peers_are_implicated_never_refuted(self, checker):
        # One of them is wrong and the physics does not say which. Refuting
        # both would let any peer refute an honest one by lying about the same
        # quantity.
        assert checker.check('sat.temp', 20.0, subject='A', now=100.0) is None
        assert checker.check('sat.temp', 60.0, subject='B', now=101.0) \
            == (IMPLICATED_SCORE, TX_CHANNEL_SWARM_DISAGREEMENT)

    def test_a_lone_outlier_against_two_is_still_only_implicated(self, checker):
        # The subset-minimal choice, where it bites. Conflicts {C,A} and {C,B}
        # have minimal diagnoses {C} AND {A,B}; preferring the smaller would
        # convict C, which is majority rule wearing physics' clothes. R+D.md
        # §12.8: a majority is not an oracle.
        checker.check('sat.temp', 20.0, subject='A', now=100.0)
        checker.check('sat.temp', 20.5, subject='B', now=101.0)
        assert checker.check('sat.temp', 90.0, subject='C', now=102.0) \
            == (IMPLICATED_SCORE, TX_CHANNEL_SWARM_DISAGREEMENT)

    def test_zero_tolerance_disables_the_intersection(self, checker):
        # A zero-width interval would make every distinct float a conflict and
        # report two honest sensors of the same thing.
        checker.check('sat.load', 400.0, subject='A', now=100.0)
        assert checker.check('sat.load', 1200.0, subject='B', now=101.0) is None

    def test_stale_observations_do_not_conflict(self, checker):
        # Peers legitimately disagree about a quantity that has moved on.
        checker.check('sat.temp', 20.0, subject='A', now=100.0)
        assert checker.check('sat.temp', 90.0, subject='B', now=400.0) is None


class TestParityRelations:
    def test_a_violated_residual_conflicts_every_contributor(self, checker):
        # 1000 - 400 - 600 balances; 1000 - 400 - 100 does not. The conflict is
        # all three, so each is only implicated: a violated conservation law
        # does not say which term was the lie.
        assert checker.check('sat.solar', 1000.0, subject='A', now=200.0) is None
        assert checker.check('sat.load', 400.0, subject='B', now=200.0) is None
        assert checker.check('sat.batt', 600.0, subject='C', now=200.0) is None
        assert checker.check('sat.batt', 100.0, subject='C', now=201.0) \
            == (IMPLICATED_SCORE, TX_CHANNEL_SWARM_DISAGREEMENT)

    def test_one_peer_supplying_every_term_refutes_itself(self, checker):
        # A conflict of size one: the peer contradicted itself and there is no
        # other story. Nothing about the arithmetic changed -- only who was
        # standing behind it.
        checker.check('sat.solar', 1000.0, subject='S', now=200.0)
        checker.check('sat.load', 400.0, subject='S', now=200.0)
        assert checker.check('sat.batt', 100.0, subject='S', now=200.0) \
            == (REFUTED_SCORE, TX_CHANNEL_PHYSICAL)

    def test_incomplete_or_stale_residuals_are_not_evaluated(self, checker):
        # Evaluating over missing or stale terms invents violations out of
        # ordinary change. The relation's own window is 5 s.
        assert checker.check('sat.solar', 1000.0, subject='A', now=200.0) is None
        checker.check('sat.load', 400.0, subject='B', now=200.0)
        assert checker.check('sat.batt', 100.0, subject='C', now=300.0) is None


class TestScorerWiring:
    """The layer as ``score_task_result`` reaches it."""

    @pytest.fixture(autouse=True)
    def _zkp_absent(self, monkeypatch):
        """Pin the ambient ZKP flag so these tests assert the arm they mean.

        ``ZKP_AVAILABLE`` is a fact about the installation, not about the
        result: with the extension unbuilt a missing proof cannot attest
        anything and completion is the honest score, while with it built a
        missing proof is suspicious and scores 0.3 on `certificate`. Every
        fall-through assertion below means the first, so it says so -- left
        unpinned they pass only where the Rust extension is absent. Same
        reason as ``test_probe_verification.py``'s pair.
        """
        monkeypatch.setattr(
            'autonomous_trust.core._python.automate.ZKP_AVAILABLE', False)

    @staticmethod
    def _result(capability, value, executor='peer-1'):
        from autonomous_trust.core.negotiation import TaskResult
        tr = TaskResult(None, value, requestor=None,
                        requested_capability_name=capability,
                        requested_kwargs={})
        tr.executor_uuid = executor
        return tr

    def test_inert_by_default(self, monkeypatch):
        # With no declaration configured the existing arms are untouched --
        # which is what keeps this change invisible to every scenario that has
        # not opted in.
        from autonomous_trust.core import automate
        monkeypatch.setattr(automate, '_PHYSICS', None)
        monkeypatch.delenv('AT_PHYSICS', raising=False)
        assert not automate.physics_checker().enabled
        assert automate.score_task_result(
            self._result('sat.solar', -5.0)) == (0.8, 'task_outcome')

    def test_a_refutation_beats_the_completion_arm(self):
        from autonomous_trust.core.automate import score_task_result
        checker = PhysicsChecker(parse_physics(DECLARATION))
        # Without physics this is a completed task worth 0.8; with it, an
        # impossible claim worth 0.1 on a channel that says why.
        assert score_task_result(self._result('sat.solar', -5.0),
                                 physics=checker, now_sec=0.0) \
            == (REFUTED_SCORE, TX_CHANNEL_PHYSICAL)

    def test_a_probe_verdict_still_comes_first(self):
        # A known answer strictly subsumes asking whether the answer is
        # possible, so the probe arm keeps its precedence.
        from autonomous_trust.core.automate import score_task_result
        checker = PhysicsChecker(parse_physics(DECLARATION))
        tr = self._result('at.handshake', 42)
        tr.requested_kwargs = {'nonce': 41}
        assert score_task_result(tr, physics=checker, now_sec=0.0) \
            == (0.9, 'probe')

    def test_a_surviving_claim_falls_through_unchanged(self):
        from autonomous_trust.core.automate import score_task_result
        checker = PhysicsChecker(parse_physics(DECLARATION))
        assert score_task_result(self._result('sat.solar', 500.0),
                                 physics=checker, now_sec=0.0) \
            == (0.8, 'task_outcome')

    def test_a_bad_declaration_leaves_the_layer_off_not_the_scorer_broken(
            self, tmp_path, monkeypatch):
        from autonomous_trust.core import automate
        path = tmp_path / 'physics.json'
        path.write_text('{"quantities": {"a": {"capability": "c",'
                        ' "unit": "furlong"}}}')
        monkeypatch.setenv('AT_PHYSICS', str(path))
        monkeypatch.setattr(automate, '_PHYSICS', None)
        assert not automate.physics_checker().enabled
        assert automate.score_task_result(
            self._result('sat.solar', -5.0)) == (0.8, 'task_outcome')
