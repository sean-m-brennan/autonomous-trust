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
"""Certificate-carrying task interfaces (R+D.md §12.3).

The C twin's suite is ``src/c/test/certificates_test.c`` and the cross-runtime
pin is the ``certificate`` conformance protocol; this covers the Python side
and the parts that exist only here (the ``$AT_CERTIFICATES`` loader, the
``Certified`` wrapper and the wiring into ``score_task_result``).
"""

import json

import pytest

from autonomous_trust.core.certificates import (
    ABSENT_SCORE, CERTIFIED, CHECKER_KINDS, CHECKERS, INVALID_SCORE, OPTIONAL,
    UNCERTIFIABLE, UNEXAMINED, VALID_SCORE, CertificateDeclarationError,
    CertificateVerifier, Certified, DratError, SplitMix64, build_inventory,
    check_refutation, format_inventory, load_certificates, parse_certificates,
    split_certified, summarise)
from autonomous_trust.core.reputation import TX_CHANNEL_CERTIFICATE

DECLARATION = {
    'version': 1,
    'capabilities': {
        'd.matmul': {'checker': 'matrix_product', 'repetitions': 4},
        'd.solve': {'checker': 'linear_solve'},
        'd.lp': {'checker': 'lp', 'tolerance': 1e-6},
        'd.sat': {'checker': 'sat'},
        'd.route': {'checker': 'path'},
        'd.flow': {'checker': 'flow'},
        'd.sched': {'checker': 'schedule'},
        'd.filter': {'checker': 'state_estimation', 'max_lag': 3, 'bound': 0.5},
        'd.opinion': {'checker': None, 'note': 'a judgement call'},
        'd.migrating': {'checker': 'sat', 'required': False},
    },
}

MATMUL = {'a': [[1, 2], [3, 4]], 'b': [[5, 6], [7, 8]]}
PRODUCT = [[19, 22], [43, 50]]
LP = {'a': [[1, 1]], 'b': [2], 'c': [1, 1]}
ROUTE = {'edges': [['s', 'a', 1], ['a', 't', 1], ['s', 't', 5]],
         'source': 's', 'target': 't'}
POTENTIAL = {'potential': {'s': 0, 'a': 1, 't': 2}}
FLOW_IN = {'edges': [['s', 'a', 3], ['a', 't', 2], ['s', 't', 1]],
           'source': 's', 'sink': 't'}
SCHED = {'jobs': [{'id': 'x', 'duration': 2}, {'id': 'y', 'duration': 3}],
         'precedences': [['x', 'y']], 'capacity': 1}


@pytest.fixture
def verifier():
    return CertificateVerifier(parse_certificates(DECLARATION))


def _ev(verifier, cap, answer, cert=None, kw=None, seed=7):
    return verifier.evaluate(cap, answer, cert, kw, seed)[0]


class TestRegistry:
    def test_every_declared_kind_has_a_checker(self):
        # A kind in the closed set with no implementation would fail at the
        # first task result that needed it, in production, on the requestor
        # side -- long after the declaration was written.
        assert set(CHECKERS) == set(CHECKER_KINDS)
        assert len(CHECKER_KINDS) == 8

    def test_splitmix64_matches_the_reference_stream(self):
        # Pinned because the C twin must emit the same stream: a Freivalds
        # challenge that differs between runtimes is a verdict that differs.
        assert SplitMix64(42).next_u64() == 13679457532755275413
        assert [SplitMix64(0).next_u64() for _ in range(1)] == [16294208416658607535]


class TestDeclaration:
    def test_three_declared_states_are_distinguishable(self):
        model = parse_certificates(DECLARATION)
        assert model.capabilities['d.lp'].certifiable
        assert not model.capabilities['d.opinion'].certifiable
        assert model.for_capability('d.nothing') is None

    def test_unknown_checker_is_refused_not_treated_as_uncertifiable(self):
        # The important one: a typo must not quietly turn a certified
        # capability into an unchecked one, which is what `null` means and is
        # indistinguishable from it downstream.
        with pytest.raises(CertificateDeclarationError, match='unknown checker'):
            parse_certificates({'capabilities': {'a': {'checker': 'matrix-product'}}})

    @pytest.mark.parametrize('spec,match', [
        ({'capabilities': {'a': {'checker': 'lp', 'tolerance': -1}}}, 'tolerance'),
        ({'capabilities': {'a': {'checker': 'lp', 'repetitions': 0}}}, 'repetitions'),
        ({'capabilities': {'a': {'checker': 'lp', 'required': 'yes'}}}, 'required'),
        ({'version': 2, 'capabilities': {}}, 'version'),
    ])
    def test_malformed_declarations_are_refused(self, spec, match):
        with pytest.raises(CertificateDeclarationError, match=match):
            parse_certificates(spec)

    def test_unset_env_is_the_empty_model(self, monkeypatch):
        monkeypatch.delenv('AT_CERTIFICATES', raising=False)
        assert load_certificates().empty

    def test_configured_but_broken_raises(self, tmp_path, monkeypatch):
        path = tmp_path / 'certificates.json'
        path.write_text('{"capabilities": {"a": {"checker": "nope"}}}')
        monkeypatch.setenv('AT_CERTIFICATES', str(path))
        with pytest.raises(CertificateDeclarationError):
            load_certificates()

    def test_loads_from_a_file(self, tmp_path, monkeypatch):
        path = tmp_path / 'certificates.json'
        path.write_text(json.dumps(DECLARATION))
        monkeypatch.setenv('AT_CERTIFICATES', str(path))
        assert len(load_certificates().capabilities) == 10


class TestMatrixProduct:
    def test_correct_product_passes_every_round(self, verifier):
        assert _ev(verifier, 'd.matmul', PRODUCT, {}, MATMUL) == 'valid'

    def test_a_single_wrong_entry_is_caught(self, verifier):
        assert _ev(verifier, 'd.matmul', [[19, 22], [43, 51]], {}, MATMUL) == 'invalid'

    def test_wrong_shape_is_invalid(self, verifier):
        assert _ev(verifier, 'd.matmul', [[19, 22]], {}, MATMUL) == 'invalid'

    def test_our_missing_inputs_never_score_the_peer(self, verifier):
        # The fault is on this side; scoring it would punish a peer for our
        # own lost record.
        assert _ev(verifier, 'd.matmul', PRODUCT, {}, {}) == 'indeterminate'

    def test_the_challenge_is_the_verifiers_not_the_provers(self, verifier):
        # Freivalds is sound only while the peer cannot predict the draw. Two
        # seeds must be able to disagree about a wrong answer -- if they never
        # did, the "randomness" would be doing nothing.
        wrong = [[19, 22], [43, 50.0000001]]
        verdicts = {verifier.evaluate('d.matmul', wrong, {}, MATMUL, s)[0]
                    for s in range(24)}
        assert 'invalid' in verdicts


class TestLinearSolve:
    def test_exact_solution(self, verifier):
        assert _ev(verifier, 'd.solve', [1.0, 1.0], {},
                   {'a': [[2, 1], [1, 3]], 'b': [3, 4]}) == 'valid'

    def test_wrong_solution(self, verifier):
        assert _ev(verifier, 'd.solve', [1.0, 2.0], {},
                   {'a': [[2, 1], [1, 3]], 'b': [3, 4]}) == 'invalid'


class TestLinearProgramming:
    def test_optimal_with_dual(self, verifier):
        assert _ev(verifier, 'd.lp', {'x': [2.0, 0.0]}, {'dual': [1.0]}, LP) == 'valid'

    def test_feasible_but_suboptimal_fails_the_duality_gap(self, verifier):
        # The check that makes the dual worth carrying: the answer is entirely
        # feasible, and only the gap reveals it is not optimal.
        assert _ev(verifier, 'd.lp', {'x': [3.0, 0.0]}, {'dual': [1.0]}, LP) == 'invalid'

    def test_infeasible_primal(self, verifier):
        assert _ev(verifier, 'd.lp', {'x': [0.0, 0.0]}, {'dual': [1.0]}, LP) == 'invalid'

    def test_optimality_without_a_dual_is_absent(self, verifier):
        assert _ev(verifier, 'd.lp', {'x': [2.0, 0.0]}, None, LP) == 'absent'

    def test_farkas_certifies_infeasibility(self, verifier):
        # The one claim with no answer to inspect: "there is no solution".
        assert _ev(verifier, 'd.lp', {'infeasible': True}, {'farkas': [1.0]},
                   {'a': [[-1]], 'b': [1], 'c': [1]}) == 'valid'

    def test_a_farkas_vector_that_proves_nothing(self, verifier):
        assert _ev(verifier, 'd.lp', {'infeasible': True}, {'farkas': [1.0]},
                   {'a': [[1]], 'b': [1], 'c': [1]}) == 'invalid'


class TestSat:
    CNF = [[1, 2], [-1, 2], [1, -2]]

    def test_assignment_satisfies(self, verifier):
        assert _ev(verifier, 'd.sat', {'sat': True}, {'assignment': [1, 2]},
                   {'cnf': self.CNF}) == 'valid'

    def test_assignment_leaving_a_clause_unsatisfied(self, verifier):
        assert _ev(verifier, 'd.sat', {'sat': True}, {'assignment': [-1, -2]},
                   {'cnf': self.CNF}) == 'invalid'

    def test_contradictory_assignment(self, verifier):
        assert _ev(verifier, 'd.sat', {'sat': True}, {'assignment': [1, -1]},
                   {'cnf': self.CNF}) == 'invalid'

    def test_unsat_needs_a_refutation(self, verifier):
        # "I searched and found nothing" is the claim a lying peer makes for
        # free, and is exactly what DRAT exists to make expensive.
        assert _ev(verifier, 'd.sat', {'sat': False}, {},
                   {'cnf': [[1], [-1]]}) == 'absent'

    def test_valid_refutation(self, verifier):
        assert _ev(verifier, 'd.sat', {'sat': False}, {'proof': [[]]},
                   {'cnf': [[1], [-1]]}) == 'valid'

    def test_refutation_of_a_satisfiable_formula_fails(self, verifier):
        assert _ev(verifier, 'd.sat', {'sat': False}, {'proof': [[]]},
                   {'cnf': self.CNF}) == 'invalid'


class TestDrat:
    def test_multi_step_refutation(self):
        formula = [[1, 2], [-1, 2], [1, -2], [-1, -2]]
        assert check_refutation(formula, [[2], [-2], []])[0]

    def test_sound_lemmas_that_never_reach_the_empty_clause(self):
        # The single most important DRAT check: a proof of true things that
        # proves nothing about satisfiability must not be accepted.
        formula = [[1, 2], [-1, 2], [1, -2], [-1, -2]]
        ok, reason = check_refutation(formula, [[2]])
        assert not ok and 'empty clause' in reason

    def test_a_lemma_that_is_neither_rup_nor_rat(self):
        assert not check_refutation([[1, 2], [-1, -2]], [[1], []])[0]

    def test_rat_admits_a_fresh_pivot(self):
        # A literal on a variable nothing else mentions is RAT vacuously; this
        # is the clause-addition step plain implication would reject.
        from autonomous_trust.core.certificates import is_rat, is_rup
        assert is_rat([[1, 2]], [3])
        assert not is_rup([[1, 2]], [3])

    def test_deletion_removes_only_one_match(self):
        # Deleting every duplicate would strip clauses the proof still needs.
        formula = [[1], [1], [-1]]
        assert check_refutation(formula, [{'d': [1]}, []])[0]

    def test_malformed_proofs_raise_rather_than_return(self):
        with pytest.raises(DratError):
            check_refutation([[1]], [[0]])
        with pytest.raises(DratError):
            check_refutation([[1]], [[]], max_proof_len=0)


class TestPath:
    def test_shortest_path_with_a_feasible_potential(self, verifier):
        assert _ev(verifier, 'd.route', {'path': ['s', 'a', 't']}, POTENTIAL,
                   ROUTE) == 'valid'

    def test_a_detour_cannot_claim_optimality(self, verifier):
        assert _ev(verifier, 'd.route', {'path': ['s', 't']}, POTENTIAL,
                   ROUTE) == 'invalid'

    def test_an_infeasible_potential_is_rejected(self, verifier):
        # Without this the "lower bound" would be whatever the peer says, and
        # a detour could certify itself.
        assert _ev(verifier, 'd.route', {'path': ['s', 't']},
                   {'potential': {'s': 0, 'a': 1, 't': 9}}, ROUTE) == 'invalid'

    def test_a_bare_asserted_bound_is_not_a_witness(self, verifier):
        assert _ev(verifier, 'd.route', {'path': ['s', 't']},
                   {'lower_bound': 5}, ROUTE) == 'invalid'

    def test_a_path_using_an_edge_that_does_not_exist(self, verifier):
        assert _ev(verifier, 'd.route', {'path': ['s', 'x', 't']}, POTENTIAL,
                   ROUTE) == 'invalid'

    def test_wrong_endpoints(self, verifier):
        assert _ev(verifier, 'd.route', {'path': ['a', 't']}, POTENTIAL,
                   ROUTE) == 'invalid'


class TestFlow:
    def test_max_flow_with_a_matching_cut(self, verifier):
        answer = {'flow': [['s', 'a', 2], ['a', 't', 2], ['s', 't', 1]],
                  'value': 3}
        assert _ev(verifier, 'd.flow', answer, {'cut': ['s', 'a']},
                   FLOW_IN) == 'valid'

    def test_conservation_is_checked(self, verifier):
        answer = {'flow': [['s', 'a', 3], ['a', 't', 2], ['s', 't', 1]]}
        assert _ev(verifier, 'd.flow', answer, {'cut': ['s', 'a']},
                   FLOW_IN) == 'invalid'

    def test_capacity_is_checked(self, verifier):
        answer = {'flow': [['s', 'a', 9], ['a', 't', 9], ['s', 't', 1]]}
        assert _ev(verifier, 'd.flow', answer, {'cut': ['s', 'a']},
                   FLOW_IN) == 'invalid'

    def test_a_feasible_but_submaximal_flow_fails_the_cut(self, verifier):
        # Feasibility alone certifies only that the peer returned *a* flow.
        answer = {'flow': [['s', 'a', 1], ['a', 't', 1]]}
        assert _ev(verifier, 'd.flow', answer, {'cut': ['s', 'a']},
                   FLOW_IN) == 'invalid'

    def test_a_cut_on_the_wrong_side(self, verifier):
        answer = {'flow': [['s', 'a', 2], ['a', 't', 2], ['s', 't', 1]],
                  'value': 3}
        assert _ev(verifier, 'd.flow', answer, {'cut': ['s', 'a', 't']},
                   FLOW_IN) == 'invalid'


class TestSchedule:
    def test_feasible_schedule(self, verifier):
        assert _ev(verifier, 'd.sched', {'start': {'x': 0, 'y': 2}},
                   {'makespan': 5}, SCHED) == 'valid'

    def test_precedence_violation(self, verifier):
        assert _ev(verifier, 'd.sched', {'start': {'x': 0, 'y': 1}},
                   {'makespan': 4}, SCHED) == 'invalid'

    def test_under_reported_makespan(self, verifier):
        # Claiming a better schedule than the one produced is the failure mode
        # worth catching, and it is invisible without checking the claim.
        assert _ev(verifier, 'd.sched', {'start': {'x': 0, 'y': 2}},
                   {'makespan': 3}, SCHED) == 'invalid'

    def test_capacity_violation(self, verifier):
        jobs = {'jobs': SCHED['jobs'], 'capacity': 1}
        assert _ev(verifier, 'd.sched', {'start': {'x': 0, 'y': 0}},
                   {'makespan': 3}, jobs) == 'invalid'

    def test_deadline_is_honoured_when_declared(self, verifier):
        late = dict(SCHED, deadline=4)
        assert _ev(verifier, 'd.sched', {'start': {'x': 0, 'y': 2}},
                   {'makespan': 5}, late) == 'invalid'


class TestStateEstimation:
    def test_a_white_sequence_passes(self, verifier):
        rng = SplitMix64(2026)
        seq = [(rng.next_u64() % 2001) / 1000.0 - 1.0 for _ in range(200)]
        assert _ev(verifier, 'd.filter', {'innovations': seq}, {}, {}) == 'valid'

    def test_a_drifting_sequence_fails(self, verifier):
        seq = [i * 0.01 for i in range(200)]
        assert _ev(verifier, 'd.filter', {'innovations': seq}, {}, {}) == 'invalid'

    def test_a_constant_sequence_has_no_spectrum(self, verifier):
        assert _ev(verifier, 'd.filter', {'innovations': [2] * 40}, {},
                   {}) == 'indeterminate'

    def test_too_short_to_test(self, verifier):
        assert _ev(verifier, 'd.filter', {'innovations': [1, 2, 3]}, {},
                   {}) == 'indeterminate'


class TestDeclaredStates:
    def test_uncertifiable_produces_no_verdict(self, verifier):
        assert _ev(verifier, 'd.opinion', 'anything') == 'none'

    def test_undeclared_produces_no_verdict(self, verifier):
        assert _ev(verifier, 'd.unknown', 'anything') == 'none'

    def test_optional_witness_may_be_absent(self, verifier):
        assert _ev(verifier, 'd.migrating', {'sat': True}, None,
                   {'cnf': [[1]]}) == 'none'

    def test_optional_witness_is_still_checked_when_present(self, verifier):
        assert _ev(verifier, 'd.migrating', {'sat': True},
                   {'assignment': [-1]}, {'cnf': [[1]]}) == 'invalid'


class TestInventory:
    def test_four_states_are_separated(self):
        model = parse_certificates(DECLARATION)
        rows = build_inventory(model, ['d.matmul', 'at.handshake'])
        by_name = {r.capability: r for r in rows}
        assert by_name['d.lp'].state == CERTIFIED
        assert by_name['d.migrating'].state == OPTIONAL
        assert by_name['d.opinion'].state == UNCERTIFIABLE
        # The state the inventory exists for: registered here, never
        # considered by anyone.
        assert by_name['at.handshake'].state == UNEXAMINED

    def test_worst_known_first(self):
        rows = build_inventory(parse_certificates(DECLARATION), ['zz.unknown'])
        assert rows[0].state == UNEXAMINED

    def test_summary_counts_every_state_including_empty_ones(self):
        counts = summarise(build_inventory(parse_certificates(DECLARATION)))
        assert counts[UNEXAMINED] == 0
        assert counts[UNCERTIFIABLE] == 1
        assert counts[CERTIFIED] == 8

    def test_report_is_self_diagnosing(self):
        text = format_inventory(build_inventory(
            parse_certificates(DECLARATION), ['zz.unknown']))
        assert 'never examined' in text
        assert 'a judgement call' in text          # the note travels
        assert 'not mentioned in the declaration' in text


class TestScorerWiring:
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
    def _result(capability, value, certificate=None, kwargs=None):
        from autonomous_trust.core.negotiation import TaskResult
        tr = TaskResult(None, value, requestor=None,
                        requested_capability_name=capability,
                        requested_kwargs=kwargs or {})
        tr.certificate = certificate
        tr.executor_uuid = 'peer-1'
        return tr

    def test_inert_by_default(self, monkeypatch):
        from autonomous_trust.core import automate
        monkeypatch.setattr(automate, '_CERTIFICATES', None)
        monkeypatch.delenv('AT_CERTIFICATES', raising=False)
        assert not automate.certificate_verifier().enabled
        assert automate.score_task_result(
            self._result('d.matmul', PRODUCT, None, MATMUL)) == (0.8, 'task_outcome')

    def test_a_verified_witness_earns_more_than_completion(self, verifier):
        from autonomous_trust.core.automate import score_task_result
        assert score_task_result(self._result('d.matmul', PRODUCT, None, MATMUL),
                                 certificates=verifier, seed=7) \
            == (VALID_SCORE, TX_CHANNEL_CERTIFICATE)

    def test_a_failed_witness_is_a_defection(self, verifier):
        from autonomous_trust.core.automate import score_task_result
        assert score_task_result(
            self._result('d.matmul', [[19, 22], [43, 51]], None, MATMUL),
            certificates=verifier, seed=7) == (INVALID_SCORE, TX_CHANNEL_CERTIFICATE)

    def test_a_required_witness_that_never_arrived(self, verifier):
        from autonomous_trust.core.automate import score_task_result
        assert score_task_result(self._result('d.lp', {'x': [2.0, 0.0]}, None, LP),
                                 certificates=verifier, seed=7) \
            == (ABSENT_SCORE, TX_CHANNEL_CERTIFICATE)

    def test_an_uncertifiable_capability_falls_through(self, verifier):
        from autonomous_trust.core.automate import score_task_result
        assert score_task_result(self._result('d.opinion', 'yes'),
                                 certificates=verifier, seed=7) \
            == (0.8, 'task_outcome')

    def test_a_probe_verdict_still_outranks_a_certificate(self, verifier):
        from autonomous_trust.core.automate import score_task_result
        tr = self._result('at.handshake', 42)
        tr.requested_kwargs = {'nonce': 41}
        assert score_task_result(tr, certificates=verifier, seed=7) == (0.9, 'probe')

    def test_our_own_missing_inputs_do_not_score_the_peer(self, verifier):
        from autonomous_trust.core.automate import score_task_result
        assert score_task_result(self._result('d.matmul', PRODUCT, None, {}),
                                 certificates=verifier, seed=7) \
            == (0.8, 'task_outcome')

    def test_a_bad_declaration_leaves_the_layer_off(self, tmp_path, monkeypatch):
        from autonomous_trust.core import automate
        path = tmp_path / 'certificates.json'
        path.write_text('{"capabilities": {"a": {"checker": "nope"}}}')
        monkeypatch.setenv('AT_CERTIFICATES', str(path))
        monkeypatch.setattr(automate, '_CERTIFICATES', None)
        assert not automate.certificate_verifier().enabled


class TestCertifiedWrapper:
    def test_splits_answer_from_witness(self):
        assert split_certified(Certified(5, {'dual': [1]})) == (5, {'dual': [1]})

    def test_a_bare_answer_has_no_witness(self):
        assert split_certified({'value': 5}) == ({'value': 5}, None)

    def test_the_wire_carries_the_two_apart(self):
        from autonomous_trust.core.config import from_json_string, to_json_string
        from autonomous_trust.core.negotiation import TaskResult
        tr = TaskResult(None, {'x': [2.0]}, requestor=None,
                        certificate={'dual': [1.0]})
        back = from_json_string(to_json_string(tr))
        assert back.result == {'x': [2.0]}
        assert back.certificate == {'dual': [1.0]}

    def test_an_absent_witness_stays_absent_across_the_wire(self):
        from autonomous_trust.core.config import from_json_string, to_json_string
        from autonomous_trust.core.negotiation import TaskResult
        back = from_json_string(to_json_string(
            TaskResult(None, 5, requestor=None)))
        assert back.certificate is None
