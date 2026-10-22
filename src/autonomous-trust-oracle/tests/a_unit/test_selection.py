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
"""Selective assignment (RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md): the
declaration, the draw, the seed chain, the requestor's log and the peer's
audit of it."""
import json
from types import SimpleNamespace

import pytest

from autonomous_trust.oracle.certificates.rng import SplitMix64
from autonomous_trust.oracle.selection import (
    EMPTY_MODEL, LENGTH, SeedChain, SelectionDeclarationError, draw,
    parse_selection, propensities, verify_link, verify_rotation)
from autonomous_trust.oracle._python.selection import hooks, selector
from autonomous_trust.oracle._python.selection.draw import seed_of, unit
from autonomous_trust.oracle._python.selection.selector import Requestor

ROOT = bytes(range(32))


def _model(**over):
    doc = {'version': 1, 'default': {'k': None, 'floor': 0.05},
           'probe': {'floor': 0.1},
           'capabilities': {'q': {'k': 2}, 'one': {'k': 1, 'floor': 0.0}}}
    doc.update(over)
    return parse_selection(doc)


class TestDeclaration:
    def test_absent_is_inert(self):
        assert not EMPTY_MODEL.declared
        assert not EMPTY_MODEL.selects('anything')

    def test_policy_resolution(self):
        m = _model()
        assert m.policy_for('q').k == 2 and m.policy_for('q').floor == 0.05
        assert m.policy_for('one').floor == 0.0
        assert m.policy_for('unnamed').k is None
        assert m.selects('q') and not m.selects('unnamed')
        assert m.probe_floor == 0.1

    @pytest.mark.parametrize('doc', [
        {'version': 2},
        {'version': 1, 'default': {'floor': 1.5}},
        {'version': 1, 'default': {'k': 0}},
        {'version': 1, 'default': {'k': True}},
        {'version': 1, 'capabilities': {'x': {'k': 1, 'typo': 1}}},
        {'version': 1, 'probe': []},
        {'version': 1, 'log_records': 0},
        {'version': 1, 'surprise': 1},
    ])
    def test_malformed_is_refused(self, doc):
        with pytest.raises(SelectionDeclarationError):
            parse_selection(doc)


class TestDraw:
    def test_floor_holds_and_sums_to_one(self):
        probs, degraded = propensities([0.0, 1.0, 9.0], 0.1)
        assert not degraded
        assert min(probs) >= 0.1
        assert abs(sum(probs) - 1.0) < 1e-12

    def test_unsatisfiable_floor_degrades_to_uniform(self):
        probs, degraded = propensities([1, 2, 3], 0.5)
        assert degraded and probs == [1 / 3] * 3

    def test_zero_weights_are_equal(self):
        probs, _ = propensities([0, 0], 0.0)
        assert probs == [0.5, 0.5]

    def test_k_none_and_k_at_least_n_select_everyone(self):
        assert draw([1, 2], None, 0.05, 1).selected == (0, 1)
        d = draw([1, 2], 5, 0.05, 1)
        assert d.kind == 'all' and d.inclusion == (1.0, 1.0)

    def test_categorical_matches_the_stream(self):
        d = draw([1, 1, 1, 1], 1, 0.0, 7)
        u = unit(SplitMix64(7))
        assert d.selected == (int(u * 4),)

    def test_bernoulli_inclusion_includes_the_fallback(self):
        # A tiny k makes empty rounds likely; the logged inclusion must be the
        # exact probability, so its sum is the expected set size.
        d = draw([1, 1, 1, 1], 2, 0.0, 3)
        assert d.kind == 'bernoulli'
        pis = [0.5] * 4
        empty = 0.5 ** 4
        assert all(abs(x - (pi + empty * 0.25)) < 1e-12 for x, pi in zip(d.inclusion, pis))

    def test_empirical_inclusion(self):
        hits = [0, 0, 0]
        n = 4000
        for seed in range(n):
            for i in draw([1, 2, 5], 2, 0.05, seed).selected:
                hits[i] += 1
        want = draw([1, 2, 5], 2, 0.05, 0).inclusion
        for h, w in zip(hits, want):
            assert abs(h / n - w) < 0.03


class TestChain:
    def test_links_verify_against_the_head(self):
        c = SeedChain(ROOT)
        for i in (1, 2, 255, 256, 257, LENGTH):
            assert verify_link(c.head, i, c.link(i))
        assert c.link(LENGTH) == ROOT

    def test_forward_check_from_a_known_link(self):
        c = SeedChain(ROOT)
        assert verify_link(c.head, 40, c.link(40), (3, c.link(3)))
        assert not verify_link(c.head, 40, c.link(41), (3, c.link(3)))

    def test_wrong_index_or_link_fails(self):
        c = SeedChain(ROOT)
        assert not verify_link(c.head, 5, c.link(6))
        assert not verify_link(c.head, 0, c.link(1))
        assert not verify_link(c.head, 1, b'short')

    def test_rotation_needs_the_root(self):
        c = SeedChain(ROOT)
        assert verify_rotation(c.head, ROOT)
        assert not verify_rotation(c.head, c.link(LENGTH - 1))


class TestRequestor:
    def test_index_is_persisted_before_use(self, tmp_path):
        r = Requestor('negotiation', _model(), cfg_dir=str(tmp_path), root=ROOT)
        r.decide('t1', 'q', ['a', 'b', 'c'], [1, 1, 1], 2, 0.05, 'task')
        again = Requestor('negotiation', _model(), cfg_dir=str(tmp_path))
        assert again.next_index == 2
        assert again.chain.head == r.chain.head

    def test_log_is_bounded_and_survives_a_restart(self, tmp_path):
        m = _model(log_records=2)
        r = Requestor('negotiation', m, cfg_dir=str(tmp_path), root=ROOT)
        for i in range(3):
            r.decide('t%d' % i, 'q', ['a', 'b'], [1, 1], 1, 0.05, 'task')
        assert sorted(r.records) == [2, 3]
        assert r.audit_answer(1, 'a')['status'] == 'unknown'
        r.flush(force=True)
        again = Requestor('negotiation', m, cfg_dir=str(tmp_path))
        assert sorted(again.records) == [2, 3]

    def test_rotation(self, tmp_path):
        r = Requestor('negotiation', _model(), cfg_dir=str(tmp_path), root=ROOT)
        r.next_index = LENGTH + 1
        old = r.chain.head
        _, field = r.decide('t', 'q', ['a'], [1], 1, 0.0, 'task')
        assert field['index'] == 1 and field['prev_root'] == ROOT.hex()
        assert bytes.fromhex(field['head']) != old

    def test_outcomes_and_declines_join_the_selecting_decision(self, tmp_path):
        r = Requestor('negotiation', _model(), cfg_dir=str(tmp_path), root=ROOT)
        selected, _ = r.decide('t', 'q', ['a', 'b', 'c'], [1, 1, 1], 1, 0.0, 'task')
        who = ['a', 'b', 'c'][selected[0]]
        assert r.record_decline('t', who) is not None
        assert r.record_outcome('t', who, 0.9)
        assert not r.record_outcome('t', 'nobody', 0.9)

    def test_audit_answer_shows_only_the_askers_row(self, tmp_path):
        r = Requestor('negotiation', _model(), cfg_dir=str(tmp_path), root=ROOT)
        r.decide('t', 'q', ['a', 'b', 'c'], [1, 2, 3], 2, 0.05, 'task')
        answer = r.audit_answer(1, 'b')
        assert answer['row']['position'] == 1
        assert set(answer) == {'index', 'status', 'head', 'link', 'task',
                               'eligible_count', 'row'}
        assert 'peer' not in json.dumps(answer)
        assert r.audit_answer(1, 'stranger')['row'] is None
        assert r.audit_answer(9, 'b')['status'] == 'unknown'


class TestAudit:
    def _draws(self, tmp_path, kinds):
        r = Requestor('negotiation', _model(), cfg_dir=str(tmp_path), root=ROOT)
        return r, [r.decide('t%d' % i, 'q', ['a', 'b', 'c'], [1, 2, 3], k,
                            0.05, 'task')[1] for i, k in enumerate(kinds)]

    def test_honest_draws_pass(self, tmp_path):
        r, fields = self._draws(tmp_path, [1, 2, 1])
        state = {'chains': {}, 'findings': {}}
        for f in fields:
            assert hooks.check_draw(state, 'R', f) == (None, [])

    def test_a_gap_is_audited_and_every_honest_answer_checks(self, tmp_path):
        r, fields = self._draws(tmp_path, [1, 2, 2, 1, 2])
        state = {'chains': {}, 'findings': {}}
        assert hooks.check_draw(state, 'R', fields[0]) == (None, [])
        finding, gap = hooks.check_draw(state, 'R', fields[4])
        assert finding is None and gap == [2, 3, 4]
        for index in gap:
            for asker in ('a', 'b', 'c'):
                assert hooks.check_answer(state, 'R', r.audit_answer(index, asker)) in (
                    None, 'audit_selected_uninvited')

    def test_a_lied_selection_is_inconsistent(self, tmp_path):
        r, fields = self._draws(tmp_path, [2])
        state = {'chains': {}, 'findings': {}}
        hooks.check_draw(state, 'R', fields[0])
        answer = r.audit_answer(1, 'a')
        answer['row']['selected'] = not answer['row']['selected']
        assert hooks.check_answer(state, 'R', answer) in (
            'audit_inconsistent', 'audit_selected_uninvited')

    def test_bad_link_replay_and_head_change(self, tmp_path):
        r, fields = self._draws(tmp_path, [1, 1])
        state = {'chains': {}, 'findings': {}}
        hooks.check_draw(state, 'R', fields[1])
        assert hooks.check_draw(state, 'R', fields[0])[0] == 'index_not_increasing'
        assert hooks.check_draw(state, 'R', fields[1]) == (None, [])  # re-announce
        forged = dict(fields[1], index=3)
        assert hooks.check_draw(state, 'R', forged)[0] == 'bad_link'
        other = SeedChain(bytes(32))
        stranger = {'head': other.head.hex(), 'index': 1, 'link': other.link(1).hex()}
        assert hooks.check_draw(state, 'R', stranger)[0] == 'head_changed'

    def test_rotation_with_the_root_is_accepted(self, tmp_path):
        r, fields = self._draws(tmp_path, [1])
        state = {'chains': {}, 'findings': {}}
        hooks.check_draw(state, 'R', fields[0])
        r.next_index = LENGTH + 1
        _, rotated = r.decide('t', 'q', ['a'], [1], 1, 0.0, 'task')
        assert hooks.check_draw(state, 'R', rotated) == (None, [])


class TestHooks:
    """The hooks against a stub negotiation process."""

    def _proc(self, tmp_path, monkeypatch, model):
        monkeypatch.setattr(selector, '_MODEL', model)
        proc = SimpleNamespace(name='negotiation', q_cadence=0.01)
        proc.__dict__[hooks._REQ_KEY] = Requestor('negotiation', model,
                                                  cfg_dir=str(tmp_path), root=ROOT)
        return proc

    @staticmethod
    def _peer(uid, tier=0):
        return SimpleNamespace(uuid=uid, _tier=tier, nickname=uid)

    @staticmethod
    def _task(cap, uid='t1'):
        return SimpleNamespace(uuid=uid, capability=SimpleNamespace(name=cap),
                               draw=None)

    def test_undeclared_or_unselected_leaves_the_task_alone(self, tmp_path, monkeypatch):
        proc = self._proc(tmp_path, monkeypatch, EMPTY_MODEL)
        assert hooks.select_participants(proc, self._task('q'), [self._peer('a')], None) is None
        proc = self._proc(tmp_path, monkeypatch, _model())
        assert hooks.select_participants(proc, self._task('other'), [self._peer('a')], None) is None
        # A directed task that is not a probe keeps its address.
        assert hooks.select_participants(proc, self._task('q'), [self._peer('a')],
                                         self._peer('a')) is None

    def test_a_drawn_task_is_stamped(self, tmp_path, monkeypatch):
        proc = self._proc(tmp_path, monkeypatch, _model())
        task = self._task('q')
        peers = [self._peer(u) for u in ('c', 'a', 'b')]
        chosen = hooks.select_participants(proc, task, peers, None)
        assert chosen and task.draw['index'] == 1
        rec = proc.__dict__[hooks._REQ_KEY].records[1]
        assert [r['peer'] for r in rec['eligible']] == ['a', 'b', 'c']

    def test_a_probe_target_is_drawn_and_counted(self, tmp_path, monkeypatch):
        from autonomous_trust.core._python.bootstrap_capabilities import \
            BOOTSTRAP_CAPABILITY_NAMES
        cap = BOOTSTRAP_CAPABILITY_NAMES[0]
        proc = self._proc(tmp_path, monkeypatch, _model())
        peers = [self._peer(u) for u in ('a', 'b')]
        chosen = hooks.select_participants(proc, self._task(cap), peers, peers[0])
        req = proc.__dict__[hooks._REQ_KEY]
        assert len(chosen) == 1 and req.probe_total == 1
        assert req.probe_counts[chosen[0].uuid] == 1
        # The window-phase broadcast of a bootstrap capability is not drawn.
        assert hooks.select_participants(proc, self._task(cap, 't2'), peers, None) is None

    def test_a_decline_is_redrawn_over_the_rest(self, tmp_path, monkeypatch):
        proc = self._proc(tmp_path, monkeypatch, _model())
        task = self._task('one')
        peers = [self._peer(u) for u in ('a', 'b', 'c')]
        first = hooks.select_participants(proc, task, peers, None)[0]
        again = hooks.on_decline(proc, task, first.uuid, peers)
        assert len(again) == 1 and again[0].uuid != first.uuid
        assert task.draw['index'] == 2
        rec = proc.__dict__[hooks._REQ_KEY].records[2]
        assert rec['redraw_of'] == 1
        assert first.uuid not in [r['peer'] for r in rec['eligible']]
        # Nobody left once all have declined.
        third = hooks.on_decline(proc, task, again[0].uuid, peers)
        assert hooks.on_decline(proc, task, third[0].uuid, peers) is None

    def test_a_decline_from_an_undrawn_peer_is_ignored(self, tmp_path, monkeypatch):
        proc = self._proc(tmp_path, monkeypatch, _model())
        assert hooks.on_decline(proc, self._task('q'), 'z', [self._peer('a')]) is None

    def test_score_echo_joins_the_log(self, tmp_path, monkeypatch):
        proc = self._proc(tmp_path, monkeypatch, _model())
        task = self._task('one')
        who = hooks.select_participants(proc, task, [self._peer('a')], None)[0]
        result = SimpleNamespace()
        hooks.on_result(proc, None, result, SimpleNamespace(draw=task.draw))
        assert result.echo_score
        hooks.on_score(proc, SimpleNamespace(task_uuid='t1', executor_uuid=who.uuid,
                                             score=0.8))
        rec = proc.__dict__[hooks._REQ_KEY].records[1]
        assert rec['outcome'] == {'a': 0.8}


class TestEstimate:
    """Doubly robust over a hand-computed log."""

    @staticmethod
    def _rec(index, cap, purpose, rows, outcome):
        return {'index': index, 'capability': cap, 'purpose': purpose,
                'eligible': [{'peer': p, 'propensity': mu, 'selected': sel}
                             for p, mu, sel in rows],
                'outcome': outcome}

    def test_reward_model_shrinks_toward_the_probe_mean(self):
        from autonomous_trust.oracle.selection import reward_model
        recs = [self._rec(1, 'p', 'probe', [('a', 0.5, True), ('b', 0.5, False)], {'a': 1.0}),
                self._rec(2, 'p', 'probe', [('a', 0.5, False), ('b', 0.5, True)], {'b': 0.0}),
                self._rec(3, 'q', 'task', [('a', 1.0, True)], {'a': 0.2})]
        model, prior = reward_model(recs)
        assert prior == 0.5
        assert model == {'a': (1.0 + 2 * 0.5) / 3, 'b': (0.0 + 2 * 0.5) / 3}

    def test_values_and_regret(self):
        from autonomous_trust.oracle.selection import estimate
        recs = [self._rec(1, 'p', 'probe', [('a', 0.5, True), ('b', 0.5, False)], {'a': 1.0}),
                self._rec(2, 'p', 'probe', [('a', 0.5, False), ('b', 0.5, True)], {'b': 0.0}),
                self._rec(3, 'q', 'task', [('a', 0.25, True), ('b', 0.75, False)], {'a': 0.9})]
        out = estimate(recs)
        ra, rb = 2 / 3, 1 / 3
        # Decision 3: a observed at mu 0.25, b not.
        ta = ra + (0.9 - ra) / 0.25
        tb = rb
        q = out['q']
        assert q['decisions'] == 1 and q['observed'] == 1
        assert abs(q['value']['logged'] - (0.25 * ta + 0.75 * tb)) < 1e-12
        assert abs(q['value']['uniform'] - (ta + tb) / 2) < 1e-12
        assert abs(q['value']['greedy'] - ta) < 1e-12
        assert abs(q['regret']['greedy'] - (ta - (0.25 * ta + 0.75 * tb))) < 1e-12

    def test_a_decision_with_no_outcome_is_skipped(self):
        from autonomous_trust.oracle.selection import estimate
        recs = [self._rec(1, 'q', 'task', [('a', 1.0, True)], {'a': 'declined'})]
        assert estimate(recs) == {}
