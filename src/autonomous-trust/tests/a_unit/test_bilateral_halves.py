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
"""Signed halves (R+D.md §14.2; RD_14.2_BILATERAL_EVIDENCE_PLAN.md Phase 1).

A commit certificate is the acceptors' word that a round ran. These pin the
scorer's own word: every ordinary half carries its scorer's signature over
`half_designation`, which names its counterparty; two halves pair only when
each names the other; and a half without a valid signature is refused on
commit, at placement and on catch-up. Only an entry this node already holds
is exempt (the user's calls, 2026-10-22).

The cross-language half is pinned by the conformance corpus
(scenarios/reputation/half-*)."""

import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from autonomous_trust.core.config import from_json_string
from autonomous_trust.core.reputation.placement import (entry_from_dict,
                                                        entry_to_dict)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import (
    Checkpoint, Transaction, TransactionHistory, TransactionScore,
    evidence_from_dict, evidence_to_dict, half_designation, window_root_of)

from autonomous_trust.core.reputation.reputation import score_to_milli
from tests.a_unit.test_commit_certificates import (_half, _ident, _msg, _node,
                                                    _roster, _sent,
                                                    _sign_halves, four)  # noqa: F401
from tests.a_unit.test_placement_acceptor import _roster_of

A = UUID('aaaaaaaa-0000-4000-8000-000000000001')
B = UUID('bbbbbbbb-0000-4000-8000-000000000002')
C = UUID('cccccccc-0000-4000-8000-000000000003')
T1 = UUID('00000000-0000-4000-8000-000000000001')


class TestDesignation:
    def test_the_bytes_are_pinned(self):
        # The C twin (half_designation, reputation.c) writes exactly these.
        assert half_designation(T1, A, B, 750) == (
            b'AT-HALF\x0000000000-0000-4000-8000-000000000001'
            b'|aaaaaaaa-0000-4000-8000-000000000001'
            b'|bbbbbbbb-0000-4000-8000-000000000002|750|task_outcome')

    def test_an_absent_channel_is_the_default(self):
        assert half_designation(T1, A, B, 500) == \
            half_designation(T1, A, B, 500, 'task_outcome')

    def test_it_binds_the_counterparty_and_the_score(self):
        base = half_designation(T1, A, B, 500)
        assert half_designation(T1, A, C, 500) != base
        assert half_designation(T1, A, B, 250) != base
        assert half_designation(T1, B, A, 500) != base


class TestPairing:
    def test_halves_that_name_each_other_pair(self):
        h = TransactionHistory()
        assert h.record_half(T1, A, 900, counterparty=B, half_sig='s1') == 'pending'
        assert h.record_half(T1, B, 700, counterparty=A, half_sig='s2') == 'ready'
        tx = h.pooled(T1)
        assert tx.half_sig_of(A) == 's1' and tx.half_sig_of(B) == 's2'

    def test_a_half_the_held_one_does_not_name_is_refused(self):
        # A names B; C, seeing the task id on the wire, races B to it.
        h = TransactionHistory()
        h.record_half(T1, A, 900, counterparty=B, half_sig='s1')
        assert h.record_half(T1, C, 0, counterparty=A, half_sig='s3') == 'mismatch'
        assert h.record_half(T1, B, 700, counterparty=A, half_sig='s2') == 'ready'
        assert {str(h.pooled(T1).p1_id), str(h.pooled(T1).p2_id)} == {str(A), str(B)}

    def test_a_half_naming_somebody_else_is_refused(self):
        h = TransactionHistory()
        h.record_half(T1, A, 900, counterparty=B, half_sig='s1')
        assert h.record_half(T1, B, 700, counterparty=C, half_sig='s2') != 'ready'

    def test_a_squatted_half_gives_way_to_the_half_it_names(self):
        # C got there first naming A; A's own signed half names B, which
        # proves C's can never pair. A's takes its place and B's completes it.
        h = TransactionHistory()
        h.record_half(T1, C, 0, counterparty=A, half_sig='s3')
        assert h.record_half(T1, A, 900, counterparty=B, half_sig='s1') == 'pending'
        assert h.record_half(T1, B, 700, counterparty=A, half_sig='s2') == 'ready'
        tx = h.pooled(T1)
        assert {str(tx.p1_id), str(tx.p2_id)} == {str(A), str(B)}
        assert tx.half_sig_of(C) is None

    def test_unnamed_halves_pair_as_they_always_did(self):
        h = TransactionHistory()
        h.record_half(T1, A, 900)
        assert h.record_half(T1, B, 700) == 'ready'


class TestPersistence:
    def test_a_lone_half_keeps_its_name_and_signature(self):
        h = TransactionHistory()
        h.record_half(T1, A, 900, certificate={str(C): 'ab'}, counterparty=B,
                      half_sig='ef01')
        doc = h.pool_to_dict()
        half = doc['pool'][0]['halves'][0]
        assert half['names'] == str(B) and half['sig'] == 'ef01'
        again = TransactionHistory()
        again.pool_from_dict(json.loads(json.dumps(doc)))
        tx = again.pooled(T1)
        assert tx.counterparty_of(A) == str(B) and tx.half_sig_of(A) == 'ef01'
        # The name still guards the pairing after a restart.
        assert again.record_half(T1, C, 100, counterparty=A) == 'mismatch'

    def test_the_placement_wire_carries_both_signatures(self):
        tx = Transaction(T1, p1_id=A, p1_score_milli=900, p2_id=B, p2_score_milli=700,
                         half_sigs={str(A): 'aa', str(B): 'bb'})
        d = entry_to_dict(tx)
        assert d['p1_sig'] == 'aa' and d['p2_sig'] == 'bb'
        back = entry_from_dict(d)
        assert back.half_sig_of(A) == 'aa' and back.half_sig_of(B) == 'bb'

    def test_signatures_are_outside_the_entry_hash(self):
        plain = Transaction(T1, p1_id=A, p1_score_milli=900, p2_id=B, p2_score_milli=700,
                            index=0)
        signed = Transaction(T1, p1_id=A, p1_score_milli=900, p2_id=B, p2_score_milli=700,
                             index=0, half_sigs={str(A): 'aa', str(B): 'bb'})
        assert plain.entry_hash() == signed.entry_hash()
        assert 'half_sigs' not in plain.to_dict()
        assert 'names' not in signed.to_dict()

    def test_the_evidence_document_carries_them(self):
        h = TransactionHistory()
        h.update(T1, A, 900)
        h.update(T1, B, 700)
        h[T1].half_sigs = {str(A): 'aa', str(B): 'bb'}
        doc = evidence_to_dict(list(h), None)
        assert doc['chain'][0]['half_sigs'] == {str(A): 'aa', str(B): 'bb'}
        chain, _ = evidence_from_dict(json.loads(json.dumps(doc)))
        assert chain[0].half_sig_of(B) == 'bb'


def _committed(scorer, task, score, names, sig, cert=None):
    """A `committed` tuple; `score` 0.0..1.0, carried as thousandths."""
    return (task, scorer.uuid, score_to_milli(score), None, None,
            cert if cert is not None else {'stand-in': 'ab'},
            None if names is None else str(names), sig)


class TestCommitted:
    """handle_committed: the scorer's signature over a half naming its
    counterparty, or nothing pools."""

    def _obs(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        obs._commit_cert_ok = lambda *a, **k: True    # certificates: elsewhere
        return obs, p, a1

    def test_a_signed_half_is_pooled(self, four):
        obs, p, a1 = self._obs(four)
        t = uuid4()
        obs.handle_committed(None, _msg(ReputationProtocol.committed, _committed(
            p, t, 0.9, a1.uuid, _half(p, a1, t, 900)), p))
        tx = obs.history.pooled(t)
        assert tx is not None and tx.counterparty_of(p.uuid) == str(a1.uuid)

    @pytest.mark.parametrize('spoil', ['unsigned', 'unnamed', 'forged',
                                       'other-name', 'other-score', 'self'])
    def test_a_half_its_scorer_did_not_sign_is_refused(self, four, spoil):
        obs, p, a1 = self._obs(four)
        t = uuid4()
        names, sig = a1.uuid, _half(p, a1, t, 900)
        if spoil == 'unsigned':
            sig = None
        elif spoil == 'unnamed':
            names = None
        elif spoil == 'forged':
            # The certifiers' majority signs in the scorer's name.
            sig = obs._detached_sig(a1, half_designation(t, p.uuid, a1.uuid, 900))
        elif spoil == 'other-name':
            names = four[2].uuid           # signed for a1, sent naming a2
        elif spoil == 'other-score':
            sig = _half(p, a1, t, 200)
        else:
            names, sig = p.uuid, obs._detached_sig(
                p, half_designation(t, p.uuid, p.uuid, 900))
        obs.handle_committed(None, _msg(ReputationProtocol.committed,
                                        _committed(p, t, 0.9, names, sig), p))
        assert obs.history.pooled(t) is None

    def test_the_two_halves_pair(self, four):
        obs, p, a1 = self._obs(four)
        t = uuid4()
        for me, other, s in ((p, a1, 0.9), (a1, p, 0.7)):
            obs.handle_committed(None, _msg(ReputationProtocol.committed, _committed(
                me, t, s, other.uuid, _half(me, other, t, score_to_milli(s))), me))
        assert len(obs.history.pooled(t)) == 2

    def test_a_third_party_cannot_complete_the_entry(self, four):
        obs, p, a1 = self._obs(four)
        a2 = four[2]
        t = uuid4()
        obs.handle_committed(None, _msg(ReputationProtocol.committed, _committed(
            p, t, 0.9, a1.uuid, _half(p, a1, t, 900)), p))
        # a2 signs honestly, naming p; p named a1.
        obs.handle_committed(None, _msg(ReputationProtocol.committed, _committed(
            a2, t, 0.0, p.uuid, _half(a2, p, t, 0)), a2))
        assert len(obs.history.pooled(t)) == 1


class TestForward:
    def test_a_half_that_names_nobody_runs_no_round(self, four):
        p = four[0]
        rp, q = _node(p, _roster(p, four))
        rp.forward_transaction(q, TransactionScore(uuid4(), 0.9))
        assert not _sent(q) and not rp.awaiting_commit

    def test_a_half_that_names_its_own_scorer_runs_no_round(self, four):
        p = four[0]
        rp, q = _node(p, _roster(p, four))
        rp.forward_transaction(q, TransactionScore(uuid4(), 0.9,
                                                   subject_uuid=p.uuid))
        assert not _sent(q) and not rp.awaiting_commit

    def test_a_named_half_does(self, four):
        p = four[0]
        rp, q = _node(p, _roster(p, four))
        rp.forward_transaction(q, TransactionScore(uuid4(), 0.9,
                                                   subject_uuid=four[1].uuid))
        assert [m for m in _sent(q)
                if m.function == ReputationProtocol.transaction]


class TestCatchup:
    MSG = SimpleNamespace(from_whom=SimpleNamespace(nickname='peer'))

    def _chain(self, four, n=2):
        p, a1 = four[0], four[1]
        h = TransactionHistory()
        for _ in range(n):
            t = uuid4()
            h.update(t, p.uuid, 900)
            h.update(t, a1.uuid, 700)
        return _sign_halves(list(h), four)

    def _obs(self, four):
        o = four[3]
        obs, _ = _node(o, _roster(o, four))
        obs._commit_certs_ok = lambda *a, **k: True   # certificates: elsewhere
        return obs

    def test_a_signed_segment_is_accepted(self, four):
        assert self._obs(four)._chain_certified(self._chain(four), self.MSG)

    def test_a_half_signed_by_somebody_else_is_refused(self, four):
        chain = self._chain(four)
        tx = chain[1]
        tx.half_sigs[str(four[0].uuid)] = four[2].sign(half_designation(
            tx.task_id, four[0].uuid, four[1].uuid, 900)).signature.decode()
        assert not self._obs(four)._chain_certified(chain, self.MSG)

    def test_a_held_entry_is_not_asked_again(self, four):
        """The one exemption: an entry this node already holds identically,
        such as one it held before signed halves existed."""
        obs = self._obs(four)
        p, a1 = four[0], four[1]
        t = uuid4()
        obs.history.update(t, p.uuid, 900)
        obs.history.update(t, a1.uuid, 700)
        assert obs._chain_certified(list(obs.history), self.MSG)

    def test_a_checkpoint_does_not_excuse_an_unsigned_half(self, four):
        obs = self._obs(four)
        chain = self._chain(four)
        chain[0].half_sigs = None
        obs._finalized = Checkpoint(proposer_uuid=four[0].uuid,
                                    root=window_root_of(chain), epoch=1,
                                    first_index=0, count=len(chain))
        assert not obs._chain_certified(chain, self.MSG)

    def test_a_departed_scorers_key_comes_from_our_roster(self, four):
        """`gone` scored a1 and has left: identity no longer holds it, but
        the roster logged in our chain records its key."""
        p, a1, a2, o = four
        gone = _ident('gone', 9)
        obs, _ = _node(o, [p, a1, a2])
        obs._commit_certs_ok = lambda *a, **k: True
        obs.history.roster_anchor = _roster_of([gone, a1, o])
        h = TransactionHistory()
        t = uuid4()
        h.update(t, gone.uuid, 900)
        h.update(t, a1.uuid, 700)
        chain = _sign_halves(list(h), [gone, a1])
        assert obs._chain_certified(chain, self.MSG)
        chain[0].half_sigs[str(gone.uuid)] = _half(a1, gone, t, 900)
        assert not obs._chain_certified(chain, self.MSG)

    def test_a_key_a_segment_brings_is_never_used(self, four):
        """A segment's own roster could list any key for any uuid; a scorer
        we know no key for is unverifiable, so its half is refused."""
        p, a1, a2, o = four
        gone = _ident('gone', 9)
        obs, _ = _node(o, [p, a1, a2])
        obs._commit_certs_ok = lambda *a, **k: True
        h = TransactionHistory()
        t = uuid4()
        h.update(t, gone.uuid, 900)
        h.update(t, a1.uuid, 700)
        chain = _sign_halves(list(h), [gone, a1])
        assert not obs._chain_certified(chain, self.MSG)


def test_end_to_end_both_halves_reach_an_observer(four):
    """Two real rounds on real keys: p scores a1 and a1 scores p; each signs
    its own half naming the other, and an observer pairs them."""
    p, a1, a2, o = four
    nodes = {i.uuid: _node(i, _roster(i, four)) for i in four}
    task = uuid4()
    commits = []
    for scorer, other, s in ((p, a1, 0.9), (a1, p, 0.7)):
        rp, q = nodes[scorer.uuid]
        score = TransactionScore(task, s, subject_uuid=other.uuid)
        rp.forward_transaction(q, score)
        prop = [m for m in _sent(q) if m.function == ReputationProtocol.transaction][0]
        for acc in (x for x in four if x is not scorer):
            arp, aq = nodes[acc.uuid]
            arp.handle_transaction(aq, _msg(ReputationProtocol.transaction,
                                            from_json_string(prop.obj), scorer))
            for m in _sent(aq):
                if m.function == ReputationProtocol.accepted:
                    rp.handle_accepted(q, _msg(ReputationProtocol.accepted,
                                               from_json_string(m.obj), acc))
        commits += [(scorer, m) for m in _sent(q)
                    if m.function == ReputationProtocol.committed]
    assert len(commits) == 2
    obs, _ = nodes[o.uuid]
    for scorer, m in commits:
        obs.handle_committed(None, _msg(ReputationProtocol.committed,
                                        from_json_string(m.obj), scorer))
    tx = obs.history.pooled(task)
    assert len(tx) == 2
    assert obs._entry_halves_signed(tx) is None
