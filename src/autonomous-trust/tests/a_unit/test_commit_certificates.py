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
"""Commit certificates (doc/architecture/reputation.md,
"Commit certificates"): every ordinary half needs a quorum of acceptors'
signatures over exactly what it writes.

The cross-language half is pinned by the conformance corpus
(scenarios/reputation/commit-cert-*). These cover the retired group
declarations, the round end to end on real keys, persistence, and catch-up's
gate, including the checkpoint that covers a chain cut before every group
required certificates."""

import queue
from types import SimpleNamespace
from uuid import uuid4

import pytest

from autonomous_trust.core.config import to_json_string, from_json_string
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.identity.group import Group
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    Checkpoint, Transaction, TransactionHistory, TransactionScore,
    commit_designation, evidence_from_dict, evidence_to_dict, half_designation,
    window_root_of)
from autonomous_trust.core.system import CfgIds
from unittest.mock import MagicMock


def _tx_body(id1, id2, proposer, score, certify=True, group=''):
    """A `transaction` proposal in its wire shape: the JSON object with named
    fields both runtimes send. `certify`/`group` of None leave the key off, as
    a half-round build's proposal did."""
    from autonomous_trust.core.config import to_json_string
    body = {'id1': id1, 'id2': id2, 'peer_uuid': str(proposer),
            'score_milli': score.score_milli, 'task_uuid': str(score.task_id)}
    if getattr(score, 'channel', None):
        body['channel'] = score.channel
    if certify is not None:
        body['certify'] = certify
    if group is not None:
        body['group'] = group
    return to_json_string(body)



def _ident(name, n):
    return Identity.initialize(name, name, '10.0.8.%d' % n)


def _node(me, others):
    """A ReputationProcess as `me`, rostered with `others`."""
    procs = []
    for name in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
                 CfgIds.reputation):
        p = MagicMock()
        p.name = name
        procs.append(p)
    configs = {'processes': procs, CfgIds.identity: me,
               CfgIds.peers: MagicMock(), CfgIds.group: MagicMock()}
    rp = ReputationProcess(configs, ProcessTracker(), queue.Queue(),
                           suppress_log=True)
    rp.protocol.peers = SimpleNamespace(all=list(others))
    return rp, {CfgIds.network: queue.Queue()}


def _sent(queues):
    out = []
    while not queues[CfgIds.network].empty():
        out.append(queues[CfgIds.network].get_nowait())
    return out


def _msg(function, obj, sender):
    m = Message(CfgIds.reputation, function, to_json_string(obj), None,
                from_whom=sender)
    m.verified = True
    m.from_whom = sender
    return m


def _sign(ident, scorer, task, score, channel=None):
    return ReputationProcess._detached_sig(
        ident, commit_designation(scorer.uuid, task, score, channel))


def _half(scorer, other, task, score, channel=None):
    """`scorer`'s own signature over its half, naming `other` (R+D.md
    §14.2)."""
    return ReputationProcess._detached_sig(
        scorer, half_designation(task, scorer.uuid, other.uuid, score, channel))


def _sign_halves(chain, people):
    """Each scorer in `chain` signs its own half, as every commit does."""
    by = {str(i.uuid): i for i in people}
    for tx in chain:
        if tx.p1_id is None or tx.p2_id is None:
            continue
        a, b = by[str(tx.p1_id)], by[str(tx.p2_id)]
        tx.attach_half_sig(a.uuid, _half(a, b, tx.task_id, tx.p1_score_milli))
        tx.attach_half_sig(b.uuid, _half(b, a, tx.task_id, tx.p2_score_milli))
    return chain


@pytest.fixture
def four():
    """A proposer and three others: a roster of 3 per node, so a quorum is
    (3 + 1) // 2 == 2 signatures besides the scorer's."""
    return (_ident('prop', 1), _ident('acc1', 2), _ident('acc2', 3),
            _ident('obs', 4))


def _roster(me, everyone):
    return [x for x in everyone if x is not me]


class TestRetiredDeclarations:
    """`commit_certificates` and `ordered_placement` were retired 2026-10-16:
    every group places its order and certifies its commits. A config or a
    canonical form written before then still loads, and nothing writes the
    keys any more."""

    def test_the_canonical_form_carries_neither(self):
        d = Group.initialize({}, 'g').to_canonical()
        assert 'commit_certificates' not in d
        assert 'ordered_placement' not in d

    def test_an_old_canonical_form_still_loads(self):
        d = Group.initialize({}, 'g').to_canonical()
        for value in (True, False):
            d['commit_certificates'] = d['ordered_placement'] = value
            g = Group.from_canonical(d)
            assert 'ordered_placement' not in g.to_canonical()

    def test_an_old_config_still_loads(self):
        g = Group.initialize({}, 'g')
        kw = g.to_dict()
        kw.update(_commit_certificates=False, _ordered_placement=False)
        kw.pop('__type__', None)
        back = Group(**kw)
        assert back.uuid == g.uuid
        assert '_ordered_placement' not in back.to_dict()

    def test_the_proto_has_no_field(self):
        fields = Group.initialize({}, 'g').message.DESCRIPTOR.fields_by_name
        assert 'commit_certificates' not in fields
        assert 'ordered_placement' not in fields


class TestDesignationAndEntry:
    def test_absent_and_default_channel_are_one_claim(self):
        a, t = uuid4(), uuid4()
        assert commit_designation(a, t, 500) == \
            commit_designation(a, t, 500, 'task_outcome')
        assert commit_designation(a, t, 500) != commit_designation(a, t, 600)

    def test_the_bytes_are_pinned(self):
        # The C twin (rep_commit_cert_test.c) pins the same two literals.
        from uuid import UUID
        s = UUID('11111111-2222-4333-8444-555555555555')
        t = UUID('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee')
        assert commit_designation(s, t, 900) == (
            b'AT-COMMIT\x0011111111-2222-4333-8444-555555555555'
            b'|aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee|900|task_outcome')
        assert commit_designation(s, t, 300, 'probe') == (
            b'AT-COMMIT\x0011111111-2222-4333-8444-555555555555'
            b'|aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee|300|probe')

    def test_a_score_off_the_scale_has_no_designation(self):
        a, t = uuid4(), uuid4()
        for bad in (0.9, 1001, -1, True):
            with pytest.raises(ValueError):
                commit_designation(a, t, bad)

    def test_a_certificate_changes_neither_the_hash_nor_the_plain_shape(self):
        t, a, b = uuid4(), uuid4(), uuid4()
        h = TransactionHistory()
        h.update(t, a, 900)
        h.update(t, b, 800)
        plain = list(h)[0]
        before = plain.entry_hash()
        assert 'commit_sigs' not in plain.to_dict()
        plain.attach_certificate(a, {'x': 'ab'})
        assert plain.entry_hash() == before
        assert plain.to_dict()['commit_sigs'] == {str(a): {'x': 'ab'}}

    def test_update_keeps_a_certificate_beside_an_already_held_half(self):
        t, a = uuid4(), uuid4()
        h = TransactionHistory()
        h.update(t, a, 900)
        h.update(t, a, 900, certificate={'v': 'cd'})
        assert h[t].certificate_of(a) == {'v': 'cd'}

    def test_the_evidence_document_keeps_both_certificates(self):
        t, a, b = uuid4(), uuid4(), uuid4()
        h = TransactionHistory()
        h.update(t, a, 900, certificate={'v1': 'aa'})
        h.update(t, b, 800, certificate={'v2': 'bb'})
        doc = evidence_to_dict(h)
        chain, _ = evidence_from_dict(doc)
        assert chain[0].entry_hash() == list(h)[0].entry_hash()
        assert chain[0].certificate_of(a) == {'v1': 'aa'}
        assert chain[0].certificate_of(b) == {'v2': 'bb'}

    def test_the_catchup_wire_keeps_them(self):
        t, a = uuid4(), uuid4()
        h = TransactionHistory()
        h.update(t, a, 900, certificate={'v1': 'aa'})
        h.update(t, uuid4(), 800)
        back = from_json_string(to_json_string(list(h)))
        assert back[0].certificate_of(a) == {'v1': 'aa'}


class TestCertificateCheck:
    def test_more_than_a_quorum_of_our_view_is_needed(self, four):
        p, a1, a2, o = four
        rp, _ = _node(o, _roster(o, four))
        t = uuid4()
        one = {str(a1.uuid): _sign(a1, p, t, 900)}
        two = dict(one, **{str(a2.uuid): _sign(a2, p, t, 900)})
        assert not rp._commit_cert_ok(p.uuid, t, 900, None, one)
        assert rp._commit_cert_ok(p.uuid, t, 900, None, two)

    def test_the_scorers_own_signature_never_counts(self, four):
        p, a1, _, o = four
        rp, _ = _node(o, _roster(o, four))
        t = uuid4()
        sigs = {str(a1.uuid): _sign(a1, p, t, 900),
                str(p.uuid): _sign(p, p, t, 900)}
        assert not rp._commit_cert_ok(p.uuid, t, 900, None, sigs)

    def test_a_certificate_for_another_score_does_not_count(self, four):
        p, a1, a2, o = four
        rp, _ = _node(o, _roster(o, four))
        t = uuid4()
        sigs = {str(a1.uuid): _sign(a1, p, t, 900),
                str(a2.uuid): _sign(a2, p, t, 900)}
        assert not rp._commit_cert_ok(p.uuid, t, 200, None, sigs)


class TestRound:
    def test_a_proposal_asks_to_be_certified_and_names_its_group(self, four):
        p = four[0]
        rp, q = _node(p, _roster(p, four))
        rp._start_paxos(q, TransactionScore(uuid4(), 0.9), group_uuid='')
        tx = [m for m in _sent(q)
              if m.function == ReputationProtocol.transaction]
        assert len(tx) == 1
        parts = from_json_string(tx[0].obj)
        assert parts['certify'] is True and parts['group'] == ''

    def test_end_to_end_commit_carries_a_certificate_others_accept(self, four):
        p, a1, a2, o = four
        prop, pq = _node(p, _roster(p, four))
        acc1, q1 = _node(a1, _roster(a1, four))
        acc2, q2 = _node(a2, _roster(a2, four))
        obs, _ = _node(o, _roster(o, four))
        score = TransactionScore(uuid4(), 0.9, subject_uuid=o.uuid)
        idx = (7, 1)
        prop.proposals[idx] = score

        # Each acceptor signs exactly what it accepts.
        accepts = []
        for acc, q in ((acc1, q1), (acc2, q2)):
            acc.handle_transaction(q, _msg(ReputationProtocol.transaction,
                                           from_json_string(_tx_body(7, 1, p.uuid, score)),
                                           p))
            out = [m for m in _sent(q)
                   if m.function == ReputationProtocol.accepted]
            assert len(out) == 1 and len(from_json_string(out[0].obj)) == 4
            accepts.append(out[0])

        # One signature is short of the quorum; the second carries it.
        prop.handle_accepted(pq, _msg(ReputationProtocol.accepted,
                                      from_json_string(accepts[0].obj), a1))
        assert not [m for m in _sent(pq)
                    if m.function == ReputationProtocol.committed]
        prop.handle_accepted(pq, _msg(ReputationProtocol.accepted,
                                      from_json_string(accepts[1].obj), a2))
        commits = [m for m in _sent(pq)
                   if m.function == ReputationProtocol.committed]
        assert len(commits) == 1
        parsed = from_json_string(commits[0].obj)
        assert len(parsed) == 8 and len(parsed[5]) == 2
        # Whom the half names, and the scorer's own signature over it.
        assert parsed[6] == str(o.uuid)
        assert parsed[7] == _half(p, o, score.task_id, 900)
        # The half waits in the pool, beside its certificate, to be placed.
        assert prop.history.pooled(score.task_id).certificate_of(p.uuid) \
            == parsed[5]

        obs.handle_committed(None, _msg(ReputationProtocol.committed, parsed, p))
        assert obs.history.pooled(score.task_id).certificate_of(p.uuid) \
            == parsed[5]

    def test_an_unsigned_acceptance_is_not_counted(self, four):
        p, a1, a2, _ = four
        prop, pq = _node(p, _roster(p, four))
        score = TransactionScore(uuid4(), 0.9)
        prop.proposals[(7, 1)] = score
        for who in (a1, a2):
            prop.handle_accepted(pq, _msg(ReputationProtocol.accepted,
                                          (7, 1, p.uuid), who))
        assert not [m for m in _sent(pq)
                    if m.function == ReputationProtocol.committed]
        assert score.task_id not in prop.history._task_mapping
        assert prop.history.pooled(score.task_id) is None

    def test_a_relayed_proposal_is_accepted_but_not_certified(self, four):
        p, a1, a2, _ = four
        acc, q = _node(a1, _roster(a1, four))
        score = TransactionScore(uuid4(), 0.9)
        acc.handle_transaction(q, _msg(ReputationProtocol.transaction,
                                       from_json_string(_tx_body(7, 1, p.uuid, score)), a2))
        out = [m for m in _sent(q) if m.function == ReputationProtocol.accepted]
        assert len(from_json_string(out[0].obj)) == 3

    def test_an_uncertified_commit_is_refused(self, four):
        p, _, _, o = four
        obs, _ = _node(o, _roster(o, four))
        t = uuid4()
        obs.handle_committed(None, _msg(ReputationProtocol.committed,
                                        (t, p.uuid, 0.9), p))
        assert t not in obs.history._task_mapping
        assert obs.history.pooled(t) is None


def _certified_chain(signers_by_node, n, scorers):
    """`n` bilateral entries between `scorers`, each half certified by every
    identity in `signers_by_node` other than its scorer."""
    h = TransactionHistory()
    for _ in range(n):
        t = uuid4()
        for scorer in scorers:
            sigs = {str(s.uuid): _sign(s, scorer, t, 900)
                    for s in signers_by_node if s is not scorer}
            h.update(t, scorer.uuid, 900, certificate=sigs)
    return _sign_halves(list(h), signers_by_node)


class TestCatchup:
    MSG = SimpleNamespace(from_whom=SimpleNamespace(nickname='peer'))

    def test_an_uncertified_tail_is_refused(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        h = TransactionHistory()
        t = uuid4()
        h.update(t, p.uuid, 900)
        h.update(t, a1.uuid, 900)
        assert not obs._chain_certified(list(h), self.MSG)

    def test_a_certified_tail_is_accepted(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        chain = _certified_chain(four, 2, (p, a1))
        assert obs._chain_certified(chain, self.MSG)

    def test_a_quorum_checkpoint_covers_what_it_commits_to(self, four):
        """The user's call: a chain cut before every group required certificates
        (or by members since gone) is acceptable once a quorum checkpointed
        it; only the tail past the checkpoint must carry certificates."""
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        h = TransactionHistory()
        for _ in range(3):
            t = uuid4()
            h.update(t, p.uuid, 900)
            h.update(t, a1.uuid, 900)
        chain = _sign_halves(list(h), four)
        obs._finalized = Checkpoint(proposer_uuid=p.uuid,
                                    root=window_root_of(chain[:2]), epoch=1,
                                    first_index=0, count=2)
        # Entries 0 and 1 are covered; entry 2 is the uncertified tail.
        assert not obs._chain_certified(chain, self.MSG)
        assert obs._chain_certified(chain[:2], self.MSG)

    def test_a_checkpoint_does_not_excuse_an_unsigned_half(self, four):
        """The user's call, 2026-10-22: the majority that could forge a
        half also signs the checkpoint, so its cover excuses a missing
        certificate and never a missing scorer signature (R+D.md §14.2)."""
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        h = TransactionHistory()
        for _ in range(2):
            t = uuid4()
            h.update(t, p.uuid, 900)
            h.update(t, a1.uuid, 900)
        chain = _sign_halves(list(h), four)
        chain[1].half_sigs.pop(str(a1.uuid))
        obs._finalized = Checkpoint(proposer_uuid=p.uuid,
                                    root=window_root_of(chain), epoch=1,
                                    first_index=0, count=2)
        assert not obs._chain_certified(chain, self.MSG)

    def test_a_checkpoint_the_segment_does_not_reproduce_covers_nothing(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        h = TransactionHistory()
        for _ in range(2):
            t = uuid4()
            h.update(t, p.uuid, 900)
            h.update(t, a1.uuid, 900)
        obs._finalized = Checkpoint(proposer_uuid=p.uuid, root=b'00' * 32,
                                    epoch=1, first_index=0, count=2)
        assert not obs._chain_certified(list(h), self.MSG)

    def test_an_entry_we_already_hold_is_not_asked_again(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        t = uuid4()
        obs.history.update(t, p.uuid, 900)
        obs.history.update(t, a1.uuid, 900)
        assert obs._chain_certified(list(obs.history), self.MSG)
