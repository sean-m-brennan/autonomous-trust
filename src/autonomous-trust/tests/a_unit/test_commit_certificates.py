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
"Commit certificates"): a group may declare that every ordinary half needs a
quorum of acceptors' signatures over exactly what it writes.

The cross-language half is pinned by the conformance corpus
(scenarios/reputation/commit-cert-*). These cover the group declaration, the
round end to end on real keys, persistence, and catch-up's gate, including the
checkpoint that covers a chain cut before the group required certificates."""

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
    commit_designation, evidence_from_dict, evidence_to_dict, window_root_of)
from autonomous_trust.core.system import CfgIds
from unittest.mock import MagicMock


def _ident(name, n):
    return Identity.initialize(name, name, '10.0.8.%d' % n)


def _node(me, others, required=True):
    """A ReputationProcess as `me`, rostered with `others`, in a group that
    does (or does not) declare commit certificates."""
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
    rp.protocol.group.commit_certificates = required
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


@pytest.fixture
def four():
    """A proposer and three others: a roster of 3 per node, so a quorum is
    more than 3 // 2 == 1, i.e. two signatures."""
    return (_ident('prop', 1), _ident('acc1', 2), _ident('acc2', 3),
            _ident('obs', 4))


def _roster(me, everyone):
    return [x for x in everyone if x is not me]


class TestGroupDeclaration:
    def test_absent_by_default_and_omitted_from_the_canonical_form(self):
        g = Group.initialize({}, 'g')
        assert g.commit_certificates is False
        assert 'commit_certificates' not in g.to_canonical()

    def test_round_trips_and_travels_with_the_published_view(self):
        g = Group.initialize({}, 'g')
        g._commit_certificates = True
        d = g.to_canonical()
        assert d['commit_certificates'] is True
        assert Group.from_canonical(d).commit_certificates is True
        assert g.publish().commit_certificates is True

    def test_only_a_literal_true_turns_it_on(self):
        d = Group.initialize({}, 'g').to_canonical()
        d['commit_certificates'] = 'yes'
        assert Group.from_canonical(d).commit_certificates is False

    def test_a_merge_adopts_the_surviving_groups_value(self):
        mine, theirs = Group.initialize({}, 'a'), Group.initialize({}, 'b')
        theirs._commit_certificates = True
        mine.adopt_membership(theirs)
        assert mine.commit_certificates is True

    def test_the_knob_stamps_only_a_minted_group(self, monkeypatch):
        monkeypatch.setenv('AT_COMMIT_CERTIFICATES', '1')
        assert Group.initialize({}, 'g').commit_certificates is True
        monkeypatch.setenv('AT_COMMIT_CERTIFICATES', 'garbage')
        assert Group.initialize({}, 'g').commit_certificates is False

    def test_proto_round_trip(self):
        g = Group.initialize({}, 'g')
        if 'commit_certificates' not in g.message.DESCRIPTOR.fields_by_name:
            pytest.skip('generated identity_pb2 predates the field')
        g._commit_certificates = True
        g.sync_to_message()
        h = Group.initialize({}, 'h')
        h.message.CopyFrom(g.message)
        h.sync_from_message()
        assert h.commit_certificates is True


class TestDesignationAndEntry:
    def test_absent_and_default_channel_are_one_claim(self):
        a, t = uuid4(), uuid4()
        assert commit_designation(a, t, 0.5) == \
            commit_designation(a, t, 0.5, 'task_outcome')
        assert commit_designation(a, t, 0.5) != commit_designation(a, t, 0.6)

    def test_a_certificate_changes_neither_the_hash_nor_the_plain_shape(self):
        t, a, b = uuid4(), uuid4(), uuid4()
        h = TransactionHistory()
        h.update(t, a, 0.9)
        h.update(t, b, 0.8)
        plain = list(h)[0]
        before = plain.entry_hash()
        assert 'commit_sigs' not in plain.to_dict()
        plain.attach_certificate(a, {'x': 'ab'})
        assert plain.entry_hash() == before
        assert plain.to_dict()['commit_sigs'] == {str(a): {'x': 'ab'}}

    def test_update_keeps_a_certificate_beside_an_already_held_half(self):
        t, a = uuid4(), uuid4()
        h = TransactionHistory()
        h.update(t, a, 0.9)
        h.update(t, a, 0.9, certificate={'v': 'cd'})
        assert h[t].certificate_of(a) == {'v': 'cd'}

    def test_the_evidence_document_keeps_both_certificates(self):
        t, a, b = uuid4(), uuid4(), uuid4()
        h = TransactionHistory()
        h.update(t, a, 0.9, certificate={'v1': 'aa'})
        h.update(t, b, 0.8, certificate={'v2': 'bb'})
        doc = evidence_to_dict(h)
        chain, _ = evidence_from_dict(doc)
        assert chain[0].entry_hash() == list(h)[0].entry_hash()
        assert chain[0].certificate_of(a) == {'v1': 'aa'}
        assert chain[0].certificate_of(b) == {'v2': 'bb'}

    def test_the_catchup_wire_keeps_them(self):
        t, a = uuid4(), uuid4()
        h = TransactionHistory()
        h.update(t, a, 0.9, certificate={'v1': 'aa'})
        h.update(t, uuid4(), 0.8)
        back = from_json_string(to_json_string(list(h)))
        assert back[0].certificate_of(a) == {'v1': 'aa'}


class TestCertificateCheck:
    def test_more_than_a_quorum_of_our_view_is_needed(self, four):
        p, a1, a2, o = four
        rp, _ = _node(o, _roster(o, four))
        t = uuid4()
        one = {str(a1.uuid): _sign(a1, p, t, 0.9)}
        two = dict(one, **{str(a2.uuid): _sign(a2, p, t, 0.9)})
        assert not rp._commit_cert_ok(p.uuid, t, 0.9, None, one)
        assert rp._commit_cert_ok(p.uuid, t, 0.9, None, two)

    def test_the_scorers_own_signature_never_counts(self, four):
        p, a1, _, o = four
        rp, _ = _node(o, _roster(o, four))
        t = uuid4()
        sigs = {str(a1.uuid): _sign(a1, p, t, 0.9),
                str(p.uuid): _sign(p, p, t, 0.9)}
        assert not rp._commit_cert_ok(p.uuid, t, 0.9, None, sigs)

    def test_a_certificate_for_another_score_does_not_count(self, four):
        p, a1, a2, o = four
        rp, _ = _node(o, _roster(o, four))
        t = uuid4()
        sigs = {str(a1.uuid): _sign(a1, p, t, 0.9),
                str(a2.uuid): _sign(a2, p, t, 0.9)}
        assert not rp._commit_cert_ok(p.uuid, t, 0.2, None, sigs)


class TestRound:
    def test_grant_asks_for_certification_only_when_required(self, four):
        p = four[0]
        for required, marker in ((True, True), (False, None)):
            rp, q = _node(p, _roster(p, four), required)
            score = TransactionScore(uuid4(), 0.9)
            idx = (1, 1)
            rp.my_requests[idx] = SimpleNamespace(score=score, count=0)
            rp.handle_grant(q, _msg(ReputationProtocol.grant,
                                    ((1, 1, p.uuid), (None, 0), None),
                                    four[1]))
            tx = [m for m in _sent(q)
                  if m.function == ReputationProtocol.transaction]
            assert len(tx) == 1
            parts = from_json_string(tx[0].obj)
            assert (parts[2] if len(parts) > 2 else None) is marker

    def test_end_to_end_commit_carries_a_certificate_others_accept(self, four):
        p, a1, a2, o = four
        prop, pq = _node(p, _roster(p, four))
        acc1, q1 = _node(a1, _roster(a1, four))
        acc2, q2 = _node(a2, _roster(a2, four))
        obs, _ = _node(o, _roster(o, four))
        score = TransactionScore(uuid4(), 0.9)
        idx = (7, 1)
        prop.proposals[idx] = score

        # Each acceptor signs exactly what it accepts.
        accepts = []
        for acc, q in ((acc1, q1), (acc2, q2)):
            acc.requests.append(idx)
            acc.handle_transaction(q, _msg(ReputationProtocol.transaction,
                                           ((7, 1, p.uuid), score, True), p))
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
        assert len(parsed) == 6 and len(parsed[5]) == 2
        assert prop.history[score.task_id].certificate_of(p.uuid) == parsed[5]

        obs.handle_committed(None, _msg(ReputationProtocol.committed, parsed, p))
        assert obs.history[score.task_id].certificate_of(p.uuid) == parsed[5]

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

    def test_a_relayed_proposal_is_accepted_but_not_certified(self, four):
        p, a1, a2, _ = four
        acc, q = _node(a1, _roster(a1, four))
        acc.requests.append((7, 1))
        score = TransactionScore(uuid4(), 0.9)
        acc.handle_transaction(q, _msg(ReputationProtocol.transaction,
                                       ((7, 1, p.uuid), score, True), a2))
        out = [m for m in _sent(q) if m.function == ReputationProtocol.accepted]
        assert len(from_json_string(out[0].obj)) == 3

    def test_a_group_that_requires_them_refuses_an_uncertified_commit(self, four):
        p, _, _, o = four
        obs, _ = _node(o, _roster(o, four))
        t = uuid4()
        obs.handle_committed(None, _msg(ReputationProtocol.committed,
                                        (t, p.uuid, 0.9), p))
        assert t not in obs.history._task_mapping

    def test_a_group_that_does_not_still_writes_it(self, four):
        p, _, _, o = four
        obs, _ = _node(o, _roster(o, four), required=False)
        t = uuid4()
        obs.handle_committed(None, _msg(ReputationProtocol.committed,
                                        (t, p.uuid, 0.9), p))
        assert t in obs.history._task_mapping


def _certified_chain(signers_by_node, n, scorers):
    """`n` bilateral entries between `scorers`, each half certified by every
    identity in `signers_by_node` other than its scorer."""
    h = TransactionHistory()
    for _ in range(n):
        t = uuid4()
        for scorer in scorers:
            sigs = {str(s.uuid): _sign(s, scorer, t, 0.9)
                    for s in signers_by_node if s is not scorer}
            h.update(t, scorer.uuid, 0.9, certificate=sigs)
    return list(h)


class TestCatchup:
    MSG = SimpleNamespace(from_whom=SimpleNamespace(nickname='peer'))

    def test_an_uncertified_tail_is_refused(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        h = TransactionHistory()
        t = uuid4()
        h.update(t, p.uuid, 0.9)
        h.update(t, a1.uuid, 0.9)
        assert not obs._chain_certified(list(h), self.MSG)

    def test_a_certified_tail_is_accepted(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        chain = _certified_chain(four, 2, (p, a1))
        assert obs._chain_certified(chain, self.MSG)

    def test_a_group_that_does_not_require_them_accepts_either(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four), required=False)
        h = TransactionHistory()
        t = uuid4()
        h.update(t, p.uuid, 0.9)
        h.update(t, a1.uuid, 0.9)
        assert obs._chain_certified(list(h), self.MSG)

    def test_a_quorum_checkpoint_covers_what_it_commits_to(self, four):
        """The user's call: a chain cut before its group required certificates
        (or by members since gone) is acceptable once a quorum checkpointed
        it; only the tail past the checkpoint must carry certificates."""
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        h = TransactionHistory()
        for _ in range(3):
            t = uuid4()
            h.update(t, p.uuid, 0.9)
            h.update(t, a1.uuid, 0.9)
        chain = list(h)
        obs._finalized = Checkpoint(proposer_uuid=p.uuid,
                                    root=window_root_of(chain[:2]), epoch=1,
                                    first_index=0, count=2)
        # Entries 0 and 1 are covered; entry 2 is the uncertified tail.
        assert not obs._chain_certified(chain, self.MSG)
        assert obs._chain_certified(chain[:2], self.MSG)

    def test_a_checkpoint_the_segment_does_not_reproduce_covers_nothing(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        h = TransactionHistory()
        for _ in range(2):
            t = uuid4()
            h.update(t, p.uuid, 0.9)
            h.update(t, a1.uuid, 0.9)
        obs._finalized = Checkpoint(proposer_uuid=p.uuid, root=b'00' * 32,
                                    epoch=1, first_index=0, count=2)
        assert not obs._chain_certified(list(h), self.MSG)

    def test_an_entry_we_already_hold_is_not_asked_again(self, four):
        p, a1, _, o = four
        obs, _ = _node(o, _roster(o, four))
        t = uuid4()
        obs.history.update(t, p.uuid, 0.9)
        obs.history.update(t, a1.uuid, 0.9)
        assert obs._chain_certified(list(obs.history), self.MSG)
