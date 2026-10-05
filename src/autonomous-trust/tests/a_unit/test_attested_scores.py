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
"""Verifier-attested scores (doc/architecture/reputation.md, "Verifier-attested
scores"): one-sided entries that commit on the verifier's half plus a quorum.

The cross-language half is pinned by the conformance corpus
(scenarios/reputation/attest-*). These cover what a single-step scenario cannot:
the round end to end on real keys, catch-up's certificate gate, the re-append
after a fork, and how the entry folds."""

import queue
from types import SimpleNamespace
from uuid import uuid4

import pytest

from autonomous_trust.core.config import to_json_string
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    AttestedScore, SignedAttestation, Transaction, TransactionHistory,
    attest_task_id, consensus_score_from_window, evidence_attest_certs,
    evidence_from_dict, evidence_to_dict)
from autonomous_trust.core.system import CfgIds
from unittest.mock import MagicMock

DIGEST = 'ab' * 32


def _ident(name, n):
    return Identity.initialize(name, name, '10.0.9.%d' % n)


def _node(me, others):
    """A ReputationProcess whose identity is `me` and whose roster is `others`,
    with a real network queue to read what it sends."""
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
    queues = {CfgIds.network: queue.Queue()}
    return rp, queues


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


def _sig(ident, att):
    return ReputationProcess._detached_sig(ident, att.designation)


@pytest.fixture
def trio():
    return _ident('ver', 1), _ident('subj', 2), _ident('obs', 3)


def _att(v, s, score=0.3, digest=DIGEST):
    return AttestedScore(verifier_uuid=str(v.uuid), subject_uuid=str(s.uuid),
                         score=score, evidence_digest=digest)


class TestQuorum:
    def test_verifier_and_one_other_of_three_meets_it(self, trio):
        v, s, o = trio
        rp, _ = _node(o, [v, s])
        att = _att(v, s)
        assert rp._attest_quorum_met(att, {str(v.uuid): _sig(v, att),
                                           str(o.uuid): _sig(o, att)})

    def test_the_subjects_signature_is_not_counted(self, trio):
        v, s, o = trio
        rp, _ = _node(o, [v, s])
        att = _att(v, s)
        assert not rp._attest_quorum_met(att, {str(v.uuid): _sig(v, att),
                                               str(s.uuid): _sig(s, att)})

    def test_the_verifiers_own_signature_is_required(self, trio):
        v, s, o = trio
        d = _ident('dave', 4)
        rp, _ = _node(o, [v, s, d])
        att = _att(v, s)
        assert not rp._attest_quorum_met(att, {str(o.uuid): _sig(o, att),
                                               str(d.uuid): _sig(d, att)})

    def test_a_signature_by_the_wrong_key_does_not_count(self, trio):
        v, s, o = trio
        rp, _ = _node(o, [v, s])
        att = _att(v, s)
        assert not rp._attest_quorum_met(att, {str(v.uuid): _sig(v, att),
                                               str(o.uuid): _sig(v, att)})


class TestRound:
    def test_propose_sign_commit_final_end_to_end(self, trio):
        v, s, o = trio
        ver, vq = _node(v, [s, o])
        obs, oq = _node(o, [v, s])
        subj, sq = _node(s, [v, o])
        obs.reputations.update(v.uuid, 0.7)

        assert ver.forward_attestation(vq, AttestedScore(
            subject_uuid=str(s.uuid), score=0.3, evidence_digest=DIGEST))
        propose = [m for m in _sent(vq)
                   if m.function == ReputationProtocol.attest_propose]
        assert len(propose) == 1
        assert len(ver.history) == 0, 'nothing commits before the quorum'

        att = _att(v, s)
        obs.handle_attest_propose(oq, _msg(ReputationProtocol.attest_propose,
                                           att, v))
        signs = [m for m in _sent(oq)
                 if m.function == ReputationProtocol.attest_sign]
        assert len(signs) == 1

        ver.handle_attest_sign(vq, _msg(ReputationProtocol.attest_sign,
                                        from_json_string_obj(signs[0].obj), o))
        assert len(ver.history) == 1
        finals = [m for m in _sent(vq)
                  if m.function == ReputationProtocol.attest_final]
        assert len(finals) == 1

        # The subject's own node appends it too: it was never asked.
        signed = finals[0].obj if isinstance(finals[0].obj, SignedAttestation) \
            else from_json_string_obj(finals[0].obj)
        subj.handle_attest_final(sq, _msg(ReputationProtocol.attest_final,
                                          signed, v))
        assert len(subj.history) == 1
        tx = list(subj.history)[0]
        assert tx.attested and str(tx.subject_id) == str(s.uuid)
        assert subj.history.attest_certs[tx.task_id]

    def test_a_member_declines_a_verifier_below_the_floor(self, trio):
        v, s, o = trio
        obs, oq = _node(o, [v, s])
        obs.reputations.update(v.uuid, 0.3)
        obs.handle_attest_propose(oq, _msg(ReputationProtocol.attest_propose,
                                           _att(v, s), v))
        assert not [m for m in _sent(oq)
                    if m.function == ReputationProtocol.attest_sign]

    def test_the_proposal_must_come_from_its_verifier(self, trio):
        v, s, o = trio
        obs, oq = _node(o, [v, s])
        obs.reputations.update(v.uuid, 0.7)
        obs.reputations.update(s.uuid, 0.7)
        # sent by s, naming v as verifier
        obs.handle_attest_propose(oq, _msg(ReputationProtocol.attest_propose,
                                           _att(v, s), s))
        assert not _sent(oq)


class TestChain:
    def _history_with_attested(self, v, s):
        h = TransactionHistory()
        att = _att(v, s)
        sigs = {str(v.uuid): _sig(v, att)}
        assert h.append_attested(att.to_transaction(), sigs)
        return h, att

    def test_a_pairing_commit_cannot_fill_its_other_half(self, trio):
        v, s, _ = trio
        h, att = self._history_with_attested(v, s)
        h.update(att.task_id, s.uuid, 1.0)
        assert h[att.task_id].p2_id is None

    def test_catch_up_refuses_an_uncertified_attested_entry(self, trio):
        v, s, o = trio
        rp, _ = _node(o, [v, s])
        att = _att(v, s)
        tx = att.to_transaction()
        msg = SimpleNamespace(from_whom=SimpleNamespace(nickname='x'))
        assert not rp._chain_certified([tx], msg)
        tx.attest_sigs = {str(v.uuid): _sig(v, att), str(o.uuid): _sig(o, att)}
        assert rp._chain_certified([tx], msg)

    def test_a_fork_cannot_take_a_certified_entry_away(self, trio):
        v, s, o = trio
        rp, _ = _node(o, [v, s])
        att = _att(v, s)
        sigs = {str(v.uuid): _sig(v, att), str(o.uuid): _sig(o, att)}
        assert rp.history.append_attested(att.to_transaction(), sigs)
        # A peer's longer chain that forks at index 0 and never saw it.
        peer = TransactionHistory()
        for _ in range(2):
            t = uuid4()
            peer.update(t, v.uuid, 0.9)
            peer.update(t, s.uuid, 0.9)
        res = rp.history.reconcile(list(peer))
        assert res.status == 'adopted'
        assert att.task_id not in rp.history._task_mapping
        rp._reappend_attested(res)
        assert att.task_id in rp.history._task_mapping
        assert rp.history.verify_links()

    def test_it_is_about_its_subject_and_not_its_verifier(self, trio):
        v, s, _ = trio
        h = TransactionHistory()
        t = uuid4()
        h.update(t, v.uuid, 0.9)
        h.update(t, s.uuid, 0.9)
        before_s = consensus_score_from_window(s.uuid, list(h), 20)
        before_v = consensus_score_from_window(v.uuid, list(h), 20)
        att = _att(v, s)
        assert h.append_attested(att.to_transaction(), {})
        assert consensus_score_from_window(s.uuid, list(h), 20) < before_s
        assert consensus_score_from_window(v.uuid, list(h), 20) == before_v

    def test_the_evidence_document_keeps_entry_and_certificate(self, trio):
        v, s, _ = trio
        h, att = self._history_with_attested(v, s)
        doc = evidence_to_dict(h, None, h.attest_certs)
        chain, _ = evidence_from_dict(doc)
        assert chain[0].entry_hash() == list(h)[0].entry_hash()
        assert evidence_attest_certs(doc)[att.task_id] == h.attest_certs[att.task_id]

    def test_malformed_entries_are_refused(self, trio):
        v, s, _ = trio
        h = TransactionHistory()
        for bad in (
                Transaction(attest_task_id(v.uuid, s.uuid, DIGEST), p1_id=v.uuid,
                            p1_score=0.3, p1_channel='first_person',
                            attested=True, subject_id=s.uuid,
                            evidence_digest=DIGEST),
                Transaction(uuid4(), p1_id=v.uuid, p1_score=0.3,
                            p1_channel='probe', attested=True,
                            subject_id=s.uuid, evidence_digest=DIGEST),
                Transaction(attest_task_id(v.uuid, v.uuid, DIGEST), p1_id=v.uuid,
                            p1_score=0.3, p1_channel='probe', attested=True,
                            subject_id=v.uuid, evidence_digest=DIGEST),
                Transaction(attest_task_id(v.uuid, s.uuid, 'zz'), p1_id=v.uuid,
                            p1_score=0.3, p1_channel='probe', attested=True,
                            subject_id=s.uuid, evidence_digest='zz')):
            assert not h.append_attested(bad)
        assert len(h) == 0



def _proposes(queues):
    return [m for m in _sent(queues)
            if m.function == ReputationProtocol.attest_propose]


def _later(rp, n):
    """A sweep time n retry intervals from now (plus a second of slack)."""
    from autonomous_trust.core._python.reputation.repprocess import now
    return now().timestamp() + n * rp.ATTEST_RETRY_SEC + 1


class TestReproposal:
    """ISSUES §2.40: the propose is a one-shot fan-out, and a lost copy left
    the round pending forever (Stele st-660084). It is now sent again on the
    reputation tick, a bounded number of times."""

    def _proposed(self, trio):
        v, s, o = trio
        ver, vq = _node(v, [s, o])
        assert ver.forward_attestation(vq, AttestedScore(
            subject_uuid=str(s.uuid), score=0.3, evidence_digest=DIGEST))
        assert len(_proposes(vq)) == 1   # ...and, say, lost on the way
        return ver, vq

    def test_a_lost_propose_is_sent_again_after_the_interval(self, trio):
        ver, vq = self._proposed(trio)
        assert ver._retry_pending_attestations(vq, _later(ver, 0) - 2) == 0
        assert _proposes(vq) == []
        assert ver._retry_pending_attestations(vq, _later(ver, 1)) == 1
        again = _proposes(vq)
        assert len(again) == 1
        # The same round: a co-signer signs the same designation again.
        assert from_json_string_obj(again[0].obj).task_id == \
            list(ver._attest_pending.values())[0].task_id

    def test_reproposals_are_bounded_then_the_round_is_abandoned(self, trio):
        ver, vq = self._proposed(trio)
        sent = sum(ver._retry_pending_attestations(vq, _later(ver, i))
                   for i in range(1, 3 * ver.ATTEST_RETRIES))
        assert sent == ver.ATTEST_RETRIES
        assert ver._attest_pending == {} and ver._attest_retry == {}

    def test_a_certified_round_is_not_proposed_again(self, trio):
        v, s, o = trio
        ver, vq = self._proposed(trio)
        obs, oq = _node(o, [v, s])
        obs.reputations.update(v.uuid, 0.7)
        obs.handle_attest_propose(oq, _msg(ReputationProtocol.attest_propose,
                                           _att(v, s), v))
        sign = [m for m in _sent(oq)
                if m.function == ReputationProtocol.attest_sign][0]
        ver.handle_attest_sign(vq, _msg(ReputationProtocol.attest_sign,
                                        from_json_string_obj(sign.obj), o))
        assert len(ver.history) == 1
        _sent(vq)
        assert ver._retry_pending_attestations(vq, _later(ver, 1)) == 0
        assert _proposes(vq) == []

    def test_a_round_already_in_the_chain_is_forgotten(self, trio):
        v, s, o = trio
        ver, vq = self._proposed(trio)
        att = list(ver._attest_pending.values())[0]
        # Certified elsewhere, and its final reached us first.
        ver._commit_attestation(att, {str(v.uuid): _sig(v, att),
                                      str(o.uuid): _sig(o, att)})
        assert ver._retry_pending_attestations(vq, _later(ver, 1)) == 0
        assert _proposes(vq) == []
        assert ver._attest_pending == {} and ver._attest_retry == {}

def from_json_string_obj(obj):
    from autonomous_trust.core.config import from_json_string
    return obj if not isinstance(obj, str) else from_json_string(obj)
