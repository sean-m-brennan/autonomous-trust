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

import json
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
from autonomous_trust.core.structures.merkle import MerkleTree
from autonomous_trust.core.reputation.reputation import (
    AttestedScore, Checkpoint, SignedAttestation, Transaction,
    TransactionHistory, attest_task_id, consensus_score_from_window,
    SignedCheckpoint, attested_record, evidence_attest_certs,
    evidence_from_dict, evidence_to_dict, load_anchor, verify_attested_record)
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

    def test_a_grown_group_does_not_decertify_what_it_holds(self, trio):
        """ISSUES §2.48 (Stele red team rt-1520252): an entry certified by 2
        while the group had 3 members looked short once it had 5, so every
        member refused every other member's chain and no checkpoint finalized
        again. What a node holds certified passes; anything new still needs
        today's quorum."""
        import copy
        v, s, o = trio
        rp, _ = _node(o, [v, s])
        att = _att(v, s)
        sigs = {str(v.uuid): _sig(v, att), str(o.uuid): _sig(o, att)}
        assert rp.history.append_attested(att.to_transaction(), sigs)
        rp.protocol.peers.all += [_ident('w', 4), _ident('x', 5)]
        msg = SimpleNamespace(from_whom=SimpleNamespace(nickname='x'))
        same = att.to_transaction()
        same.attest_sigs = dict(sigs)
        assert not rp._attest_certified(same)          # short against 5 members
        assert rp._chain_certified([same], msg)        # but we hold it
        other = _att(v, s, digest='cd' * 32)
        new = other.to_transaction()
        new.attest_sigs = {str(v.uuid): _sig(v, other), str(o.uuid): _sig(o, other)}
        assert not rp._chain_certified([new], msg)     # new: today's quorum
        changed = copy.copy(same)
        changed.p1_score = 0.8
        assert not rp._chain_certified([changed], msg)

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



SCOPE_A = 'aa' * 32
SCOPE_B = 'bb' * 32


class TestScope:
    """An optional scope names what an attestation is about, so the rate cap is
    one per (verifier, subject, channel, scope): a fresh scan of a fixed commit
    answers a finding instead of waiting for it to leave the window."""

    def test_an_unscoped_entry_hashes_as_it_always_did(self, trio):
        v, s, _ = trio
        plain = _att(v, s).to_transaction()
        assert plain.attest_scope is None
        scoped = AttestedScore(verifier_uuid=str(v.uuid), subject_uuid=str(s.uuid),
                               score=0.3, evidence_digest=DIGEST,
                               attest_scope=SCOPE_A).to_transaction()
        assert scoped._canonical_bytes() == (plain._canonical_bytes()
                                             + b'|' + SCOPE_A.encode())

    def test_the_designation_carries_the_scope_only_when_set(self, trio):
        v, s, _ = trio
        plain = _att(v, s)
        scoped = AttestedScore(verifier_uuid=str(v.uuid), subject_uuid=str(s.uuid),
                               score=0.3, evidence_digest=DIGEST,
                               attest_scope=SCOPE_A)
        assert scoped.designation == plain.designation + b'|' + SCOPE_A.encode()

    def test_the_cap_is_per_scope_and_channel(self, trio):
        v, s, o = trio
        rp, _ = _node(o, [v, s])
        rp.reputations.update(v.uuid, 0.7)
        held = AttestedScore(verifier_uuid=str(v.uuid), subject_uuid=str(s.uuid),
                             score=0.3, evidence_digest='cd' * 32,
                             attest_scope=SCOPE_A)
        assert rp.history.append_attested(held.to_transaction(), {})

        def _new(scope, channel='probe'):
            return AttestedScore(verifier_uuid=str(v.uuid),
                                 subject_uuid=str(s.uuid), score=0.8,
                                 channel=channel, evidence_digest=DIGEST,
                                 attest_scope=scope)
        assert rp._attest_admissible(_new(SCOPE_B))[0]
        assert rp._attest_admissible(_new(SCOPE_A, 'certificate'))[0]
        ok, why = rp._attest_admissible(_new(SCOPE_A))
        assert not ok and 'scope' in why
        assert not rp._attest_admissible(_new(None))[0]   # unscoped: per pair

    def test_the_scope_survives_the_evidence_document_and_catch_up(self, trio):
        v, s, _ = trio
        h = TransactionHistory()
        att = AttestedScore(verifier_uuid=str(v.uuid), subject_uuid=str(s.uuid),
                            score=0.3, evidence_digest=DIGEST,
                            attest_scope=SCOPE_A)
        assert h.append_attested(att.to_transaction(), {str(v.uuid): _sig(v, att)})
        doc = evidence_to_dict(h, None, h.attest_certs)
        chain, _ = evidence_from_dict(doc)
        assert chain[0].attest_scope == SCOPE_A
        assert chain[0].entry_hash() == list(h)[0].entry_hash()
        wire = list(h)[0].to_dict()
        assert wire['attest_scope'] == SCOPE_A
        assert 'attest_scope' not in _att(v, s).to_transaction().to_dict() \
            or not _att(v, s).to_transaction().to_dict().get('attest_scope')

    def test_a_malformed_scope_is_refused(self, trio):
        v, s, _ = trio
        bad = AttestedScore(verifier_uuid=str(v.uuid), subject_uuid=str(s.uuid),
                            score=0.3, evidence_digest=DIGEST, attest_scope='zz')
        assert not bad.well_formed()
        assert not TransactionHistory().append_attested(bad.to_transaction())


class TestChannels:
    def test_four_channels_are_attestable(self, trio):
        v, s, _ = trio
        for ch in ('probe', 'certificate', 'self_consistency', 'replication'):
            att = AttestedScore(verifier_uuid=str(v.uuid), subject_uuid=str(s.uuid),
                                score=0.3, channel=ch, evidence_digest=DIGEST)
            assert att.well_formed(), ch
        for ch in ('first_person', 'task_outcome'):
            att = AttestedScore(verifier_uuid=str(v.uuid), subject_uuid=str(s.uuid),
                                score=0.3, channel=ch, evidence_digest=DIGEST)
            assert not att.well_formed(), ch


class TestArchive:
    """A quorum-signed checkpoint over an attested entry writes a durable,
    self-contained record of it, which verifies from what it carries alone and
    outlives the 200-entry window and the rewritten evidence file."""

    def _archived(self, trio, tmp_path, monkeypatch):
        import json
        from autonomous_trust.core.config import Configuration
        monkeypatch.setattr(Configuration, 'get_cfg_dir',
                            staticmethod(lambda: str(tmp_path)))
        v, s, o = trio
        rp, _ = _node(o, [v, s])
        t = uuid4()
        rp.history.update(t, v.uuid, 0.9)
        rp.history.update(t, s.uuid, 0.9)
        att = _att(v, s)
        assert rp.history.append_attested(
            att.to_transaction(), {str(v.uuid): _sig(v, att), str(o.uuid): _sig(o, att)})
        window = rp.history._indexed_window()
        ck = Checkpoint(proposer_uuid=o.uuid, root=rp.history.window_root(),
                        epoch=1, first_index=window[0].index, count=len(window))
        sigs = {str(o.uuid): ReputationProcess._detached_sig(o, ck.designation),
                str(v.uuid): ReputationProcess._detached_sig(v, ck.designation)}
        rp._store_checkpoint(ck, sigs)
        path = tmp_path / 'attested' / ('%s.json' % att.task_id)
        assert path.exists()
        return json.loads(path.read_text()), rp, att, path

    def test_a_record_verifies_on_its_own(self, trio, tmp_path, monkeypatch):
        rec, _, att, _ = self._archived(trio, tmp_path, monkeypatch)
        ok, why = verify_attested_record(rec)
        assert ok, why
        assert rec['entry']['task_id'] == str(att.task_id)

    def test_a_tampered_score_does_not_verify(self, trio, tmp_path, monkeypatch):
        rec, _, _, _ = self._archived(trio, tmp_path, monkeypatch)
        rec['entry']['p1_score'] = 0.9
        ok, why = verify_attested_record(rec)
        assert not ok
        assert 'entry not in the checkpoint window' in why

    def test_quorums_are_counted_from_the_record(self, trio, tmp_path, monkeypatch):
        v, s, o = trio
        rec, _, _, _ = self._archived(trio, tmp_path, monkeypatch)
        short = json.loads(json.dumps(rec))
        short['checkpoint']['sigs'].pop(str(v.uuid))
        assert 'checkpoint short of a quorum' in verify_attested_record(short)[1]
        nov = json.loads(json.dumps(rec))
        nov['entry']['attest_sigs'].pop(str(v.uuid))
        assert "the verifier's own signature is missing" in \
            verify_attested_record(nov)[1]
        unknown = json.loads(json.dumps(rec))
        unknown['signers'].pop(str(o.uuid))
        assert not verify_attested_record(unknown)[0]

    def test_a_record_the_c_runtime_wrote_verifies_here(self):
        """Cross-runtime: written by C's _archive_attested (rep_archive_test.c,
        AT_ARCHIVE_TEST_KEEP), checked by this runtime's verifier, and a
        tampered copy of it refused."""
        import os
        path = os.path.join(os.path.dirname(__file__), 'fixtures',
                            'attested_record_from_c.json')
        with open(path) as f:
            rec = json.load(f)
        assert verify_attested_record(rec) == (True, [])
        rec['entry']['p1_score'] = 0.9
        assert not verify_attested_record(rec)[0]

    def test_nothing_is_written_while_our_window_is_off_the_signed_root(
            self, trio, tmp_path, monkeypatch):
        """Stele st-1410977: the observer archived while still on a fork the
        quorum had not signed, so every record's proof failed against the
        checkpoint root, and a record is never rewritten. Now it waits until
        its own window reproduces the root."""
        rec, rp, att, path = self._archived(trio, tmp_path, monkeypatch)
        path.unlink()
        v, _, o = trio
        good = rp._checkpoints['']
        fork = Checkpoint(proposer_uuid=v.uuid, root=MerkleTree.get_hash(b'a fork'),
                          epoch=2, first_index=good.first_index, count=good.count)
        rp._checkpoints[''] = fork
        rp._checkpoint_sigs_final[''] = {
            str(o.uuid): ReputationProcess._detached_sig(o, fork.designation),
            str(v.uuid): ReputationProcess._detached_sig(v, fork.designation)}
        rp._archive_attested('')
        assert not path.exists()
        rp._checkpoints[''] = good
        rp._checkpoint_sigs_final[''] = {
            str(o.uuid): ReputationProcess._detached_sig(o, good.designation),
            str(v.uuid): ReputationProcess._detached_sig(v, good.designation)}
        rp._archive_attested('')
        assert verify_attested_record(json.loads(path.read_text()))[0]

    def test_it_is_written_once_and_outlives_the_window(self, trio, tmp_path,
                                                         monkeypatch):
        rec, rp, att, path = self._archived(trio, tmp_path, monkeypatch)
        before = path.read_text()
        rp._archive_attested('')
        assert path.read_text() == before
        rp.history.max_chain_len = 2
        for _ in range(3):
            t = uuid4()
            rp.history.update(t, uuid4(), 0.9)
            rp.history.update(t, uuid4(), 0.9)
        assert att.task_id not in rp.history._task_mapping
        assert verify_attested_record(json.loads(path.read_text()))[0]


class TestTierGate:
    """Eligibility is the verifier's EFFECTIVE tier in the co-signer's view:
    tier 1 for probe/certificate/self_consistency, tier 3 for replication, the
    score bounded by any standing ceiling, and nothing once excluded."""

    def _signs(self, trio, rep, channel='probe', setup=None):
        v, s, o = trio
        obs, oq = _node(o, [v, s])
        obs.reputations.update(v.uuid, rep)
        if setup is not None:
            setup(obs, v)
        att = AttestedScore(verifier_uuid=str(v.uuid), subject_uuid=str(s.uuid),
                            score=0.3, channel=channel, evidence_digest=DIGEST)
        obs.handle_attest_propose(oq, _msg(ReputationProtocol.attest_propose,
                                           att, v))
        return bool([m for m in _sent(oq)
                     if m.function == ReputationProtocol.attest_sign])

    def test_a_probe_needs_tier_one(self, trio):
        assert self._signs(trio, 0.55)
        assert not self._signs(trio, 0.45)

    def test_a_replication_needs_tier_three(self, trio):
        assert not self._signs(trio, 0.7, 'replication')
        assert self._signs(trio, 0.85, 'replication')

    def test_a_ceiling_caps_eligibility(self, trio):
        assert not self._signs(trio, 0.9, setup=lambda rp, v: setattr(
            rp, '_standing_ceiling', lambda u: 0.4))

    def test_an_excluded_verifier_is_refused(self, trio):
        assert not self._signs(trio, 0.9, setup=lambda rp, v: rp._excluded.add(
            str(v.uuid)))

    def test_the_old_raw_floor_still_sets_the_other_channels(self, trio,
                                                            monkeypatch):
        monkeypatch.setattr(ReputationProcess, 'ATTEST_MIN_REP', 0.3)
        assert self._signs(trio, 0.35)
        assert not self._signs(trio, 0.35, 'replication')


class TestAnchor:
    """A record carries its signers' keys and its group's size, which is what
    a forger writes too. Verified against the reader's own roster instead
    (roster.cfg.json, load_anchor), the keys and sizes are the reader's."""

    def _real(self, trio, tmp_path, monkeypatch):
        return TestArchive()._archived(trio, tmp_path, monkeypatch)

    def _forged(self, subject):
        """A self-signed record: one fresh key, a group of one."""
        x = _ident('forger', 9)
        rp, _ = _node(x, [])
        t = uuid4()
        rp.history.update(t, x.uuid, 0.9)
        rp.history.update(t, subject.uuid, 0.9)
        att = AttestedScore(verifier_uuid=str(x.uuid),
                            subject_uuid=str(subject.uuid), score=0.8,
                            evidence_digest=DIGEST)
        assert rp.history.append_attested(att.to_transaction(),
                                          {str(x.uuid): _sig(x, att)})
        window = rp.history._indexed_window()
        ck = Checkpoint(proposer_uuid=x.uuid, root=rp.history.window_root(),
                        epoch=1, first_index=window[0].index, count=len(window))
        sigs = {str(x.uuid): ReputationProcess._detached_sig(x, ck.designation)}
        doc = evidence_to_dict(rp.history, SignedCheckpoint(checkpoint=ck, sigs=sigs),
                               rp.history.attest_certs)
        key = x.signature.public.encode(encoder=__import__(
            'nacl.encoding', fromlist=['HexEncoder']).HexEncoder).decode('ascii')
        return attested_record(doc, att.task_id, {str(x.uuid): key}, 1, 1, False)

    def test_the_roster_is_written_beside_the_archive(self, trio, tmp_path,
                                                      monkeypatch):
        v, s, o = trio
        self._real(trio, tmp_path, monkeypatch)
        anchor = load_anchor(str(tmp_path))
        assert anchor is not None
        assert set(anchor['members']) == {str(v.uuid), str(s.uuid), str(o.uuid)}
        assert all(m['member'] for m in anchor['members'].values())
        assert [c['epoch'] for c in anchor['checkpoints']] == [1]

    def test_a_real_record_verifies_and_links(self, trio, tmp_path, monkeypatch):
        rec, _, _, _ = self._real(trio, tmp_path, monkeypatch)
        details = {}
        ok, why = verify_attested_record(rec, load_anchor(str(tmp_path)), details)
        assert ok, why
        assert details['linked'] and details['anchored']

    def test_a_self_signed_forgery_passes_alone_and_fails_anchored(
            self, trio, tmp_path, monkeypatch):
        _, s, _ = trio
        self._real(trio, tmp_path, monkeypatch)
        forged = self._forged(s)
        assert verify_attested_record(forged) == (True, [])
        ok, why = verify_attested_record(forged, load_anchor(str(tmp_path)))
        assert not ok
        assert 'checkpoint short of a quorum' in why
        assert "the verifier's own signature is missing" in why

    def test_a_record_key_that_disagrees_with_the_roster_fails(
            self, trio, tmp_path, monkeypatch):
        v, _, _ = trio
        rec, _, _, _ = self._real(trio, tmp_path, monkeypatch)
        rec['signers'][str(v.uuid)] = '00' * 32
        ok, why = verify_attested_record(rec, load_anchor(str(tmp_path)))
        assert not ok and any('disagrees' in r for r in why)

    def test_a_shrunk_group_still_needs_the_anchor_floor(self, trio, tmp_path,
                                                         monkeypatch):
        v, _, o = trio
        rec, _, _, _ = self._real(trio, tmp_path, monkeypatch)
        rec['checkpoint']['sigs'].pop(str(o.uuid))
        rec['group_size'] = rec['ckpt_group_size'] = 1
        assert 'checkpoint short of a quorum' not in verify_attested_record(rec)[1]
        assert 'checkpoint short of a quorum' in \
            verify_attested_record(rec, load_anchor(str(tmp_path)))[1]

    def test_another_group_and_another_root_fail(self, trio, tmp_path, monkeypatch):
        rec, _, _, _ = self._real(trio, tmp_path, monkeypatch)
        anchor = load_anchor(str(tmp_path))
        other = json.loads(json.dumps(rec))
        other['checkpoint']['group_uuid'] = str(uuid4())
        assert 'checkpoint from a group this node does not hold' in \
            verify_attested_record(other, anchor)[1]
        anchor['checkpoints'][0]['root'] = 'cd' * 32
        details = {}
        ok, why = verify_attested_record(rec, anchor, details)
        assert not ok and any('root differs' in r for r in why)
        assert not details['linked']

    def test_a_c_record_verifies_against_the_c_roster(self):
        """Cross-runtime: both files written by one C rep_archive_test run
        (AT_ARCHIVE_TEST_KEEP), the record anchored on the roster beside it."""
        import os
        here = os.path.join(os.path.dirname(__file__), 'fixtures')
        with open(os.path.join(here, 'attested_record_from_c.json')) as f:
            rec = json.load(f)
        anchor = load_anchor(os.path.join(here, 'roster_from_c.json'))
        details = {}
        assert verify_attested_record(rec, anchor, details) == (True, [])
        assert details['linked']
        anchor['members'].pop(rec['entry']['p1_id'])
        assert not verify_attested_record(rec, anchor)[0]

    def test_no_roster_no_anchor(self, tmp_path):
        assert load_anchor(str(tmp_path)) is None


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
