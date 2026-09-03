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
"""Phase 0 slashing (fast-penalty path) tests.

Validates that a finalized slash floors a peer's reputation *immediately*
at the top of the scoring functions, bypassing the slow consensus EMA —
the principled fix for the dod_mission "mq800 stuck at 0.5" bug. Also
exercises the propose -> sign -> final quorum flow across two processes.
"""
import hashlib
import queue
from uuid import UUID, uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    TransactionScore, SlashAttestation, SignedSlash, Checkpoint,
)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import to_json_string, from_json_string


@pytest.fixture(autouse=True)
def _arm_slashing(monkeypatch):
    """The slash protocol is opt-in (R+D.md §12.8): unarmed, a node
    originates nothing, declines to co-sign, and ignores a finalized slash.
    Every flow test in this module drives that protocol deliberately, so it
    arms it deliberately -- which is also the pin that the DEFAULT is off,
    since these tests fail without this fixture."""
    monkeypatch.setattr(ReputationProcess, 'SLASH_ENABLED', True)


def _identity(tag: str, uuid=None) -> Identity:
    """A real identity with a signing key DISTINCT per tag.

    Real keys because slash co-signatures are now verified by every receiver:
    a slash floors a peer into sticky exclusion, so the tally has to count
    signatures rather than assertions. Distinct keys per tag keep the negative
    controls honest (one member's signature must fail against another's key).
    Deterministic, so a failure reproduces. ``Identity.uuid`` is read-only,
    hence passed in rather than assigned afterwards.
    """
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(uuid or UUID(bytes=hashlib.md5(tag.encode()).digest()),
                    '10.0.0.1', '%s.test' % tag,
                    Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False),
                    _public_only=False)


def _cosign(voter: Identity, att: SlashAttestation) -> str:
    """A voter's detached co-signature over the attestation designation, in the
    ASCII-hex form handle_slash_sign verifies."""
    return voter.sign(att.designation).signature.decode('ascii')


def _make_rep_process(self_uuid=None, identity=None):
    log_q = queue.Queue()
    if identity is None:
        identity = _identity('self-node', uuid=self_uuid or uuid4())

    procs = []
    for nm in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
               CfgIds.reputation):
        p = MagicMock()
        p.name = nm
        procs.append(p)
    configs = {
        'processes': procs,
        CfgIds.identity: identity,
        CfgIds.peers: MagicMock(),
        CfgIds.group: MagicMock(),
    }
    rp = ReputationProcess(configs, ProcessTracker(), log_q, suppress_log=True)
    # Deterministic group uuid for round/group keying.
    rp.protocol.group.uuid = uuid4()
    return rp


def _att(slasher, target, reason=SlashAttestation.REASON_SUSTAINED_ANOMALY,
         floor=0.1, epoch=1):
    return SlashAttestation(slasher_uuid=slasher, target_uuid=target,
                            reason=reason, floor_score=floor, epoch=epoch)


# --- scoring-floor invariant (the mq800 fix) --------------------------------

class TestSlashScoringFloor:
    def test_consensus_reputation_floored_when_slashed(self):
        rp = _make_rep_process()
        peer = uuid4()
        rp._slashed[str(peer)] = (0.1, 1)
        assert rp._consensus_reputation(peer) == pytest.approx(0.1)
        # Sticky memory is refreshed to the floor so a later lift won't
        # snap back to a stale pre-slash value.
        assert rp._consensus_last[str(peer)] == pytest.approx(0.1)

    def test_consensus_reputation_unslashed_uses_baseline(self):
        rp = _make_rep_process()
        peer = uuid4()
        # No slash, empty chain -> consensus baseline (PREREP_NEUTRAL, 0.2),
        # NOT floored.
        assert rp._consensus_reputation(peer) == pytest.approx(0.2)

    def test_compute_reputation_short_circuits_on_slash(self):
        rp = _make_rep_process()
        rp._persist_reputations = lambda: None  # avoid disk write
        peer = uuid4()
        rp._slashed[str(peer)] = (0.0, 2)
        rp._compute_reputation(peer, CfgIds.reputation,
                               MagicMock(uuid=uuid4()))
        # Floor stored and queued for a tier recompute (-> tier_lost).
        assert rp.reputations[peer] == pytest.approx(0.0)
        assert any(str(u) == str(peer) for u, _ in rp.pending_tiers)


# --- apply / rehabilitate ---------------------------------------------------

class TestApplySlash:
    def test_apply_sets_floor_and_queues_tier(self):
        rp = _make_rep_process()
        target = uuid4()
        rp._apply_slash(_att(rp.identity.uuid, target, floor=0.1, epoch=1))
        assert rp._slashed[str(target)][0] == pytest.approx(0.1)
        assert (str(target), 1) in rp._slashed_seen
        assert any(str(u) == str(target) for u, _ in rp.pending_tiers)

    def test_apply_is_idempotent_per_epoch(self):
        rp = _make_rep_process()
        target = uuid4()
        att = _att(rp.identity.uuid, target, floor=0.1, epoch=1)
        rp._apply_slash(att)
        n = len(rp.pending_tiers)
        rp._apply_slash(att)  # same (target, epoch) -> no-op
        assert len(rp.pending_tiers) == n

    def test_rehabilitate_lifts_to_neutral_and_readmits(self):
        rp = _make_rep_process()
        target = uuid4()
        rp._apply_slash(_att(rp.identity.uuid, target, floor=0.0, epoch=1))
        # Slashed below the 0.1 comm cut-off -> excluded.
        assert rp._is_excluded(rp._consensus_reputation(target))
        rp._apply_slash(_att(rp.identity.uuid, target,
                             reason=SlashAttestation.REASON_REHABILITATE,
                             floor=0.0, epoch=2))
        # The hard floor is released: the peer is no longer pinned in _slashed.
        assert str(target) not in rp._slashed
        # Rehabilitation LIFTS the score to neutral (PREREP_NEUTRAL, 0.2) --
        # above the cut-off -- so the peer is re-admitted and then re-earns
        # elevated trust from neutral. Recovery is explicit-only (this
        # REASON_REHABILITATE lift); an excluded peer, being ignored, could
        # never transact its way back on its own.
        assert rp._consensus_reputation(target) == pytest.approx(0.2)
        assert not rp._is_excluded(rp._consensus_reputation(target))


# --- replay bounds (epoch high-water marks) ---------------------------------

class TestSlashReplayBounds:
    """A slash decision must not be re-applicable.

    The FIFO ring alone could not promise this: it is bounded, so on a busy
    node an old key ages out and the slash behind it becomes replayable again
    — and because a slash floors a peer into an exclusion that is sticky by
    design, that is a durable penalty an attacker gets to re-impose. The
    per-(target, slasher) high-water mark is what closes it.
    """

    def test_replay_refused_after_ring_eviction(self):
        rp = _make_rep_process()
        rp._persist_slash_marks = lambda: None  # no disk in unit tests
        target = uuid4()
        att = _att(rp.identity.uuid, target, floor=0.1, epoch=1)
        rp._apply_slash(att)
        # Evict the ring entry the cheap filter relies on, leaving the
        # high-water mark as the only thing standing between the replay and
        # a second application. This is the state a busy node reaches on its
        # own, once COMMITTED_ROUNDS_CAP rounds have passed.
        rp._slashed_seen.clear()
        n = len(rp.pending_tiers)
        rp._apply_slash(att)
        assert len(rp.pending_tiers) == n

    def test_replayed_slash_cannot_undo_a_rehabilitation(self):
        rp = _make_rep_process()
        rp._persist_slash_marks = lambda: None
        target = uuid4()
        punitive = _att(rp.identity.uuid, target, floor=0.0, epoch=1)
        rp._apply_slash(punitive)
        rp._apply_slash(_att(rp.identity.uuid, target,
                             reason=SlashAttestation.REASON_REHABILITATE,
                             floor=0.0, epoch=2))
        assert str(target) not in rp._slashed
        # Re-present the punitive slash, with its ring entry aged out. The
        # rehabilitation must hold: this is the whole point of the mark.
        rp._slashed_seen.clear()
        rp._apply_slash(punitive)
        assert str(target) not in rp._slashed
        assert not rp._is_excluded(rp._consensus_reputation(target))

    def test_mark_is_per_slasher_not_per_target(self):
        """Two detectors number their slashes independently, so one
        detector's high epoch must not gag the other's legitimate low one."""
        rp = _make_rep_process()
        rp._persist_slash_marks = lambda: None
        target, other = uuid4(), uuid4()
        rp._apply_slash(_att(rp.identity.uuid, target, floor=0.1, epoch=7))
        rp._slashed.pop(str(target), None)
        rp._apply_slash(_att(other, target, floor=0.2, epoch=1))
        assert str(target) in rp._slashed  # accepted on its own sequence

    def test_higher_epoch_from_same_slasher_still_applies(self):
        rp = _make_rep_process()
        rp._persist_slash_marks = lambda: None
        target = uuid4()
        rp._apply_slash(_att(rp.identity.uuid, target, floor=0.1, epoch=1))
        rp._slashed_seen.clear()
        rp._apply_slash(_att(rp.identity.uuid, target, floor=0.0, epoch=2))
        assert rp._slashed[str(target)][0] == pytest.approx(0.0)

    def test_marks_roundtrip_and_resume_own_epoch(self, tmp_path, monkeypatch):
        """The marks survive a restart, and our own counter resumes past
        them — otherwise a restarted detector would begin again at epoch 1
        and have its next slashes refused by peers still holding marks."""
        from autonomous_trust.core.config import Configuration
        monkeypatch.setattr(Configuration, 'get_cfg_dir',
                            staticmethod(lambda: str(tmp_path)))
        rp = _make_rep_process()
        target = uuid4()
        rp._slash_epoch = 4
        rp._apply_slash(_att(rp.identity.uuid, target, floor=0.1, epoch=5))

        fresh = _make_rep_process(identity=rp.identity)
        assert fresh._slash_hw.get((str(target), str(rp.identity.uuid))) == 5
        assert fresh._slash_epoch >= 5
        # And the replay is refused by the RESTARTED node, which is the case
        # a volatile ring could never cover.
        n = len(fresh.pending_tiers)
        fresh._apply_slash(_att(rp.identity.uuid, target, floor=0.1, epoch=5))
        assert len(fresh.pending_tiers) == n

    def test_corrupt_marks_file_is_refused_not_silently_emptied(self, tmp_path,
                                                               monkeypatch):
        from autonomous_trust.core.config import Configuration
        monkeypatch.setattr(Configuration, 'get_cfg_dir',
                            staticmethod(lambda: str(tmp_path)))
        rp = _make_rep_process()
        with open(rp._slash_marks_path(), 'w') as f:
            f.write('[not an object]')
        rp._slash_hw = {('a', 'b'): 3}
        rp._load_slash_marks()
        # Refused, and the in-memory marks are left alone rather than being
        # replaced by the empty state the corrupt file asserts.
        assert rp._slash_hw == {('a', 'b'): 3}


# --- serialization ----------------------------------------------------------

class TestSlashSerialization:
    def test_attestation_json_roundtrip(self):
        att = _att(uuid4(), uuid4(), floor=0.1, epoch=3)
        back = from_json_string(to_json_string(att))
        assert isinstance(back, SlashAttestation)
        assert str(back.target_uuid) == str(att.target_uuid)
        assert back.reason == att.reason
        assert back.floor_score == pytest.approx(0.1)
        assert back.epoch == 3
        assert back.key() == att.key()

    def test_signed_slash_roundtrip(self):
        att = _att(uuid4(), uuid4())
        signed = SignedSlash(attestation=att, sigs={})
        back = from_json_string(to_json_string(signed))
        assert isinstance(back, SignedSlash)
        assert isinstance(back.attestation, SlashAttestation)
        assert str(back.attestation.target_uuid) == str(att.target_uuid)


# --- propose / sign / final flow --------------------------------------------

class TestSlashFlow:
    def test_forward_slash_self_applies_and_broadcasts(self):
        rp = _make_rep_process()
        rp.protocol.peers.all = [MagicMock(uuid=uuid4())]
        net_q = queue.Queue()
        target = uuid4()
        att = SlashAttestation(slasher_uuid=None, target_uuid=target,
                               reason=SlashAttestation.REASON_PEER_EXCLUDE,
                               floor_score=0.0)
        handled = rp.forward_slash({CfgIds.network: net_q}, att)
        assert handled is True
        # Slasher floors its OWN view immediately (what the dashboard reads).
        assert str(target) in rp._slashed
        assert rp._consensus_reputation(target) == pytest.approx(0.0)
        # And broadcast a slash_propose to collect co-signatures.
        msg = net_q.get_nowait()
        assert msg.function == ReputationProtocol.slash_propose

    def test_acceptor_co_signs_then_applies_on_final(self):
        slasher = _identity('slasher')
        slasher_id = slasher.uuid
        acc = _make_rep_process()
        acc.protocol.peers.all = [slasher]
        net_q = queue.Queue()
        queues = {CfgIds.network: net_q}
        target = uuid4()
        att = _att(slasher_id, target, floor=0.1, epoch=5)

        # Acceptor receives a verified slash_propose -> emits slash_sign.
        propose = Message(CfgIds.reputation, ReputationProtocol.slash_propose,
                          to_json_string(att), acc.group,
                          from_whom=slasher)
        propose.verified = True
        assert acc.handle_slash_propose(queues, propose) is True
        sign = net_q.get_nowait()
        assert sign.function == ReputationProtocol.slash_sign
        # The ack carries a verifiable detached signature, not a bare uuid.
        _tgt, _epoch, voter, sig = from_json_string(sign.obj)
        assert voter == str(acc.identity.uuid)
        assert acc._verify_cosignature(att.designation, voter, sig)
        # It has NOT applied the floor yet (waits for final).
        assert str(target) not in acc._slashed

        # Acceptor receives the finalized slash -> applies the floor.
        signed = SignedSlash(attestation=att,
                             sigs={str(slasher_id): _cosign(slasher, att)})
        final = Message(CfgIds.reputation, ReputationProtocol.slash_final,
                        to_json_string(signed), acc.group,
                        from_whom=slasher)
        final.verified = True
        assert acc.handle_slash_final(queues, final) is True
        assert str(target) in acc._slashed
        assert acc._consensus_reputation(target) == pytest.approx(0.1)

    def test_final_without_cosignatures_refused(self):
        """Negative control for the pre-fix behaviour: an evidence-free
        slash_final used to be applied on transport authentication alone, so
        any admitted member could floor any peer into sticky exclusion."""
        slasher = _identity('slasher')
        acc = _make_rep_process()
        acc.protocol.peers.all = [slasher, _identity('bystander')]
        target = uuid4()
        att = _att(slasher.uuid, target, floor=0.1, epoch=6)
        final = Message(CfgIds.reputation, ReputationProtocol.slash_final,
                        to_json_string(SignedSlash(attestation=att, sigs={})),
                        acc.group, from_whom=slasher)
        final.verified = True
        assert acc.handle_slash_final({CfgIds.network: queue.Queue()},
                                      final) is True
        assert str(target) not in acc._slashed

    def test_slash_sign_finalizes_at_quorum(self):
        rp = _make_rep_process()
        # One peer -> quorum floor(1/2)=0; a single co-sign (>0) finalizes.
        voter = _identity('voter')
        rp.protocol.peers.all = [voter]
        net_q = queue.Queue()
        target = uuid4()
        att = SlashAttestation(slasher_uuid=None, target_uuid=target,
                               reason=SlashAttestation.REASON_SUSTAINED_ANOMALY,
                               floor_score=0.1)
        rp.forward_slash({CfgIds.network: net_q}, att)
        net_q.get_nowait()  # drain the slash_propose
        key = att.key()  # epoch stamped by forward_slash
        sign = Message(CfgIds.reputation, ReputationProtocol.slash_sign,
                       to_json_string((key[0], key[1], str(voter.uuid),
                                       _cosign(voter, att))),
                       rp.group, from_whom=voter)
        sign.verified = True
        assert rp.handle_slash_sign({CfgIds.network: net_q}, sign) is True
        final = net_q.get_nowait()
        assert final.function == ReputationProtocol.slash_final
        # The finalizer carries the retained co-signatures (ours + the
        # voter's), which is what lets a receiver check quorum itself.
        signed = (final.obj if isinstance(final.obj, SignedSlash)
                  else from_json_string(final.obj))
        assert set(signed.sigs) == {str(rp.identity.uuid), str(voter.uuid)}
        # Pending dropped -> a duplicate sign is now a no-op.
        assert key not in rp._slash_pending

    def test_unverified_slash_propose_rejected(self):
        rp = _make_rep_process()
        net_q = queue.Queue()
        att = _att(uuid4(), uuid4())
        msg = Message(CfgIds.reputation, ReputationProtocol.slash_propose,
                      to_json_string(att), rp.group,
                      from_whom=MagicMock(uuid=uuid4()))
        msg.verified = False
        assert rp.handle_slash_propose({CfgIds.network: net_q}, msg) is True
        assert net_q.empty()  # no co-sign emitted


# --- Phase 3: Merkle-evidence-gated slashing --------------------------------

def _seed_window_and_checkpoint(rp, n=4):
    """Commit n bilateral txs, then finalize a checkpoint over that window.
    Returns the list of committed task_ids (in chain order)."""
    task_ids = []
    for _ in range(n):
        tid, p1, p2 = uuid4(), uuid4(), uuid4()
        rp.history.update(tid, p1, 0.7)
        rp.history.update(tid, p2, 0.5)
        task_ids.append(tid)
    rp._checkpoint = Checkpoint(
        proposer_uuid=rp.identity.uuid, root=rp.history.window_root(),
        epoch=1, first_index=0, count=n)
    return task_ids


class TestSlashEvidence:
    def test_no_evidence_is_trusted_fallback(self):
        rp = _make_rep_process()
        att = _att(uuid4(), uuid4())  # evidence_ref defaults to None
        assert rp._verify_slash_evidence(att) is True

    def test_build_and_verify_roundtrip(self):
        rp = _make_rep_process()
        tids = _seed_window_and_checkpoint(rp, 5)
        ev = rp.build_slash_evidence(tids[2])
        assert ev is not None and ev['root'] and ev['proof'] is not None
        att = _att(rp.identity.uuid, uuid4())
        att.evidence_ref = ev
        assert rp._verify_slash_evidence(att) is True

    def test_verify_fails_without_checkpoint(self):
        rp = _make_rep_process()
        tids = _seed_window_and_checkpoint(rp, 3)
        ev = rp.build_slash_evidence(tids[0])
        rp._checkpoint = None  # no finalized checkpoint to verify against
        att = _att(rp.identity.uuid, uuid4())
        att.evidence_ref = ev
        assert rp._verify_slash_evidence(att) is False

    def test_verify_fails_on_tampered_proof(self):
        rp = _make_rep_process()
        tids = _seed_window_and_checkpoint(rp, 4)
        ev = rp.build_slash_evidence(tids[1])
        # Flip a hex char in the first sibling digest -> proof no longer folds
        # to the checkpoint root.
        sib = list(ev['proof'][0])
        sib[0] = ('b' if sib[0][0] != 'b' else 'a') + sib[0][1:]
        ev['proof'][0] = sib
        att = _att(rp.identity.uuid, uuid4())
        att.evidence_ref = ev
        assert rp._verify_slash_evidence(att) is False

    def test_verify_fails_when_root_not_our_checkpoint(self):
        rp = _make_rep_process()
        tids = _seed_window_and_checkpoint(rp, 3)
        ev = rp.build_slash_evidence(tids[0])
        # Our finalized checkpoint is over a DIFFERENT root than the evidence
        # claims -> reject (accuser can't pick the root).
        rp._checkpoint.root = b'f' * 64
        att = _att(rp.identity.uuid, uuid4())
        att.evidence_ref = ev
        assert rp._verify_slash_evidence(att) is False

    def test_slash_final_applies_with_good_evidence(self):
        rp = _make_rep_process()
        slasher_id = _identity('slasher')
        rp.protocol.peers.all = [slasher_id]
        tids = _seed_window_and_checkpoint(rp, 4)
        target = uuid4()
        slasher = slasher_id.uuid
        att = _att(slasher, target, floor=0.1, epoch=9)
        att.evidence_ref = rp.build_slash_evidence(tids[0])
        signed = SignedSlash(attestation=att,
                             sigs={str(slasher): _cosign(slasher_id, att)})
        final = Message(CfgIds.reputation, ReputationProtocol.slash_final,
                        to_json_string(signed), rp.group,
                        from_whom=slasher_id)
        final.verified = True
        assert rp.handle_slash_final({CfgIds.network: queue.Queue()}, final) is True
        assert str(target) in rp._slashed  # evidence verified -> floored

    def test_slash_final_rejected_with_bad_evidence(self):
        rp = _make_rep_process()
        slasher_id = _identity('slasher')
        rp.protocol.peers.all = [slasher_id]
        tids = _seed_window_and_checkpoint(rp, 4)
        target = uuid4()
        slasher = slasher_id.uuid
        att = _att(slasher, target, floor=0.1, epoch=9)
        ev = rp.build_slash_evidence(tids[0])
        ev['leaf'] = ('b' if ev['leaf'][0] != 'b' else 'a') + ev['leaf'][1:]
        att.evidence_ref = ev
        # Co-signatures are deliberately VALID here, so this pin keeps testing
        # what it claims -- bad Merkle evidence -- rather than passing because
        # quorum was also absent.
        signed = SignedSlash(attestation=att,
                             sigs={str(slasher): _cosign(slasher_id, att)})
        final = Message(CfgIds.reputation, ReputationProtocol.slash_final,
                        to_json_string(signed), rp.group,
                        from_whom=slasher_id)
        final.verified = True
        assert rp.handle_slash_final({CfgIds.network: queue.Queue()}, final) is True
        assert str(target) not in rp._slashed  # bad evidence -> NOT floored
