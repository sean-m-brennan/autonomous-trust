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
import queue
from uuid import uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    TransactionScore, SlashAttestation, SignedSlash, Checkpoint,
)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import to_json_string, from_json_string


def _make_rep_process(self_uuid=None):
    log_q = queue.Queue()
    identity = MagicMock()
    identity.uuid = self_uuid or uuid4()
    # Real, JSON-serializable signature so to_json_string(attestation)
    # (which carries .signature) doesn't choke on a MagicMock.
    identity.sign = lambda m: b'\x01\x02\x03\x04'

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
        # No slash, empty chain -> consensus baseline (0.5), NOT floored.
        assert rp._consensus_reputation(peer) == pytest.approx(0.5)

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

    def test_rehabilitate_lifts_hard_floor_but_score_stays_low(self):
        rp = _make_rep_process()
        target = uuid4()
        rp._apply_slash(_att(rp.identity.uuid, target, floor=0.1, epoch=1))
        rp._apply_slash(_att(rp.identity.uuid, target,
                             reason=SlashAttestation.REASON_REHABILITATE,
                             floor=0.0, epoch=2))
        # The hard floor is released: the peer is no longer pinned in
        # _slashed and CAN climb again.
        assert str(target) not in rp._slashed
        # ...but rehabilitation is an UPHILL BATTLE. The score does NOT snap
        # back to the 0.5 baseline — the slashed value persists in
        # self.reputations as the cold-start prior (_consensus_baseline), so
        # the peer must earn its standing back through new committed
        # transactions rather than being handed neutrality for free.
        assert rp._consensus_reputation(target) == pytest.approx(0.1)


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
        slasher_id = uuid4()
        acc = _make_rep_process()
        acc.protocol.peers.all = [MagicMock(uuid=slasher_id)]
        net_q = queue.Queue()
        queues = {CfgIds.network: net_q}
        target = uuid4()
        att = _att(slasher_id, target, floor=0.1, epoch=5)

        # Acceptor receives a verified slash_propose -> emits slash_sign.
        propose = Message(CfgIds.reputation, ReputationProtocol.slash_propose,
                          to_json_string(att), acc.group,
                          from_whom=MagicMock(uuid=slasher_id))
        propose.verified = True
        assert acc.handle_slash_propose(queues, propose) is True
        sign = net_q.get_nowait()
        assert sign.function == ReputationProtocol.slash_sign
        # It has NOT applied the floor yet (waits for final).
        assert str(target) not in acc._slashed

        # Acceptor receives the finalized slash -> applies the floor.
        signed = SignedSlash(attestation=att, sigs={})
        final = Message(CfgIds.reputation, ReputationProtocol.slash_final,
                        to_json_string(signed), acc.group,
                        from_whom=MagicMock(uuid=slasher_id))
        final.verified = True
        assert acc.handle_slash_final(queues, final) is True
        assert str(target) in acc._slashed
        assert acc._consensus_reputation(target) == pytest.approx(0.1)

    def test_slash_sign_finalizes_at_quorum(self):
        rp = _make_rep_process()
        # One peer -> quorum floor(1/2)=0; a single co-sign (>0) finalizes.
        voter = uuid4()
        rp.protocol.peers.all = [MagicMock(uuid=voter)]
        net_q = queue.Queue()
        target = uuid4()
        att = SlashAttestation(slasher_uuid=None, target_uuid=target,
                               reason=SlashAttestation.REASON_SUSTAINED_ANOMALY,
                               floor_score=0.1)
        rp.forward_slash({CfgIds.network: net_q}, att)
        net_q.get_nowait()  # drain the slash_propose
        key = att.key()  # epoch stamped by forward_slash
        sign = Message(CfgIds.reputation, ReputationProtocol.slash_sign,
                       to_json_string((key[0], key[1], str(voter), b'sig')),
                       rp.group, from_whom=MagicMock(uuid=voter))
        sign.verified = True
        assert rp.handle_slash_sign({CfgIds.network: net_q}, sign) is True
        final = net_q.get_nowait()
        assert final.function == ReputationProtocol.slash_final
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
        rp.protocol.peers.all = [MagicMock(uuid=uuid4())]
        tids = _seed_window_and_checkpoint(rp, 4)
        target = uuid4()
        slasher = uuid4()
        att = _att(slasher, target, floor=0.1, epoch=9)
        att.evidence_ref = rp.build_slash_evidence(tids[0])
        signed = SignedSlash(attestation=att, sigs={})
        final = Message(CfgIds.reputation, ReputationProtocol.slash_final,
                        to_json_string(signed), rp.group,
                        from_whom=MagicMock(uuid=slasher))
        final.verified = True
        assert rp.handle_slash_final({CfgIds.network: queue.Queue()}, final) is True
        assert str(target) in rp._slashed  # evidence verified -> floored

    def test_slash_final_rejected_with_bad_evidence(self):
        rp = _make_rep_process()
        rp.protocol.peers.all = [MagicMock(uuid=uuid4())]
        tids = _seed_window_and_checkpoint(rp, 4)
        target = uuid4()
        slasher = uuid4()
        att = _att(slasher, target, floor=0.1, epoch=9)
        ev = rp.build_slash_evidence(tids[0])
        ev['leaf'] = ('b' if ev['leaf'][0] != 'b' else 'a') + ev['leaf'][1:]
        att.evidence_ref = ev
        signed = SignedSlash(attestation=att, sigs={})
        final = Message(CfgIds.reputation, ReputationProtocol.slash_final,
                        to_json_string(signed), rp.group,
                        from_whom=MagicMock(uuid=slasher))
        final.verified = True
        assert rp.handle_slash_final({CfgIds.network: queue.Queue()}, final) is True
        assert str(target) not in rp._slashed  # bad evidence -> NOT floored
