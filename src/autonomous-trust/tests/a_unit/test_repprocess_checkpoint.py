# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
"""Phase 2 quorum-signed Merkle checkpoint tests.

Exercises the propose -> sign -> final flow: a proposer commits to its own
window_root, members co-sign ONLY when their own window_root matches, and a
finalized checkpoint stores the agreed commitment. See
reputation-vs-blockchain-analysis.md §2.1 and reputation.py
Checkpoint/SignedCheckpoint.
"""
import queue
from uuid import uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    Checkpoint, SignedCheckpoint,
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
    rp.protocol.group.uuid = uuid4()
    return rp


def _fill(rp, n):
    """Commit n bilateral txs into rp's history so window_root is non-trivial."""
    for _ in range(n):
        tid, p1, p2 = uuid4(), uuid4(), uuid4()
        rp.history.update(tid, p1, 0.7)
        rp.history.update(tid, p2, 0.5)


# --- serialization ----------------------------------------------------------

class TestCheckpointSerialization:
    def test_checkpoint_json_roundtrip(self):
        ck = Checkpoint(proposer_uuid=uuid4(), root=b'a' * 64, epoch=3,
                        first_index=2, count=5)
        back = from_json_string(to_json_string(ck))
        assert isinstance(back, Checkpoint)
        assert str(back.proposer_uuid) == str(ck.proposer_uuid)
        assert back.epoch == 3 and back.first_index == 2 and back.count == 5
        assert back.key() == ck.key()
        # designation is reproducible across the round-trip (signable bytes).
        assert back.designation == ck.designation

    def test_signed_checkpoint_roundtrip(self):
        ck = Checkpoint(proposer_uuid=uuid4(), root=b'b' * 64, epoch=1)
        signed = SignedCheckpoint(checkpoint=ck, sigs={})
        back = from_json_string(to_json_string(signed))
        assert isinstance(back, SignedCheckpoint)
        assert isinstance(back.checkpoint, Checkpoint)
        assert str(back.checkpoint.proposer_uuid) == str(ck.proposer_uuid)


# --- propose / sign / final flow --------------------------------------------

class TestCheckpointFlow:
    def test_forward_checkpoint_commits_own_window_and_broadcasts(self):
        rp = _make_rep_process()
        rp.protocol.peers.all = [MagicMock(uuid=uuid4())]
        _fill(rp, 4)
        net_q = queue.Queue()
        handled = rp.forward_checkpoint({CfgIds.network: net_q}, Checkpoint(None, b''))
        assert handled is True
        # Self-stored a checkpoint over the live window root.
        assert rp._checkpoint is not None
        assert rp._checkpoint.root == rp.history.window_root()
        assert rp._checkpoint.count == 4
        # Broadcast a checkpoint_propose to collect co-signatures.
        msg = net_q.get_nowait()
        assert msg.function == ReputationProtocol.checkpoint_propose

    def test_member_cosigns_only_on_matching_root(self):
        proposer_id = uuid4()
        member = _make_rep_process()
        member.protocol.peers.all = [MagicMock(uuid=proposer_id)]
        net_q = queue.Queue()
        queues = {CfgIds.network: net_q}
        # Member and proposer share the SAME committed window content.
        seed = [(uuid4(), uuid4(), uuid4()) for _ in range(3)]
        for tid, p1, p2 in seed:
            member.history.update(tid, p1, 0.7)
            member.history.update(tid, p2, 0.5)
        matching_root = member.history.window_root()
        ck = Checkpoint(proposer_uuid=proposer_id, root=matching_root,
                        epoch=7, first_index=0, count=3)
        propose = Message(CfgIds.reputation, ReputationProtocol.checkpoint_propose,
                          to_json_string(ck), member.group,
                          from_whom=MagicMock(uuid=proposer_id))
        propose.verified = True
        assert member.handle_checkpoint_propose(queues, propose) is True
        sign = net_q.get_nowait()
        assert sign.function == ReputationProtocol.checkpoint_sign

    def test_member_declines_on_root_mismatch(self):
        proposer_id = uuid4()
        member = _make_rep_process()
        member.protocol.peers.all = [MagicMock(uuid=proposer_id)]
        net_q = queue.Queue()
        _fill(member, 2)  # member's window differs from the proposed root
        ck = Checkpoint(proposer_uuid=proposer_id, root=b'f' * 64, epoch=1,
                        first_index=0, count=9)
        propose = Message(CfgIds.reputation, ReputationProtocol.checkpoint_propose,
                          to_json_string(ck), member.group,
                          from_whom=MagicMock(uuid=proposer_id))
        propose.verified = True
        assert member.handle_checkpoint_propose({CfgIds.network: net_q}, propose) is True
        assert net_q.empty()  # no co-sign emitted on mismatch

    def test_sign_finalizes_at_quorum_and_stores(self):
        rp = _make_rep_process()
        voter = uuid4()
        rp.protocol.peers.all = [MagicMock(uuid=voter)]  # quorum floor(1/2)=0
        _fill(rp, 3)
        net_q = queue.Queue()
        rp.forward_checkpoint({CfgIds.network: net_q}, Checkpoint(None, b''))
        net_q.get_nowait()  # drain the checkpoint_propose
        ck = rp._checkpoint  # epoch stamped by forward_checkpoint
        key = ck.key()
        sign = Message(CfgIds.reputation, ReputationProtocol.checkpoint_sign,
                       to_json_string((key[0], key[1], str(voter), b'sig')),
                       rp.group, from_whom=MagicMock(uuid=voter))
        sign.verified = True
        assert rp.handle_checkpoint_sign({CfgIds.network: net_q}, sign) is True
        final = net_q.get_nowait()
        assert final.function == ReputationProtocol.checkpoint_final
        # Pending dropped -> a duplicate sign is now a no-op.
        assert key not in rp._checkpoint_pending

    def test_final_stores_checkpoint_on_receiver(self):
        proposer_id = uuid4()
        rp = _make_rep_process()
        rp.protocol.peers.all = [MagicMock(uuid=proposer_id)]
        ck = Checkpoint(proposer_uuid=proposer_id, root=b'c' * 64, epoch=2,
                        first_index=0, count=1)
        signed = SignedCheckpoint(checkpoint=ck, sigs={})
        final = Message(CfgIds.reputation, ReputationProtocol.checkpoint_final,
                        to_json_string(signed), rp.group,
                        from_whom=MagicMock(uuid=proposer_id))
        final.verified = True
        assert rp.handle_checkpoint_final({CfgIds.network: queue.Queue()}, final) is True
        assert rp._checkpoint is not None
        assert rp._checkpoint.key() == ck.key()

    def test_unverified_propose_rejected(self):
        rp = _make_rep_process()
        net_q = queue.Queue()
        ck = Checkpoint(proposer_uuid=uuid4(), root=b'd' * 64, epoch=1)
        msg = Message(CfgIds.reputation, ReputationProtocol.checkpoint_propose,
                      to_json_string(ck), rp.group,
                      from_whom=MagicMock(uuid=uuid4()))
        msg.verified = False
        assert rp.handle_checkpoint_propose({CfgIds.network: net_q}, msg) is True
        assert net_q.empty()  # no co-sign emitted
