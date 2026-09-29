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
"""Phase 2 quorum-signed Merkle checkpoint tests.

Exercises the propose -> sign -> final flow: a proposer commits to its own
window_root, members co-sign ONLY when their own window_root matches, and a
finalized checkpoint stores the agreed commitment. See
reputation-vs-blockchain-analysis.md §2.1 and reputation.py
Checkpoint/SignedCheckpoint.
"""
import hashlib
import queue
from uuid import UUID, uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    Checkpoint, SignedCheckpoint, TransactionHistory,
)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import to_json_string, from_json_string


def _identity(tag: str, uuid=None) -> Identity:
    """A real identity with a signing key DISTINCT per tag.

    Distinctness is the whole point since checkpoint co-signatures became
    verifiable: a signature made by one member must fail against another
    member's key, so a shared seed would make every negative control pass for
    the wrong reason. Deterministic (derived from the tag, not `hash()`, which
    is salted per process) so a failure reproduces. ``Identity.uuid`` is
    read-only, hence passed in rather than assigned after the fact.
    """
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(uuid or UUID(bytes=hashlib.md5(tag.encode()).digest()),
                    '10.0.0.1', '%s.test' % tag,
                    Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False),
                    _public_only=False)


def _cosign(voter: Identity, ckpt: Checkpoint) -> str:
    """A voter's detached co-signature over the checkpoint designation, in the
    ASCII-hex form handle_checkpoint_sign verifies."""
    return voter.sign(ckpt.designation).signature.decode('ascii')


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
        proposer = _identity('proposer')
        proposer_id = proposer.uuid
        member = _make_rep_process()
        member.protocol.peers.all = [proposer]
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
                          from_whom=proposer)
        propose.verified = True
        assert member.handle_checkpoint_propose(queues, propose) is True
        sign = net_q.get_nowait()
        assert sign.function == ReputationProtocol.checkpoint_sign
        # The ack carries a real detached signature over the designation, not a bare
        # uuid: the proposer counts signatures now. The ack gained a trailing chain key
        # (doc/architecture/gateway-reputation-tree.md): '' is the primary chain, a
        # group-uuid names one of a gateway's child chains.
        _tgt, _epoch, voter, sig, chain = from_json_string(sign.obj)
        assert chain == ''
        assert voter == str(member.identity.uuid)
        assert member._verify_cosignature(ck.designation, voter, sig)

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
        voter = _identity('voter')
        rp.protocol.peers.all = [voter]  # quorum floor(1/2)=0
        _fill(rp, 3)
        net_q = queue.Queue()
        rp.forward_checkpoint({CfgIds.network: net_q}, Checkpoint(None, b''))
        net_q.get_nowait()  # drain the checkpoint_propose
        ck = rp._checkpoint  # epoch stamped by forward_checkpoint
        key = ck.key()
        sign = Message(CfgIds.reputation, ReputationProtocol.checkpoint_sign,
                       to_json_string((key[0], key[1], str(voter.uuid),
                                       _cosign(voter, ck))),
                       rp.group, from_whom=voter)
        sign.verified = True
        assert rp.handle_checkpoint_sign({CfgIds.network: net_q}, sign) is True
        final = net_q.get_nowait()
        assert final.function == ReputationProtocol.checkpoint_final
        # The finalizer carries the retained co-signatures -- the proposer's
        # own plus the voter's -- so a receiver can check quorum itself.
        signed = (final.obj if isinstance(final.obj, SignedCheckpoint)
                  else from_json_string(final.obj))
        assert set(signed.sigs) == {str(rp.identity.uuid), str(voter.uuid)}
        # Pending dropped -> a duplicate sign is now a no-op.
        assert key not in rp._checkpoint_pending

    def test_final_stores_checkpoint_on_receiver(self):
        # Two signers of a three-member group: a majority of the WHOLE group,
        # this node included. The proposer alone in a two-member group used to
        # finalize (ISSUES.md §2.22).
        proposer, other = _identity('proposer'), _identity('other')
        rp = _make_rep_process()
        rp.protocol.peers.all = [proposer, other]
        ck = Checkpoint(proposer_uuid=proposer.uuid, root=b'c' * 64, epoch=2,
                        first_index=0, count=1)
        signed = SignedCheckpoint(
            checkpoint=ck, sigs={str(proposer.uuid): _cosign(proposer, ck),
                                 str(other.uuid): _cosign(other, ck)})
        final = Message(CfgIds.reputation, ReputationProtocol.checkpoint_final,
                        to_json_string(signed), rp.group,
                        from_whom=proposer)
        final.verified = True
        assert rp.handle_checkpoint_final({CfgIds.network: queue.Queue()}, final) is True
        assert rp._checkpoint is not None
        assert rp._checkpoint.key() == ck.key()

    def test_final_without_cosignatures_refused(self):
        """Negative control for the pre-fix behaviour: an empty `sigs` used to
        be stored on transport authentication alone, which let any single
        member choose the root that slash evidence is measured against."""
        proposer = _identity('proposer')
        rp = _make_rep_process()
        rp.protocol.peers.all = [proposer, _identity('bystander')]
        ck = Checkpoint(proposer_uuid=proposer.uuid, root=b'e' * 64, epoch=3,
                        first_index=0, count=1)
        final = Message(CfgIds.reputation, ReputationProtocol.checkpoint_final,
                        to_json_string(SignedCheckpoint(checkpoint=ck, sigs={})),
                        rp.group, from_whom=proposer)
        final.verified = True
        assert rp.handle_checkpoint_final({CfgIds.network: queue.Queue()}, final) is True
        assert rp._checkpoint is None

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


class TestOutvotedRequestsTheQuorumChain:
    """mod-2537396 and mod-2538837 (2026-09-23): an order fork at EQUAL length
    never reconciled, because catch-up runs only when a grant finds the lengths
    differ. A quorate checkpoint our chain does not reproduce now asks its
    finalizer for its chain. Mirrors C
    test_an_outvoted_node_requests_and_adopts_the_quorum_chain."""

    def _setup(self):
        proposer = _identity('proposer')
        rp = _make_rep_process()
        # A third member co-signs the final: a majority of the whole group
        # (ISSUES.md §2.22) that this node did not join.
        self.other = _identity('other')
        rp.protocol.peers.all = [proposer, self.other]
        tasks = {c: uuid4() for c in 'abcx'}
        ours, theirs = rp.history, TransactionHistory()
        for hist, letters in ((ours, 'abx'), (theirs, 'abc')):
            for c in letters:
                hist.update(tasks[c], rp.identity.uuid, 0.7)
                hist.update(tasks[c], proposer.uuid, 0.6)
        return proposer, rp, theirs

    @staticmethod
    def _final(rp, proposer, root):
        ck = Checkpoint(proposer_uuid=proposer.uuid, root=root, epoch=2,
                        first_index=0, count=3)
        other = next(p for p in rp.protocol.peers.all if p is not proposer)
        signed = SignedCheckpoint(
            checkpoint=ck, sigs={str(proposer.uuid): _cosign(proposer, ck),
                                 str(other.uuid): _cosign(other, ck)})
        final = Message(CfgIds.reputation, ReputationProtocol.checkpoint_final,
                        to_json_string(signed), rp.group, from_whom=proposer)
        final.verified = True
        return final

    @staticmethod
    def _requests(q):
        out = []
        while not q.empty():
            m = q.get_nowait()
            if m.function == ReputationProtocol.outdated:
                out.append(m)
        return out

    def test_a_final_over_our_chain_asks_nothing(self):
        proposer, rp, _ = self._setup()
        net_q = queue.Queue()
        rp.handle_checkpoint_final({CfgIds.network: net_q},
                                   self._final(rp, proposer,
                                               rp.history.window_root()))
        assert self._requests(net_q) == []

    def test_a_final_over_another_chain_asks_its_finalizer(self):
        proposer, rp, theirs = self._setup()
        net_q = queue.Queue()
        rp.handle_checkpoint_final({CfgIds.network: net_q},
                                   self._final(rp, proposer,
                                               theirs.window_root()))
        reqs = self._requests(net_q)
        assert len(reqs) == 1
        to = reqs[0].to_whom
        to = to[0] if isinstance(to, list) else to
        assert str(to.uuid) == str(proposer.uuid)
        assert str(reqs[0].obj) == '0'
