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
import pytest
import queue
from queue import Full
from uuid import uuid4, UUID
from unittest.mock import MagicMock, patch, PropertyMock

from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    Reputation,
    TransactionScore, Transaction, TransactionHistory, Reputations,
)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import to_yaml_string, from_yaml_string


def _make_mock_peer(uid=None, nickname='peer1', address='10.0.0.1'):
    peer = MagicMock()
    peer.uuid = uid or uuid4()
    peer.nickname = nickname
    peer.address = address
    return peer


def _make_rep_process():
    log_q = queue.Queue()
    identity = MagicMock()
    identity.uuid = uuid4()

    mock_net_proc = MagicMock()
    mock_net_proc.name = CfgIds.network
    mock_id_proc = MagicMock()
    mock_id_proc.name = CfgIds.identity
    mock_neg_proc = MagicMock()
    mock_neg_proc.name = CfgIds.negotiation
    mock_rep_proc = MagicMock()
    mock_rep_proc.name = CfgIds.reputation

    configs = {
        'processes': [mock_net_proc, mock_id_proc, mock_neg_proc, mock_rep_proc],
        CfgIds.identity: identity,
        CfgIds.peers: MagicMock(),
        CfgIds.group: MagicMock(),
    }
    subsystems = ProcessTracker()
    rp = ReputationProcess(configs, subsystems, log_q, suppress_log=True)
    return rp


class TestReputationProcessInit:
    def test_init(self):
        rp = _make_rep_process()
        assert isinstance(rp.history, TransactionHistory)
        assert isinstance(rp.reputations, Reputations)
        assert rp.proposals == {}

    def test_properties(self):
        rp = _make_rep_process()
        assert rp.peers is rp.protocol.peers
        assert rp.group is rp.protocol.group


class TestPaxosIdIndex:
    def test_basic(self):
        idx = ReputationProcess._paxos_id_index(100, 5)
        assert idx == (100, 5)

    def test_larger(self):
        idx = ReputationProcess._paxos_id_index(1000, 99)
        assert idx == (1000, 99)


class TestHandleTransaction:
    def test_not_granted(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        score = TransactionScore(uuid4(), 0.8)
        data = ((100, 1, peer.uuid), score)
        msg = Message(CfgIds.reputation, ReputationProtocol.transaction,
                      to_yaml_string(data), from_whom=peer)
        result = rp.handle_transaction({CfgIds.network: queue.Queue()}, msg)
        assert result is True  # dropped (not in requests)

    def test_wrong_function(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong', 'data')
        result = rp.handle_transaction({}, msg)
        assert result is False


class TestHandleAccepted:
    def test_wrong_function(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong', 'data')
        result = rp.handle_accepted(None, msg)
        assert result is False


class TestHandleOutdated:
    def test_wrong_function(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong', 'data')
        result = rp.handle_outdated({}, msg)
        assert result is False

    def test_sends_update(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        net_q = queue.Queue()
        queues = {CfgIds.network: net_q}
        msg = Message(CfgIds.reputation, ReputationProtocol.outdated,
                      '0', from_whom=peer)
        result = rp.handle_outdated(queues, msg)
        assert result is True
        assert not net_q.empty()


class TestHandleUpdate:
    def test_wrong_function(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong', 'data')
        result = rp.handle_update({}, msg)
        assert result is False


class TestHandleReputationRequest:
    def test_wrong_function(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong', 'data')
        result = rp.handle_reputation_request(None, msg)
        assert result is False


class TestForwardTransaction:
    def test_not_transaction_score(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'func', 'data')
        result = rp.forward_transaction({}, msg)
        assert result is False


class TestForwardReputation:
    def test_empty(self):
        rp = _make_rep_process()
        rp.forward_reputation({})  # should not crash

    def test_with_pending(self):
        rp = _make_rep_process()
        from autonomous_trust.core.reputation.reputation import Reputation
        rep = Reputation(uuid4(), 0.9)
        # MagicMock requestor auto-creates a .uuid distinct from rp.identity.uuid,
        # so forward_reputation routes the rep_resp to the network queue.
        rp.requested_reps.append((rep, 'some_proc', MagicMock()))
        net_q = queue.Queue()
        queues = {'some_proc': queue.Queue(), CfgIds.network: net_q}
        rp.forward_reputation(queues)
        assert len(rp.requested_reps) == 0
        assert not net_q.empty()


class TestContriteTitForTat:
    def test_no_history(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        result = rp._contrite_tit_for_tat(peer)
        assert result == 0.2  # cold-start prior: PREREP_NEUTRAL

    def test_with_history(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        # Set up transactions
        tid = uuid4()
        rp.history.update(tid, peer.uuid, 0.8)
        rp.history.update(tid, rp.identity.uuid, 0.9)
        result = rp._contrite_tit_for_tat(peer)
        assert isinstance(result, float)


class TestPureReputation:
    def test_with_history(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        other = _make_mock_peer(nickname='other', address='10.0.0.2')
        rp.reputations.update(other.uuid, 0.8)
        tid = uuid4()
        rp.history.update(tid, peer.uuid, 0.7)
        rp.history.update(tid, other.uuid, 0.9)
        result = rp._pure_reputation(peer)
        assert isinstance(result, float)


class TestHandleTransactionDeeper:
    def test_a_proposal_naming_its_group_is_accepted(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8)

        rp._detached_sig = MagicMock(return_value='ab')  # a mock cannot sign
        net_q = queue.Queue()
        msg = Message(CfgIds.reputation, ReputationProtocol.transaction,
                      to_yaml_string(((id1, id2, peer.uuid), score, True, '')),
                      from_whom=peer)
        msg.verified = True  # simulate signed message (mock peer can't sign)
        result = rp.handle_transaction({CfgIds.network: net_q}, msg)
        assert result is True
        assert idx in rp.proposals
        assert not net_q.empty()       # `tx accepted` went back

    def test_a_half_round_proposal_is_dropped(self):
        """A two-element proposal is what a build from before every group
        placed its order sent after a grant. Nothing grants now, so it is
        dropped: no acceptance, nothing recorded."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        net_q = queue.Queue()
        msg = Message(CfgIds.reputation, ReputationProtocol.transaction,
                      to_yaml_string(((100, 1, peer.uuid),
                                      TransactionScore(uuid4(), 0.8))),
                      from_whom=peer)
        msg.verified = True
        assert rp.handle_transaction({CfgIds.network: net_q}, msg) is True
        assert net_q.empty()
        assert rp.proposals == {}

    def test_unknown_evidence_channel_is_dropped_not_raised(self):
        """A peer-supplied evidence channel outside the closed set is refused
        (R+D.md §12.8) — but the refusal must not escape as an exception.

        The check lives in TransactionScore's constructor, which the wire-side
        `from_yaml_string`/`from_json_string` reconstruction runs, so without the
        handler's catch a remote could raise inside this node's reputation
        process loop just by misspelling a channel. Same reasoning as the
        off-scale score path."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1, id2 = 100, 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8, channel='physical')

        payload = to_yaml_string(((id1, id2, peer.uuid), score, True, ''))
        assert 'physical' in payload
        payload = payload.replace('physical', 'physicall')

        net_q = queue.Queue()
        msg = Message(CfgIds.reputation, ReputationProtocol.transaction,
                      payload, from_whom=peer)
        msg.verified = True
        result = rp.handle_transaction({CfgIds.network: net_q}, msg)
        assert result is True          # consumed, not passed to another handler
        assert net_q.empty()           # and no `tx accepted` went back
        assert idx not in rp.proposals  # nothing recorded from a refused payload


class TestHandleAcceptedDeeper:
    def test_accepted_with_quorum(self):
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        peer2 = _make_mock_peer(nickname='p2')
        rp.protocol.peers.all = [peer1, peer2]

        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        tid = uuid4()
        score = TransactionScore(tid, 0.8)
        rp.proposals[idx] = score

        msg = Message(CfgIds.reputation, ReputationProtocol.accepted,
                      to_yaml_string((id1, id2, peer1.uuid)),
                      from_whom=peer1)
        msg.verified = True
        result = rp.handle_accepted(None, msg)
        assert result is True
        # It carries no signature over the half, so it is not counted.
        assert idx not in rp.acceptances



class TestHandleUpdateDeeper:
    def test_update_stores_and_returns_true(self):
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        rp.num_updates = 5  # High so we don't trigger majority logic

        msg = Message(CfgIds.reputation, ReputationProtocol.update,
                      to_yaml_string('chain_data'), from_whom=peer1)
        result = rp.handle_update({CfgIds.network: queue.Queue()}, msg)
        assert result is True
        assert peer1.uuid in rp.updates


class TestForwardTransactionDeeper:
    def test_valid_transaction_score(self):
        rp = _make_rep_process()
        score = TransactionScore(uuid4(), 0.8, subject_uuid=uuid4())
        net_q = queue.Queue()
        result = rp.forward_transaction({CfgIds.network: net_q}, score)
        assert result is True
        assert not net_q.empty()

    def test_updates_history(self):
        """forward_transaction kicks off Paxos but does NOT touch the
        local history.

        Mirrors the C twin (rep_proc.c:1081-1102 _forward_transaction)
        and the comment in repprocess.forward_transaction (line
        411-423): writing the proposer's side at submission time
        would later be overwritten by the proposer's own
        handle_accepted, producing a p1=self/p2=self self-transaction
        that CTFT silently rejected. History is updated solely from
        handle_accepted once the round commits.
        """
        rp = _make_rep_process()
        tid = uuid4()
        score = TransactionScore(tid, 0.7, subject_uuid=uuid4())
        net_q = queue.Queue()
        rp.forward_transaction({CfgIds.network: net_q}, score)
        # Paxos round started — the transaction proposal is on the wire,
        # but history stays empty until handle_accepted hits majority.
        assert tid not in rp.history._task_mapping
        assert len(rp.history) == 0
        assert not net_q.empty()  # propose-message queued for network


class TestStartPaxos:
    def test_start_paxos(self):
        rp = _make_rep_process()
        score = TransactionScore(uuid4(), 0.8)
        net_q = queue.Queue()
        rp._start_paxos({CfgIds.network: net_q}, score)
        assert not net_q.empty()
        assert len(rp.awaiting_commit) == 1
        assert len(rp.proposals) == 1


class TestComputeReputation:
    def test_tit_for_tat_mode(self, setup_teardown):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        # No previous reputation -> tit-for-tat mode
        rp._compute_reputation(peer, 'some_proc', MagicMock())
        assert peer.uuid in rp.reputations
        assert len(rp.requested_reps) == 1

    def test_cooperation_mode(self, setup_teardown):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        other = _make_mock_peer(nickname='other', address='10.0.0.2')
        # Set up reputation > 0.5 for cooperation mode
        rp.reputations.update(peer.uuid, 0.6)
        rp.reputations.update(other.uuid, 0.8)
        # Set up history for _pure_reputation
        tid = uuid4()
        rp.history.update(tid, peer.uuid, 0.7)
        rp.history.update(tid, other.uuid, 0.9)
        rp._compute_reputation(peer, 'proc', MagicMock())
        assert len(rp.requested_reps) == 1


class TestContriteTitForTatBranches:
    def test_defected_low_standing(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        # In _contrite_tit_for_tat, when p1_id==peer.uuid:
        #   peer_scores uses p2_score (identity's score), my_scores uses p1_score (peer's score)
        # We want: peer_scores[-1] < 0.5 (defected) AND my_standing < 0.5
        tid = uuid4()
        rp.history.update(tid, peer.uuid, 0.3)       # p1_score=0.3 -> my_scores
        rp.history.update(tid, rp.identity.uuid, 0.3) # p2_score=0.3 -> peer_scores
        result = rp._contrite_tit_for_tat(peer)
        assert result >= 0.51  # cooperate despite defection because my standing is low

    def test_defected_good_standing(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        # Need: peer's last score < 0.5 (peer defected) AND my own
        # standing >= 0.5. Per _contrite_tit_for_tat:626-631, when
        # peer fills p1 then peer_scores gets p1_score; when self
        # fills p2 then my_scores gets p2_score. So peer must
        # submit a low score (0.3) and self must submit a high one
        # (0.8). The earlier revision of this test had the values
        # swapped, asserting a punishment that never triggered.
        tid = uuid4()
        rp.history.update(tid, peer.uuid, 0.3)        # peer's score → peer_scores
        rp.history.update(tid, rp.identity.uuid, 0.8) # self's score → my_scores
        result = rp._contrite_tit_for_tat(peer)
        assert result <= 0.49  # punish defection

    def test_cooperate(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        # peer_scores[-1] >= 0.5 (cooperated)
        tid = uuid4()
        rp.history.update(tid, peer.uuid, 0.6)       # p1_score -> my_scores
        rp.history.update(tid, rp.identity.uuid, 0.7) # p2_score -> peer_scores (cooperated)
        result = rp._contrite_tit_for_tat(peer)
        assert result >= 0.51


class TestHandleOutdatedDeeper:
    def test_outdated_with_bytes_length(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        net_q = queue.Queue()
        msg = Message(CfgIds.reputation, ReputationProtocol.outdated,
                      b'0', from_whom=peer)
        result = rp.handle_outdated({CfgIds.network: net_q}, msg)
        assert result is True
        assert not net_q.empty()

    def test_outdated_with_history(self):
        rp = _make_rep_process()
        # Add some history
        tid = uuid4()
        peer = _make_mock_peer()
        rp.history.update(tid, peer.uuid, 0.5)
        rp.history.update(tid, rp.identity.uuid, 0.7)
        net_q = queue.Queue()
        msg = Message(CfgIds.reputation, ReputationProtocol.outdated,
                      '0', from_whom=peer)
        result = rp.handle_outdated({CfgIds.network: net_q}, msg)
        assert result is True


class TestHandleReputationRequest:
    def test_rep_req_with_tuple(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        requestor = _make_mock_peer(nickname='req')
        msg = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                      (peer, 'some_proc'), from_whom=requestor)
        result = rp.handle_reputation_request(None, msg)
        assert result is True

    def test_rep_req_wrong_function(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong', 'data')
        result = rp.handle_reputation_request(None, msg)
        assert result is False


class TestForwardReputationDeeper:
    def test_forward_with_items(self, setup_teardown):
        rp = _make_rep_process()
        from autonomous_trust.core.reputation.reputation import Reputation
        peer = _make_mock_peer()
        rep = Reputation(peer.uuid, 0.7)
        # peer has its own uuid != rp.identity.uuid, so the rep_resp is
        # routed via the network queue rather than the local proc queue.
        rp.requested_reps.append((rep, 'proc1', peer))
        net_q = queue.Queue()
        queues = {'proc1': queue.Queue(), CfgIds.network: net_q}
        rp.forward_reputation(queues)
        assert len(rp.requested_reps) == 0
        assert not net_q.empty()

    def test_forward_local_when_requestor_is_none(self, setup_teardown):
        """No requestor -> local routing onto the per-proc queue."""
        rp = _make_rep_process()
        from autonomous_trust.core.reputation.reputation import Reputation
        rep = Reputation(uuid4(), 0.7)
        rp.requested_reps.append((rep, 'proc1', None))
        proc_q = queue.Queue()
        queues = {'proc1': proc_q, CfgIds.network: queue.Queue()}
        rp.forward_reputation(queues)
        assert len(rp.requested_reps) == 0
        assert not proc_q.empty()

    def test_forward_local_when_requestor_is_self(self, setup_teardown):
        """Loopback requestor (our own identity) -> local proc queue."""
        rp = _make_rep_process()
        from autonomous_trust.core.reputation.reputation import Reputation
        rep = Reputation(uuid4(), 0.7)
        # Forge a requestor whose uuid matches rp.identity.uuid.
        self_requestor = MagicMock()
        self_requestor.uuid = rp.identity.uuid
        rp.requested_reps.append((rep, 'proc1', self_requestor))
        proc_q = queue.Queue()
        queues = {'proc1': proc_q, CfgIds.network: queue.Queue()}
        rp.forward_reputation(queues)
        assert len(rp.requested_reps) == 0
        assert not proc_q.empty()


class TestPureReputation:
    def test_pure_rep_computation(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        other = _make_mock_peer(nickname='o', address='10.0.0.3')
        rp.reputations.update(other.uuid, 0.8)
        tid = uuid4()
        rp.history.update(tid, peer.uuid, 0.7)
        rp.history.update(tid, other.uuid, 0.9)
        result = rp._pure_reputation(peer)
        assert isinstance(result, float)


class TestHandleUpdateMajority:
    def test_update_majority_agrees(self):
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1', address='10.0.0.1')
        peer2 = _make_mock_peer(nickname='p2', address='10.0.0.2')
        peer3 = _make_mock_peer(nickname='p3', address='10.0.0.3')
        rp.num_updates = 3

        # Use real Transaction chain data for catchup
        tid = uuid4()
        tx = Transaction(tid, peer1.uuid, 0.8, peer2.uuid, 0.7, index=1)
        chain_data = [tx]
        # The vote, not the certificates (test_commit_certificates.py).
        rp._chain_certified = lambda *a, **k: True
        for peer in [peer1, peer2, peer3]:
            msg = Message(CfgIds.reputation, ReputationProtocol.update,
                          to_yaml_string(chain_data), from_whom=peer)
            rp.handle_update({CfgIds.network: queue.Queue()}, msg)
        assert len(rp.updates) == 3

    def test_update_no_majority(self):
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1', address='10.0.0.1')
        peer2 = _make_mock_peer(nickname='p2', address='10.0.0.2')
        peer3 = _make_mock_peer(nickname='p3', address='10.0.0.3')
        rp.num_updates = 3
        rp.protocol.peers.all = [peer1, peer2, peer3]

        # Send 3 different updates - no majority so _request_update is called
        for i, peer in enumerate([peer1, peer2, peer3]):
            tid = uuid4()
            tx = Transaction(tid, peer.uuid, 0.5 + i * 0.1, rp.identity.uuid, 0.6 + i * 0.1)
            msg = Message(CfgIds.reputation, ReputationProtocol.update,
                          to_yaml_string([tx]), from_whom=peer)
            rp.handle_update({CfgIds.network: queue.Queue()}, msg)


class TestHandleRepReqStr:
    def test_rep_req_string_obj(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        # handle_reputation_request with str obj calls from_json_string
        # Use a UUID (serializable) instead of MagicMock for the identity part
        data = to_yaml_string((peer.uuid, 'some_proc'))
        msg = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                      data, from_whom=peer)
        result = rp.handle_reputation_request(None, msg)
        assert result is True


class TestHandleAcceptedAlreadyAccepted:
    def test_duplicate_acceptance(self):
        """Re-sending an ACCEPTED from a peer that already accepted
        must not double-add to acceptances.

        This scenario also crosses the majority threshold (1 peer
        cohort), so to keep the test focused on the duplicate-add
        guard we mark the paxos round as already committed
        (repprocess.py:454-455 short-circuits the commit branch).
        The previous revision passed ``None`` for queues and ran
        into the commit broadcast site — fails as a TypeError on
        ``queues[CfgIds.network].put`` rather than the actual
        assertion under test.
        """
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        rp.protocol.peers.all = [peer1]

        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        tid = uuid4()
        score = TransactionScore(tid, 0.8)
        rp.proposals[idx] = score
        rp.acceptances[idx] = {str(peer1.uuid)}  # already accepted
        rp.committed_paxos_rounds[idx] = None  # already committed

        msg = Message(CfgIds.reputation, ReputationProtocol.accepted,
                      to_yaml_string((id1, id2, peer1.uuid)),
                      from_whom=peer1)
        msg.verified = True
        result = rp.handle_accepted({CfgIds.network: queue.Queue()}, msg)
        assert result is True
        # Should not add duplicate
        assert len(rp.acceptances[idx]) == 1


# ---------------------------------------------------------------------------
# Additional tests targeting previously-uncovered lines
# ---------------------------------------------------------------------------

class TestHandleAcceptedDeeper2:
    """Cover handle_accepted majority path (lines 229-230 area): commits transaction."""

    def test_accepted_below_majority_no_commit(self):
        """Below-majority acceptances does NOT commit to history."""
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        peer2 = _make_mock_peer(nickname='p2')
        peer3 = _make_mock_peer(nickname='p3')
        rp.protocol.peers.all = [peer1, peer2, peer3]  # 3 peers → quorum = 1

        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        tid = uuid4()
        score = TransactionScore(tid, 0.8)
        rp.proposals[idx] = score

        # Only 1 acceptance → not > 1 (quorum), so no commit
        msg = Message(CfgIds.reputation, ReputationProtocol.accepted,
                      to_yaml_string((id1, id2, peer1.uuid)),
                      from_whom=peer1)
        result = rp.handle_accepted(None, msg)
        assert result is True
        assert len(rp.history) == 0


class TestHandleUpdateFullPaths:
    """Cover handle_update majority/minority paths (lines 277-278, 284-286)."""

    def test_update_majority_catchup(self):
        """Majority agreement on updates triggers catchup."""
        from autonomous_trust.core.reputation.reputation import Transaction
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        peer2 = _make_mock_peer(nickname='p2')
        rp.num_updates = 2

        tid = uuid4()
        tx = Transaction(tid, peer1.uuid, 0.8, peer2.uuid, 0.7, index=1)
        chain = [tx]
        # The vote, not the certificates (test_commit_certificates.py).
        rp._chain_certified = lambda *a, **k: True

        for peer in [peer1, peer2]:
            msg = Message(CfgIds.reputation, ReputationProtocol.update,
                          to_yaml_string(chain), from_whom=peer)
            rp.handle_update({CfgIds.network: queue.Queue()}, msg)

        # Both peers sent identical chain → majority agrees
        assert len(rp.updates) == 2

    def test_update_no_majority_requests_more(self):
        """No majority → error logged and _request_update called."""
        from autonomous_trust.core.reputation.reputation import Transaction
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        peer2 = _make_mock_peer(nickname='p2')
        peer3 = _make_mock_peer(nickname='p3')
        rp.num_updates = 3
        rp.protocol.peers.all = [peer1, peer2, peer3]
        rp.protocol.peers.find_top_n = MagicMock(return_value=[peer1, peer2, peer3])

        # Each peer sends a different chain → no majority
        for i, peer in enumerate([peer1, peer2, peer3]):
            tid = uuid4()
            tx = Transaction(tid, peer.uuid, 0.4 + i * 0.1, rp.identity.uuid, 0.5 + i * 0.1)
            msg = Message(CfgIds.reputation, ReputationProtocol.update,
                          to_yaml_string([tx]), from_whom=peer)
            rp.handle_update({CfgIds.network: queue.Queue()}, msg)

        assert len(rp.updates) == 3


class TestPureReputationBranches:
    """Cover _pure_reputation p1/p2 branches (lines 300-302)."""

    def test_pure_rep_p1_is_peer(self):
        """When tx.p1_id == peer.uuid and tx.p2_id has reputation, uses p2_score."""
        from autonomous_trust.core.reputation.reputation import Transaction
        rp = _make_rep_process()
        peer = _make_mock_peer()
        other = _make_mock_peer(nickname='other', address='10.0.0.2')
        rp.reputations.update(other.uuid, 0.9)
        tid = uuid4()
        # peer is p1, other is p2
        rp.history.update(tid, peer.uuid, 0.7)
        rp.history.update(tid, other.uuid, 0.8)
        result = rp._pure_reputation(peer)
        assert isinstance(result, float)
        # One entry: the weighted average is p2_score itself (trust-tiers.md §5)
        assert abs(result - 0.8) < 1e-9

    def test_pure_rep_p2_is_peer(self):
        """When tx.p2_id == peer.uuid and tx.p1_id has reputation, uses p1_score."""
        from autonomous_trust.core.reputation.reputation import Transaction
        rp = _make_rep_process()
        peer = _make_mock_peer()
        other = _make_mock_peer(nickname='other', address='10.0.0.2')
        rp.reputations.update(other.uuid, 0.8)
        tid = uuid4()
        # other is p1, peer is p2
        rp.history.update(tid, other.uuid, 0.6)
        rp.history.update(tid, peer.uuid, 0.7)
        result = rp._pure_reputation(peer)
        assert isinstance(result, float)
        # One entry: the weighted average is p1_score itself (trust-tiers.md §5)
        assert abs(result - 0.6) < 1e-9


class TestContriteTitForTatBranches2:
    """Cover _contrite_tit_for_tat branches (lines 313-315)."""

    def test_p2_is_peer_branch(self):
        """When tx.p2_id == peer.uuid and tx.p1_id == identity, uses p1/p2 scores."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        tid = uuid4()
        # identity is p1, peer is p2
        rp.history.update(tid, rp.identity.uuid, 0.7)
        rp.history.update(tid, peer.uuid, 0.8)
        result = rp._contrite_tit_for_tat(peer)
        # tx.p2_id==peer.uuid, tx.p1_id==identity.uuid:
        #   peer_scores.append(tx.p1_score=0.7), my_scores.append(tx.p2_score=0.8)
        # peer_scores[-1]=0.7 >= 0.5 → cooperate: max(0.51, peer_standing=0.7) = 0.7
        assert result >= 0.51

    def test_p1_is_peer_branch(self):
        """When tx.p1_id == peer.uuid and tx.p2_id == identity, uses p2/p1 scores."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        tid = uuid4()
        # peer is p1, identity is p2
        rp.history.update(tid, peer.uuid, 0.6)
        rp.history.update(tid, rp.identity.uuid, 0.7)
        result = rp._contrite_tit_for_tat(peer)
        # tx.p1_id==peer.uuid, tx.p2_id==identity.uuid:
        #   peer_scores.append(tx.p2_score=0.7), my_scores.append(tx.p1_score=0.6)
        # peer_scores[-1]=0.7 >= 0.5 → cooperate: max(0.51, 0.7) = 0.7
        assert result >= 0.51

    def test_no_matching_transactions(self):
        """Transactions with neither peer being the target peer return the
        cold-start prior PREREP_NEUTRAL (0.2)."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        other1 = _make_mock_peer(nickname='o1', address='10.0.0.2')
        other2 = _make_mock_peer(nickname='o2', address='10.0.0.3')
        tid = uuid4()
        # History entry but neither p1 nor p2 is peer
        rp.history.update(tid, other1.uuid, 0.7)
        rp.history.update(tid, other2.uuid, 0.8)
        result = rp._contrite_tit_for_tat(peer)
        assert result == 0.2  # not enough info → cold-start neutral


class TestForwardReputationFullException:
    """Cover Full exception in forward_reputation (lines 365-366)."""

    def test_forward_reputation_full_queue(self):
        """Full exception when putting rep_resp onto a queue."""
        from autonomous_trust.core.reputation.reputation import Reputation
        rp = _make_rep_process()
        peer = _make_mock_peer()
        rep = Reputation(peer.uuid, 0.8)
        proc_name = 'some_proc'
        rp.requested_reps.append((rep, proc_name, peer))

        # Remote-uuid requestor -> network route. Make the network queue
        # raise Full to exercise the except path.
        full_net_q = MagicMock()
        full_net_q.put = MagicMock(side_effect=Full)
        rp.forward_reputation({proc_name: queue.Queue(), CfgIds.network: full_net_q})
        # requested_reps is emptied regardless (pop happens before put).
        assert len(rp.requested_reps) == 0

    def test_forward_reputation_multiple_reps(self):
        """Multiple pending reps are all forwarded."""
        from autonomous_trust.core.reputation.reputation import Reputation
        rp = _make_rep_process()
        proc_name = 'proc1'
        net_q = queue.Queue()
        for i in range(3):
            peer = _make_mock_peer(nickname='p%d' % i, address='10.0.0.%d' % (i + 1))
            rep = Reputation(peer.uuid, 0.5 + i * 0.1)
            rp.requested_reps.append((rep, proc_name, peer))

        # All three peers are remote (uuid != rp.identity.uuid) -> network.
        rp.forward_reputation({proc_name: queue.Queue(), CfgIds.network: net_q})
        assert len(rp.requested_reps) == 0
        assert net_q.qsize() == 3


class TestRunningConsensus:
    """Primary-chain consensus is a persistent per-peer running EMA (folded
    once per committed tx), so a sliding bounded window can't reshape a peer's
    score — the fix for the synchronized dashboard "Trust Dynamics" sawtooth.
    The scored peer is committed as the shared p2 (counterparty p1 carries the
    'observed about P' score), matching the eviction pattern in
    test_reputation.py so p2 is mapped once per tx."""

    @staticmethod
    def _commit(rp, peer, observed):
        tid = uuid4()
        rp.history.update(tid, uuid4(), observed)  # counterparty (p1) score
        rp.history.update(tid, peer, 0.9)          # scored peer as p2
        # Mirror what handle_accepted / handle_committed do on a real commit:
        # fold the completed tx into the running consensus EMA immediately.
        rp._fold_committed_tx(tid, rp.history)

    def test_equivalent_to_recompute_without_eviction(self):
        # No eviction (chain far under the cap): the running EMA folds the same
        # txs in the same order from the same seed as the from-scratch
        # recompute, so the value is identical. This is what keeps the
        # conformance/parity corpora (small, non-evicting) unaffected.
        rp = _make_rep_process()
        P = uuid4()
        for sc in [0.3, 0.8, 0.8, 0.5, 0.8, 0.2, 0.8, 0.8]:
            self._commit(rp, P, sc)
        running = rp._consensus_reputation(P)                  # chain=None path
        recompute = rp._consensus_reputation(P, chain=rp.history)
        assert abs(running - recompute) < 1e-12

    def test_no_wobble_between_commits(self):
        # Repeated queries with no new tx return the exact same value — the
        # sawtooth was the value changing between commits as the window slid.
        rp = _make_rep_process()
        rp.history = TransactionHistory(max_chain_len=4)
        P = uuid4()
        trace = []
        for sc in [0.3, 0.3, 0.3, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8]:
            self._commit(rp, P, sc)
            vals = [rp._consensus_reputation(P) for _ in range(4)]
            assert len(set(vals)) == 1          # identical between commits
            trace.append(vals[0])
        # On monotonically-improving input the running score rises smoothly and
        # never reverses (no teeth), even though the 4-entry window slides.
        tail = trace[3:]
        assert all(b >= a - 1e-9 for a, b in zip(tail, tail[1:]))

    def test_retains_history_after_eviction_without_querying(self):
        # Early defections (0.3) evict from the 4-entry window. Because folding
        # happens ON COMMIT (not on query), the running EMA still reflects the
        # early lows even though consensus is queried ONLY at the end — whereas
        # a from-scratch recompute sees only the resident (all-0.8) tail and
        # snaps up, the jump that made the teeth. This is query-independence.
        rp = _make_rep_process()
        rp.history = TransactionHistory(max_chain_len=4)
        P = uuid4()
        for sc in [0.3, 0.3, 0.3, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8]:
            self._commit(rp, P, sc)             # NO query during the sequence
        running = rp._consensus_reputation(P)
        resident_only = rp._consensus_reputation(P, chain=rp.history)
        assert abs(running - resident_only) > 1e-6
        assert running < resident_only          # remembers the early lows

    def test_fold_on_commit_matches_query_folding(self):
        # Folding on commit (no queries during) yields exactly the same value
        # as folding lazily on every-cycle queries — the hook is just eager.
        seq = [0.3, 0.3, 0.8, 0.5, 0.8, 0.8, 0.2, 0.8, 0.8, 0.8]
        rp_eager = _make_rep_process()
        rp_eager.history = TransactionHistory(max_chain_len=4)
        P = uuid4()
        for sc in seq:
            self._commit(rp_eager, P, sc)       # fold-on-commit only
        rp_lazy = _make_rep_process()
        rp_lazy.history = TransactionHistory(max_chain_len=4)
        Q = uuid4()
        for sc in seq:
            self._commit(rp_lazy, Q, sc)
            rp_lazy._consensus_reputation(Q)    # also query every cycle
        assert abs(rp_eager._consensus_reputation(P)
                   - rp_lazy._consensus_reputation(Q)) < 1e-12

    def test_child_chain_commit_not_folded_into_primary(self):
        # A commit routed to a gateway CHILD chain must not touch the primary
        # running EMA (child peers score via the from-scratch recompute).
        rp = _make_rep_process()
        child = TransactionHistory()
        P = uuid4()
        tid = uuid4()
        child.update(tid, uuid4(), 0.8)
        child.update(tid, P, 0.9)
        rp._fold_committed_tx(tid, child)       # child chain, not self.history
        assert str(P) not in rp._consensus_ema

    def test_slash_override_still_floors(self):
        # A finalized slash floors the score regardless of the running EMA, and
        # syncs the stored EMA so a later lift resumes from the floor.
        rp = _make_rep_process()
        P = uuid4()
        for sc in [0.8, 0.8, 0.8]:
            self._commit(rp, P, sc)
        assert rp._consensus_reputation(P) > 0.5
        rp._slashed[str(P)] = (0.05, 'test')
        assert rp._consensus_reputation(P) == 0.05
        assert rp._consensus_ema[str(P)] == 0.05


class TestScoreRangeAtTheRemoteBoundary:
    """The [0, 1] score bound (doc/architecture/reputation.md) on the paths a PEER
    controls. The constructor raises on an
    out-of-range score, and `from_json_string` runs the constructor — so without
    a catch, a remote could raise inside this node's reputation loop. Every
    handler here must drop the message instead, and history must stay clean.
    """

    @staticmethod
    def _proposal(score_json, id1=100, id2=5, peer_id=None):
        """A `transaction` message whose payload carries `score_json` verbatim,
        which is how an out-of-range score would actually arrive."""
        peer_id = peer_id or uuid4()
        payload = ('[[%d, %d, "%s"], {"__type__": "autonomous_trust.core.'
                   '_python.reputation.reputation.TransactionScore", '
                   '"task_id": {"__type__": "UUID", "__value__": "%s"}, '
                   '"score": %s, "capability_name": null}, true, ""]'
                   % (id1, id2, peer_id, uuid4(), score_json))
        msg = MagicMock()
        msg.function = ReputationProtocol.transaction
        msg.obj = payload
        msg.verified = True
        msg.from_whom = _make_mock_peer()
        return msg

    def test_an_out_of_range_proposal_is_dropped_not_raised(self):
        rp = _make_rep_process()
        msg = self._proposal('7.5')
        assert rp.handle_transaction({}, msg) is True     # consumed, no raise
        assert rp.proposals == {}                         # nothing recorded

    def test_a_nan_proposal_is_dropped(self):
        rp = _make_rep_process()
        assert rp.handle_transaction({}, self._proposal('NaN')) is True
        assert rp.proposals == {}

    def test_an_in_range_proposal_still_lands(self):
        """The negative control: the drop must not swallow honest traffic."""
        rp = _make_rep_process()
        queues = {CfgIds.network: queue.Queue()}
        assert rp.handle_transaction(queues, self._proposal('0.75')) is True
        assert list(rp.proposals.values())[0].score == 0.75

    @staticmethod
    def _rp():
        rp = _make_rep_process()
        rp._commit_cert_ok = lambda *a, **k: True
        rp._half_sig_ok = lambda *a, **k: True
        return rp

    @staticmethod
    def _committed(score_json, peer_id=None, task_id=None, names=None):
        """`committed` carries a BARE float, so it bypasses the constructor
        entirely -- and it is the path that pools a half on every acceptor.
        It carries a stand-in certificate and scorer signature, which `_rp`
        accepts: the range check is the subject here, certificates are
        test_commit_certificates' and signed halves test_bilateral_halves'."""
        peer_id = peer_id or uuid4()
        task_id = task_id or uuid4()
        names = names or uuid4()
        msg = MagicMock()
        msg.function = ReputationProtocol.committed
        msg.obj = ('[{"__type__": "UUID", "__value__": "%s"}, '
                   '{"__type__": "UUID", "__value__": "%s"}, %s, null, null, '
                   '{"signer": "ab"}, "%s", "cd"]'
                   % (task_id, peer_id, score_json, names))
        msg.verified = True
        msg.from_whom = _make_mock_peer()
        # A commit writes its SENDER's own half (ISSUES.md §2.16, shape 2), so
        # the sender is the peer the payload names.
        msg.from_whom.uuid = peer_id
        return msg

    def _assert_not_staged(self, rp, score_json):
        """An accepted half waits in the pool and leaves the chain empty, so
        asserting on `len(history)` alone would pass whether or not the score
        was rejected. Assert on the pool."""
        task_id = uuid4()
        before = len(rp.history)
        assert rp.handle_committed(
            None, self._committed(score_json, task_id=task_id)) is True
        assert rp.history.pooled(task_id) is None          # never even pooled
        assert len(rp.history) == before

    def test_an_out_of_range_committed_tx_never_reaches_history(self):
        self._assert_not_staged(self._rp(), '42.0')

    def test_a_negative_committed_tx_never_reaches_history(self):
        self._assert_not_staged(self._rp(), '-3.0')

    def test_a_nan_committed_tx_never_reaches_history(self):
        self._assert_not_staged(self._rp(), 'NaN')

    def test_an_honest_committed_tx_is_staged(self):
        """Control for the assertion above: an in-range score DOES stage."""
        rp = self._rp()
        task_id = uuid4()
        rp.handle_committed(None, self._committed('0.9', task_id=task_id))
        assert rp.history.pooled(task_id) is not None

    def test_an_in_range_committed_tx_is_recorded(self):
        """The negative control: the drop must not swallow honest traffic.
        Two sides of ONE task make an entry ready to be placed."""
        rp = self._rp()
        task_id, a, b = uuid4(), uuid4(), uuid4()
        assert rp.handle_committed(None, self._committed(
            '0.9', peer_id=a, task_id=task_id, names=b)) is True
        assert rp.handle_committed(None, self._committed(
            '0.8', peer_id=b, task_id=task_id, names=a)) is True
        assert len(rp.history.pooled(task_id)) == 2

    def test_a_rejected_side_cannot_complete_a_transaction(self):
        """The consequence that matters: one honest side plus one out-of-range
        side must NOT commit, or the rejection would only have delayed it."""
        rp = self._rp()
        task_id, a, b = uuid4(), uuid4(), uuid4()
        rp.handle_committed(None, self._committed('0.9', peer_id=a,
                                                  task_id=task_id, names=b))
        rp.handle_committed(None, self._committed('42.0', peer_id=b,
                                                  task_id=task_id, names=a))
        assert len(rp.history) == 0
        assert len(rp.history.pooled(task_id)) == 1


class TestAppFacingReputationRated:
    """The app-facing peer carrier (doc/architecture/app-peer-carrier.md), a copy
    of the C twin's design (rep_proc.c + app_events.h):
    the app-facing carrier says whether AT holds a rating at all, because an
    unrated peer reads as PREREP_NEUTRAL — which is also a score a peer can
    genuinely earn — and a consumer given only the number cannot tell them apart.

    Deliberately NOT on the peer-to-peer wire: `Reputation` / `rep_resp` are
    untouched, exactly as in C, so this costs no .proto change.
    """

    def _rp_with_queue(self, peers=()):
        rp = _make_rep_process()
        main_q = queue.Queue()
        rp.protocol.peers = MagicMock()
        rp.protocol.peers.all = list(peers)
        return rp, {CfgIds.main: main_q}, main_q

    @staticmethod
    def _drain(q):
        out = []
        while True:
            try:
                out.append(q.get_nowait())
            except queue.Empty:
                return out

    def test_the_verb_matches_the_c_spelling(self):
        """The protocol strings ARE the shared wire form; a prettier Python
        spelling would break interop (see the REP_PROTO alignment note)."""
        assert ReputationProtocol.app_roster_request == 'app_roster_request'

    def test_a_rated_peer_carries_its_score(self):
        peer = _make_mock_peer()
        rp, queues, main_q = self._rp_with_queue([peer])
        rp.reputations.update(UUID(str(peer.uuid)), 0.73)
        assert rp.emit_all_reputations(queues) == 1      # the peer; never self
        emitted = {e.peer_uuid: e for e in self._drain(main_q)}
        assert emitted[str(peer.uuid)].rated is True
        assert emitted[str(peer.uuid)].score == pytest.approx(0.73)

    def test_an_unrated_peer_is_emitted_as_unrated_not_skipped(self):
        """Silence would leave a consumer unable to tell 'we hold no rating'
        from 'the message was lost'."""
        peer = _make_mock_peer()
        rp, queues, main_q = self._rp_with_queue([peer])
        rp.emit_all_reputations(queues)
        emitted = {e.peer_uuid: e for e in self._drain(main_q)}
        assert str(peer.uuid) in emitted
        assert emitted[str(peer.uuid)].rated is False

    def test_an_unrated_score_is_zeroed_not_neutral(self):
        """C zeroes it so a consumer that ignores the flag cannot silently read
        a plausible-looking number; 0.2 would be exactly that."""
        peer = _make_mock_peer()
        rp, queues, main_q = self._rp_with_queue([peer])
        rp.emit_all_reputations(queues)
        unrated = [e for e in self._drain(main_q) if not e.rated]
        assert unrated
        for entry in unrated:
            assert entry.score == 0.0
            assert entry.score != rp.PREREP_NEUTRAL

    def test_the_pull_handler_emits_for_every_peer(self):
        peer_a, peer_b = _make_mock_peer(), _make_mock_peer()
        rp, queues, main_q = self._rp_with_queue([peer_a, peer_b])
        msg = MagicMock()
        msg.function = ReputationProtocol.app_roster_request
        msg.from_whom = None                            # the local app's
        assert rp.handle_app_roster_request(queues, msg) is True
        assert len(self._drain(main_q)) == 2            # the peers; never self

    def test_a_peers_pull_is_refused(self):
        """The local app's verb only (ISSUES §2.17): a frame carrying a
        peer's identity replays nothing. Mirrors the C guard in
        handle_app_roster_request."""
        peer = _make_mock_peer()
        rp, queues, main_q = self._rp_with_queue([peer])
        msg = MagicMock()
        msg.function = ReputationProtocol.app_roster_request
        msg.from_whom = peer
        assert rp.handle_app_roster_request(queues, msg) is True
        assert self._drain(main_q) == []

    def test_the_roster_never_carries_this_node_itself(self):
        """Peers only. A reputation is what the network observed ABOUT a peer,
        and a node holds no such observation of itself; a self-entry could only
        carry its own unrated 0.0, which a consumer cannot tell from a genuine
        unrated peer. C's reputation_emit_all walks its peers array and has
        always emitted N -- Python emitted N+1 until this was aligned."""
        peer = _make_mock_peer()
        rp, queues, main_q = self._rp_with_queue([peer])
        rp.emit_all_reputations(queues)
        emitted = {e.peer_uuid for e in self._drain(main_q)}
        assert emitted == {str(peer.uuid)}
        assert str(rp.identity.uuid) not in emitted

    def test_the_handler_declines_other_verbs(self):
        rp, queues, main_q = self._rp_with_queue([_make_mock_peer()])
        msg = MagicMock()
        msg.function = ReputationProtocol.rep_req
        assert rp.handle_app_roster_request(queues, msg) is False
        assert self._drain(main_q) == []

    def test_a_change_driven_emission_is_rated_by_construction(self):
        rp, queues, main_q = self._rp_with_queue()
        rp._publish_reputation_change(queues, uuid4(), 0.42)
        emitted = self._drain(main_q)
        assert [e.rated for e in emitted] == [True]
        assert emitted[0].score == pytest.approx(0.42)

    def test_publishing_without_a_main_queue_is_not_an_error(self):
        """Unit/embedded use has no app feed; that is not a failure."""
        rp = _make_rep_process()
        rp._publish_reputation_change({}, uuid4(), 0.42)    # must not raise

    def test_the_peer_to_peer_wire_form_is_unchanged(self):
        """The whole point of copying C's placement: no .proto change, no
        conformance churn. `Reputation` still carries exactly two fields."""
        rep = Reputation(uuid4(), 0.5)
        assert not hasattr(rep, 'rated')


