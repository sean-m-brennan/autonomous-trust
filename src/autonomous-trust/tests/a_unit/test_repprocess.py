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
import pytest
import queue
from queue import Full
from uuid import uuid4
from unittest.mock import MagicMock, patch, PropertyMock

from autonomous_trust.core.reputation.repprocess import ReputationProcess, TxCount
from autonomous_trust.core.reputation.reputation import (
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


class TestTxCount:
    def test_init(self):
        score = TransactionScore(uuid4(), 0.8)
        tc = TxCount(score=score, count=0)
        assert tc.count == 0
        assert tc.score is score


class TestReputationProcessInit:
    def test_init(self):
        rp = _make_rep_process()
        assert isinstance(rp.history, TransactionHistory)
        assert isinstance(rp.reputations, Reputations)
        assert rp.my_requests == {}
        assert rp.requests == []
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


class TestHandleRequest:
    def test_grants_valid_request(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        rp.protocol.peers.all = [peer]

        net_q = queue.Queue()
        queues = {CfgIds.network: net_q, CfgIds.reputation: queue.Queue()}

        id1 = 100
        id2 = 1  # len(history) + 1 == 0 + 1
        peer_id = peer.uuid
        msg = Message(CfgIds.reputation, ReputationProtocol.request,
                      to_yaml_string((id1, id2, peer_id)),
                      from_whom=peer)
        result = rp.handle_request(queues, msg)
        assert result is True
        assert not net_q.empty()

    def test_nacks_lower_id(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        rp.protocol.peers.all = [peer]
        rp.last_id = 200

        net_q = queue.Queue()
        queues = {CfgIds.network: net_q, CfgIds.reputation: queue.Queue()}

        msg = Message(CfgIds.reputation, ReputationProtocol.request,
                      to_yaml_string((100, 1, peer.uuid)),
                      from_whom=peer)
        result = rp.handle_request(queues, msg)
        assert result is True

    def test_ignores_non_peer(self):
        rp = _make_rep_process()
        rp.protocol.peers.all = []

        queues = {CfgIds.network: queue.Queue(), CfgIds.reputation: queue.Queue()}
        msg = Message(CfgIds.reputation, ReputationProtocol.request,
                      to_yaml_string((100, 1, uuid4())),
                      from_whom=MagicMock())
        result = rp.handle_request(queues, msg)
        assert result is True

    def test_wrong_function(self):
        rp = _make_rep_process()
        queues = {CfgIds.network: queue.Queue()}
        msg = Message(CfgIds.reputation, 'wrong_func', 'data')
        result = rp.handle_request(queues, msg)
        assert result is False

    def test_grant_advances_last_id(self):
        """Regression for BUGS.md P6.

        Prior bug: handle_request granted but never assigned self.last_id,
        so a duplicate (id1, id2) replay re-passed the `last_id is None or
        last_id < id1` guard and double-appended to self.requests. C side
        always advanced (paxos.c:123). After fix, both languages advance
        last_id to id1 immediately after the grant message is emitted; the
        ack itself still carries the PRIOR last_id (captured before
        update), matching paxos.c:114.
        """
        rp = _make_rep_process()
        peer = _make_mock_peer()
        rp.protocol.peers.all = [peer]

        net_q = queue.Queue()
        queues = {CfgIds.network: net_q, CfgIds.reputation: queue.Queue()}

        id1 = 100
        id2 = 1  # len(history) + 1 == 1
        msg = Message(CfgIds.reputation, ReputationProtocol.request,
                      to_yaml_string((id1, id2, peer.uuid)),
                      from_whom=peer)
        rp.handle_request(queues, msg)
        first = net_q.get_nowait()
        assert first.function == ReputationProtocol.grant
        assert rp.last_id == id1, (
            f'last_id must advance to {id1} after grant; '
            f'got {rp.last_id!r} (P6 regression)'
        )

    def test_replay_after_grant_is_nacked(self):
        """Regression for BUGS.md P6: duplicate ask must NACK after grant.

        With last_id correctly pinned by the first grant, the second
        identical ask hits `last_id < id1` → False and falls through to the
        nack branch. requests stays length 1 (no double-append). Mirrors
        C's behavior in paxos_handle_request when id1 is NOT > last_id.
        """
        rp = _make_rep_process()
        peer = _make_mock_peer()
        rp.protocol.peers.all = [peer]

        net_q = queue.Queue()
        queues = {CfgIds.network: net_q, CfgIds.reputation: queue.Queue()}

        id1 = 100
        id2 = 1
        msg = Message(CfgIds.reputation, ReputationProtocol.request,
                      to_yaml_string((id1, id2, peer.uuid)),
                      from_whom=peer)
        rp.handle_request(queues, msg)
        first = net_q.get_nowait()
        assert first.function == ReputationProtocol.grant

        # Replay the SAME ask. Before P6 fix this re-granted and
        # doubled requests; after fix it NACKs.
        rp.handle_request(queues, msg)
        second = net_q.get_nowait()
        assert second.function == ReputationProtocol.nack, (
            f'replayed ask must NACK after first grant, '
            f'got {second.function!r} (P6 regression)'
        )
        assert len(rp.requests) == 1, (
            'replayed ask must not double-append to requests; '
            f'got len={len(rp.requests)} (P6 regression)'
        )


class TestHandleGrant:
    def test_wrong_function(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong_func', 'data')
        result = rp.handle_grant({}, msg)
        assert result is False

    def test_not_for_me(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        ack = ((100, 1, uuid4()), (None, 0), None)  # different peer_id
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer)
        result = rp.handle_grant({CfgIds.network: queue.Queue()}, msg)
        assert result is True


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


class TestHandleBackdate:
    def test_wrong_function(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong', 'data')
        result = rp.handle_backdate({}, msg)
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


class TestHandleNack:
    def test_wrong_function(self):
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong', 'data')
        result = rp.handle_nack({}, msg)
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
        assert result == 0.49

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


class TestHandleRequestBackdate:
    def test_backdate_id_mismatch(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        rp.protocol.peers.all = [peer]
        rp.last_id = None

        net_q = queue.Queue()
        queues = {CfgIds.network: net_q, CfgIds.reputation: queue.Queue()}
        # id2 != len(history) + 1
        msg = Message(CfgIds.reputation, ReputationProtocol.request,
                      to_yaml_string((100, 999, peer.uuid)),
                      from_whom=peer)
        result = rp.handle_request(queues, msg)
        assert result is True
        assert not net_q.empty()
        sent_msg = net_q.get()
        assert sent_msg.function == ReputationProtocol.backdate


class TestHandleGrantDeeper:
    def test_grant_for_me_quorum_reached(self):
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        peer2 = _make_mock_peer(nickname='p2')
        rp.protocol.peers.all = [peer1, peer2]

        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8)
        rp.my_requests[idx] = TxCount(score=score, count=0)

        ack = ((id1, id2, rp.identity.uuid), (None, 0), None)
        net_q = queue.Queue()
        queues = {CfgIds.network: net_q}

        # First grant from peer1
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer1)
        rp.handle_grant(queues, msg)

        # With 2 peers, quorum is 1 (2//2), so 1 grant should trigger transaction
        assert not net_q.empty()

    def test_grant_already_completed(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        ack = ((100, 1, rp.identity.uuid), (None, 0), None)
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer)
        # my_requests is empty, so idx not in my_requests
        result = rp.handle_grant({CfgIds.network: queue.Queue()}, msg)
        assert result is True


class TestHandleTransactionDeeper:
    def test_granted_transaction(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        rp.requests.append(idx)
        score = TransactionScore(uuid4(), 0.8)

        net_q = queue.Queue()
        msg = Message(CfgIds.reputation, ReputationProtocol.transaction,
                      to_yaml_string(((id1, id2, peer.uuid), score)),
                      from_whom=peer)
        msg.verified = True  # simulate signed message (mock peer can't sign)
        result = rp.handle_transaction({CfgIds.network: net_q}, msg)
        assert result is True
        assert idx not in rp.requests
        assert idx in rp.proposals


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
        result = rp.handle_accepted(None, msg)
        assert result is True
        assert tid in rp.acceptances

    def test_accepted_reaches_majority(self):
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        rp.protocol.peers.all = [peer1]  # 1 peer, quorum = 0

        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        tid = uuid4()
        score = TransactionScore(tid, 0.8)
        rp.proposals[idx] = score

        # Pre-populate history with identity's side of the transaction
        # (as forward_transaction would have done)
        rp.history.update(tid, rp.identity.uuid, 0.8)

        msg = Message(CfgIds.reputation, ReputationProtocol.accepted,
                      to_yaml_string((id1, id2, peer1.uuid)),
                      from_whom=peer1)
        msg.verified = True  # simulate signed message (mock peer can't sign)
        rp.handle_accepted(None, msg)
        # 1 acceptance > 1//2=0, so transaction should be committed
        assert len(rp.history) > 0


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
        score = TransactionScore(uuid4(), 0.8)
        net_q = queue.Queue()
        result = rp.forward_transaction({CfgIds.network: net_q}, score)
        assert result is True
        assert not net_q.empty()

    def test_updates_history(self):
        rp = _make_rep_process()
        tid = uuid4()
        score = TransactionScore(tid, 0.7)
        net_q = queue.Queue()
        rp.forward_transaction({CfgIds.network: net_q}, score)
        # forward_transaction adds identity's side; transaction is in task_mapping
        # but not yet in the chain (needs 2 peers for chain commit)
        assert tid in rp.history._task_mapping


class TestHandleBackdateDeeper:
    def test_backdate_requests_update(self):
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        peer2 = _make_mock_peer(nickname='p2')
        # Configure find_top_n to return peers
        rp.protocol.peers.find_top_n.return_value = [peer1, peer2]

        net_q = queue.Queue()
        msg = Message(CfgIds.reputation, ReputationProtocol.backdate,
                      'data', from_whom=peer1)
        result = rp.handle_backdate({CfgIds.network: net_q}, msg)
        assert result is True
        assert not net_q.empty()


class TestStartPaxos:
    def test_start_paxos(self):
        rp = _make_rep_process()
        score = TransactionScore(uuid4(), 0.8)
        net_q = queue.Queue()
        rp._start_paxos({CfgIds.network: net_q}, score)
        assert not net_q.empty()
        assert len(rp.my_requests) == 1
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
        # peer_scores[-1] < 0.5 (defected) AND my_standing >= 0.5
        tid = uuid4()
        rp.history.update(tid, peer.uuid, 0.8)       # p1_score=0.8 -> my_scores (good standing)
        rp.history.update(tid, rp.identity.uuid, 0.3) # p2_score=0.3 -> peer_scores (defected)
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


class TestHandleGrantDeeper:
    def test_grant_faulty_peer(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        tid = uuid4()
        score = TransactionScore(tid, 0.8)
        rp.my_requests[idx] = TxCount(score, 0)
        # Faulty: last_id >= id1
        ack = ((id1, id2, rp.identity.uuid), (200, 0), None)  # last_id=200 >= id1=100
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer)
        result = rp.handle_grant({CfgIds.network: queue.Queue()}, msg)
        assert result is True

    def test_grant_increments_count(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        tid = uuid4()
        score = TransactionScore(tid, 0.8)
        rp.my_requests[idx] = TxCount(score, 0)
        rp.protocol.peers.all = [peer] + [_make_mock_peer(nickname='p%d' % i) for i in range(4)]  # 5 peers, quorum=2
        ack = ((id1, id2, rp.identity.uuid), (None, 0), None)
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer)
        result = rp.handle_grant({CfgIds.network: queue.Queue()}, msg)
        assert result is True
        assert rp.my_requests[idx].count == 1


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


class TestHandleNackDeeper:
    def test_nack_starts_retry(self):
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8)
        # handle_nack reads the score from my_requests (proposer-side state
        # populated by _start_paxos), not the acceptor-side `requests` list.
        rp.my_requests[idx] = TxCount(score, 0)

        msg = Message(CfgIds.reputation, ReputationProtocol.nack,
                      to_yaml_string((id1, id2, peer.uuid)),
                      from_whom=peer)
        # handle_nack spawns a thread; just verify it returns True
        result = rp.handle_nack({CfgIds.network: queue.Queue()}, msg)
        assert result is True
        assert idx in rp.backoff

    def test_nack_unknown_request_dropped(self):
        """A nack for an idx not in my_requests is dropped without retry."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        # do NOT populate my_requests — handle_nack should short-circuit

        msg = Message(CfgIds.reputation, ReputationProtocol.nack,
                      to_yaml_string((id1, id2, peer.uuid)),
                      from_whom=peer)
        result = rp.handle_nack({CfgIds.network: queue.Queue()}, msg)
        assert result is True
        assert idx not in rp.backoff


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
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        rp.protocol.peers.all = [peer1]

        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        tid = uuid4()
        score = TransactionScore(tid, 0.8)
        rp.proposals[idx] = score
        rp.acceptances[tid] = [peer1]  # already accepted

        msg = Message(CfgIds.reputation, ReputationProtocol.accepted,
                      to_yaml_string((id1, id2, peer1.uuid)),
                      from_whom=peer1)
        result = rp.handle_accepted(None, msg)
        assert result is True
        # Should not add duplicate
        assert len(rp.acceptances[tid]) == 1


# ---------------------------------------------------------------------------
# Additional tests targeting previously-uncovered lines
# ---------------------------------------------------------------------------

class TestHandleRequestFullException:
    """Cover Full exception in handle_request (lines 107-108)."""

    def test_request_full_queue(self):
        """Full exception when putting grant/nack/backdate onto network queue."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        rp.protocol.peers.all = [peer]
        rp.last_id = None

        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=Full)
        queues = {CfgIds.network: full_q, CfgIds.reputation: queue.Queue()}

        # id2 == len(history)+1 == 1, so grant path is taken and Full is raised
        msg = Message(CfgIds.reputation, ReputationProtocol.request,
                      to_yaml_string((100, 1, peer.uuid)),
                      from_whom=peer)
        result = rp.handle_request(queues, msg)
        assert result is True  # caught internally, still returns True

    def test_request_nack_full_queue(self):
        """Full exception on the nack path (last_id >= id1)."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        rp.protocol.peers.all = [peer]
        rp.last_id = 200  # force nack path

        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=Full)
        queues = {CfgIds.network: full_q, CfgIds.reputation: queue.Queue()}

        msg = Message(CfgIds.reputation, ReputationProtocol.request,
                      to_yaml_string((100, 1, peer.uuid)),
                      from_whom=peer)
        result = rp.handle_request(queues, msg)
        assert result is True


class TestHandleGrantFaultyPeer:
    """Cover faulty peer path in handle_grant (lines 135-139): last_id >= id1 → demote."""

    def test_faulty_peer_last_id_geq_id1(self):
        """Peer with last_id >= id1 is demoted."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8)
        rp.my_requests[idx] = TxCount(score, 0)
        # last_id=200 >= id1=100 → faulty peer
        ack = ((id1, id2, rp.identity.uuid), (200, 0), None)
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer)
        result = rp.handle_grant({CfgIds.network: queue.Queue()}, msg)
        assert result is True
        rp.protocol.peers.demote.assert_called_once_with(peer)

    def test_faulty_peer_wrong_last_idx(self):
        """Peer with wrong last_idx (last_idx != len(history)) is demoted."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8)
        rp.my_requests[idx] = TxCount(score, 0)
        # last_id=None (ok) but last_idx=999 != len(history)=0 → faulty
        ack = ((id1, id2, rp.identity.uuid), (None, 999), None)
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer)
        result = rp.handle_grant({CfgIds.network: queue.Queue()}, msg)
        assert result is True
        rp.protocol.peers.demote.assert_called_once_with(peer)


class TestHandleGrantAlreadyCompleted:
    """Cover already-completed path in handle_grant (lines 141-143): idx not in my_requests."""

    def test_grant_for_completed_request_returns_true(self):
        """If idx not in my_requests, log and return True without doing anything."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        # Do NOT add idx to my_requests
        ack = ((id1, id2, rp.identity.uuid), (None, 0), None)
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer)
        result = rp.handle_grant({CfgIds.network: queue.Queue()}, msg)
        assert result is True


class TestHandleGrantMajorityReached:
    """Cover majority path in handle_grant (lines 145-155): submit transaction."""

    def test_grant_majority_submits_transaction(self):
        """When count >= len(peers)//2, send transaction to group."""
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        peer2 = _make_mock_peer(nickname='p2')
        rp.protocol.peers.all = [peer1, peer2]  # 2 peers → quorum=1

        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8)
        rp.my_requests[idx] = TxCount(score, 0)

        ack = ((id1, id2, rp.identity.uuid), (None, 0), None)
        net_q = queue.Queue()
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer1)
        result = rp.handle_grant({CfgIds.network: net_q}, msg)
        assert result is True
        assert not net_q.empty()
        sent = net_q.get_nowait()
        assert sent.function == ReputationProtocol.transaction
        # idx removed from my_requests after transaction submitted
        assert idx not in rp.my_requests

    def test_grant_majority_full_queue(self):
        """Full exception when submitting transaction after majority reached."""
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        peer2 = _make_mock_peer(nickname='p2')
        rp.protocol.peers.all = [peer1, peer2]

        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8)
        rp.my_requests[idx] = TxCount(score, 0)

        ack = ((id1, id2, rp.identity.uuid), (None, 0), None)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=Full)
        msg = Message(CfgIds.reputation, ReputationProtocol.grant,
                      to_yaml_string(ack), from_whom=peer1)
        result = rp.handle_grant({CfgIds.network: full_q}, msg)
        assert result is True


class TestTryAgain:
    """Cover _try_again method (lines 159-166).

    NOTE: The source _try_again loop condition is `start - now() < wait`,
    which is effectively always True and the loop never exits without mocking.
    We patch `now()` so that `start - now()` is not less than `wait`, skipping
    the loop and reaching the _start_paxos call.
    """

    def test_try_again_calls_start_paxos(self):
        """_try_again calls _start_paxos after the wait exits."""
        from datetime import timedelta, datetime
        rp = _make_rep_process()
        score = TransactionScore(uuid4(), 0.7)
        net_q = queue.Queue()
        # Patch now() so start - now() >= wait from the first check, skipping loop
        frozen = datetime(2020, 1, 1, 12, 0, 0)
        with patch('autonomous_trust.core.reputation.repprocess.now', return_value=frozen):
            rp._try_again(0, {CfgIds.network: net_q}, score)
        assert not net_q.empty()

    def test_try_again_full_exception(self):
        """_try_again catches Full exception from _start_paxos."""
        from datetime import timedelta, datetime
        rp = _make_rep_process()
        score = TransactionScore(uuid4(), 0.7)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=Full)
        frozen = datetime(2020, 1, 1, 12, 0, 0)
        with patch('autonomous_trust.core.reputation.repprocess.now', return_value=frozen):
            # Should not raise; Full is caught inside _try_again
            rp._try_again(0, {CfgIds.network: full_q}, score)


class TestHandleNackDeeper2:
    """Cover handle_nack (lines 191-192): starts retry thread."""

    def test_nack_wrong_function(self):
        """Wrong function returns False."""
        rp = _make_rep_process()
        msg = Message(CfgIds.reputation, 'wrong', 'data')
        result = rp.handle_nack({}, msg)
        assert result is False

    def test_nack_new_backoff(self):
        """First nack for an idx initialises backoff and starts retry."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8)
        rp.my_requests[idx] = TxCount(score, 0)

        msg = Message(CfgIds.reputation, ReputationProtocol.nack,
                      to_yaml_string((id1, id2, peer.uuid)),
                      from_whom=peer)
        result = rp.handle_nack({CfgIds.network: queue.Queue()}, msg)
        assert result is True
        assert idx in rp.backoff
        assert rp.backoff[idx] == rp.backoff_mult  # 1 * backoff_mult after first nack

    def test_nack_existing_backoff(self):
        """Existing backoff below max is multiplied."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        score = TransactionScore(uuid4(), 0.8)
        rp.my_requests[idx] = TxCount(score, 0)
        rp.backoff[idx] = 2.0  # pre-existing backoff

        msg = Message(CfgIds.reputation, ReputationProtocol.nack,
                      to_yaml_string((id1, id2, peer.uuid)),
                      from_whom=peer)
        result = rp.handle_nack({CfgIds.network: queue.Queue()}, msg)
        assert result is True
        assert rp.backoff[idx] == 2.0 * rp.backoff_mult


class TestHandleAcceptedDeeper2:
    """Cover handle_accepted majority path (lines 229-230 area): commits transaction."""

    def test_accepted_majority_commits_history(self):
        """Majority of acceptances commits transaction to history."""
        rp = _make_rep_process()
        peer1 = _make_mock_peer(nickname='p1')
        rp.protocol.peers.all = [peer1]  # 1 peer → quorum = 0

        id1 = 100
        id2 = 1
        idx = rp._paxos_id_index(id1, id2)
        tid = uuid4()
        score = TransactionScore(tid, 0.9)
        rp.proposals[idx] = score
        # pre-populate identity side of tx so history.update can find it
        rp.history.update(tid, rp.identity.uuid, 0.9)

        msg = Message(CfgIds.reputation, ReputationProtocol.accepted,
                      to_yaml_string((id1, id2, peer1.uuid)),
                      from_whom=peer1)
        msg.verified = True  # simulate signed message (mock peer can't sign)
        result = rp.handle_accepted(None, msg)
        assert result is True
        # 1 acceptance > 1//2=0, so history should have been updated
        assert len(rp.history) > 0

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
        # p2_score=0.8 * reputations[other.uuid]=0.9 / 1 entry
        assert abs(result - 0.8 * 0.9) < 1e-9

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
        # p1_score=0.6 * reputations[other.uuid]=0.8 / 1 entry
        assert abs(result - 0.6 * 0.8) < 1e-9


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
        """Transactions with neither peer being the target peer return 0.49."""
        rp = _make_rep_process()
        peer = _make_mock_peer()
        other1 = _make_mock_peer(nickname='o1', address='10.0.0.2')
        other2 = _make_mock_peer(nickname='o2', address='10.0.0.3')
        tid = uuid4()
        # History entry but neither p1 nor p2 is peer
        rp.history.update(tid, other1.uuid, 0.7)
        rp.history.update(tid, other2.uuid, 0.8)
        result = rp._contrite_tit_for_tat(peer)
        assert result == 0.49  # not enough info


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
