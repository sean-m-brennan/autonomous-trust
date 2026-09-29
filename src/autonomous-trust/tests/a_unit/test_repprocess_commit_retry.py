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
"""OUR half of a task is followed until it is in the chain (ISSUES §2.24).

A granted round leaves my_requests when its transaction goes out, so if the
acceptors never commit it the half is gone; a round nobody answers gets no
nack, so the nack retry never fires. Partition cohort part-3490610 lost island
B's app reaction the first way. Mirrors C test/rep_commit_retry_test.c.
"""
import queue
from uuid import uuid4

from autonomous_trust.core.reputation.reputation import TransactionScore
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.system import CfgIds, now
from autonomous_trust.core.config import to_yaml_string

from .test_repprocess import _make_rep_process, _make_mock_peer


def _later(n):
    return now().timestamp() + 60.0 * n


def _requests(q):
    """Drain the network queue; count the Paxos requests it carried."""
    n = 0
    while not q.empty():
        if q.get_nowait().function == ReputationProtocol.request:
            n += 1
    return n


def _cohort():
    rp = _make_rep_process()
    rp.protocol.peers.all = [_make_mock_peer(nickname='alice'),
                             _make_mock_peer(nickname='bob')]
    net_q = queue.Queue()
    return rp, {CfgIds.network: net_q}, net_q


def _grant_all(rp, queues):
    """Grant our most recent round from every peer, as handle_request does."""
    idx = next(reversed(rp.my_requests))
    id1, id2 = idx
    for peer in rp.protocol.peers.all:
        ack = ((id1, id2, rp.identity.uuid), (None, len(rp.history)), None)
        rp.handle_grant(queues, Message(CfgIds.reputation,
                                        ReputationProtocol.grant,
                                        to_yaml_string(ack), from_whom=peer))
    return idx


def _accept_all(rp, queues, idx):
    id1, id2 = idx
    for peer in rp.protocol.peers.all:
        msg = Message(CfgIds.reputation, ReputationProtocol.accepted,
                      to_yaml_string((id1, id2, rp.identity.uuid)),
                      from_whom=peer)
        msg.verified = True
        rp.handle_accepted(queues, msg)


class TestUncommittedHalvesAreReProposed:
    def test_a_granted_round_that_never_commits_is_re_proposed(self):
        """THE REGRESSION (part-3490610)."""
        rp, queues, net_q = _cohort()
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))
        _grant_all(rp, queues)
        assert not rp.my_requests, 'precondition: the transaction went out'
        assert str(task) in rp.awaiting_commit
        _requests(net_q)

        assert rp._retry_uncommitted_halves(queues, now().timestamp()) == 0
        assert rp._retry_uncommitted_halves(queues, _later(1)) == 1
        assert _requests(net_q) == 1

        idx = _grant_all(rp, queues)
        _accept_all(rp, queues, idx)
        assert str(task) not in rp.awaiting_commit
        assert rp._retry_uncommitted_halves(queues, _later(2)) == 0

    def test_a_committed_half_is_left_alone(self):
        rp, queues, net_q = _cohort()
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))
        idx = _grant_all(rp, queues)
        _accept_all(rp, queues, idx)
        assert str(task) not in rp.awaiting_commit
        _requests(net_q)
        assert rp._retry_uncommitted_halves(queues, _later(1)) == 0
        assert _requests(net_q) == 0

    def test_an_unanswered_round_is_re_proposed_and_its_ballot_retired(self):
        rp, queues, net_q = _cohort()
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))
        # A ballot is minted from the clock's millisecond and the chain length,
        # so a re-proposal inside the same millisecond would reuse the key and
        # overwrite the stale round, hiding whether it was retired. In a live
        # run the first round is seconds older: say so.
        (old_idx, tc), = rp.my_requests.items()
        del rp.my_requests[old_idx]
        rp.my_requests[(old_idx[0] - 30000, old_idx[1])] = tc
        assert rp._retry_uncommitted_halves(queues, _later(1)) == 1
        live = [tc for tc in rp.my_requests.values()
                if tc.score.task_id == task]
        assert len(live) == 1, 'the stale round was left beside the new one'

    def test_retries_are_bounded(self):
        rp, queues, net_q = _cohort()
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))
        resent = sum(rp._retry_uncommitted_halves(queues, _later(i))
                     for i in range(1, 9))
        assert resent == rp.COMMIT_RETRIES == 5
        assert str(task) not in rp.awaiting_commit

    def test_a_half_already_in_the_chain_is_forgotten(self):
        rp, queues, net_q = _cohort()
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))
        rp.history.update(task, rp.identity.uuid, 0.9)
        assert rp._retry_uncommitted_halves(queues, _later(1)) == 0
        assert str(task) not in rp.awaiting_commit
