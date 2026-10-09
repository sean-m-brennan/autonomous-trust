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
B's app reaction the first way. What outlives the retries is parked until the
chain grows from a peer (§2.60). Mirrors C test/rep_commit_retry_test.c.
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

    def test_an_exhausted_half_is_parked_not_dropped(self):
        """Five re-proposals, then PARKED (§2.60), not dropped."""
        rp, queues, net_q = _cohort()
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))
        resent = sum(rp._retry_uncommitted_halves(queues, _later(i))
                     for i in range(1, 7))
        assert resent == rp.COMMIT_RETRIES == 5
        assert str(task) in rp.awaiting_commit
        assert rp.parked_count() == 1

    def test_a_half_already_in_the_chain_is_forgotten(self):
        rp, queues, net_q = _cohort()
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))
        rp.history.update(task, rp.identity.uuid, 0.9)
        assert rp._retry_uncommitted_halves(queues, _later(1)) == 0
        assert str(task) not in rp.awaiting_commit


def _park(rp, queues, net_q):
    """Park a half, as the minority side of a partition does: five
    unanswered re-proposals, parked on the sixth pass at _later(6)."""
    task = uuid4()
    rp._start_paxos(queues, TransactionScore(task, 0.9))
    for i in range(1, 7):
        rp._retry_uncommitted_halves(queues, _later(i))
    assert rp.parked_count() == 1
    _requests(net_q)
    return task


def _catch_up(rp, queues, n):
    """alice sends a chain of ``n`` unrelated alice/bob entries, as the
    majority island's does at the heal."""
    from autonomous_trust.core.reputation.reputation import Transaction
    alice, bob = rp.protocol.peers.all[:2]
    chain = [Transaction(uuid4(), alice.uuid, 0.8, bob.uuid, 0.7, index=i + 1)
             for i in range(n)]
    rp.handle_update(queues, Message(
        CfgIds.reputation, ReputationProtocol.update,
        to_yaml_string(chain), from_whom=alice))


class TestParkedHalves:
    """ISSUES §2.60. Mirrors the parked tests in rep_commit_retry_test.c."""

    def test_a_parked_half_is_re_proposed_every_park_retry(self):
        rp, queues, net_q = _cohort()
        _park(rp, queues, net_q)
        assert rp._retry_uncommitted_halves(queues, _later(7)) == 0
        assert rp._retry_uncommitted_halves(queues, _later(8)) == 1
        assert rp.parked_count() == 1
        assert rp._retry_uncommitted_halves(queues, _later(9)) == 0
        assert rp._retry_uncommitted_halves(queues, _later(10)) == 1

    def test_a_grown_chain_wakes_parked_halves(self):
        """THE HEAL: the minority's chain is a prefix of the majority's, so
        the heal arrives as an EXTENDED catch-up and wakes the parked half."""
        rp, queues, net_q = _cohort()
        _park(rp, queues, net_q)
        _catch_up(rp, queues, 1)
        assert len(rp.history) == 1, 'precondition: caught up'
        # Not at once: the last round has its COMMIT_TIMEOUT first.
        assert rp._retry_uncommitted_halves(queues, now().timestamp()) == 0
        # _later(7) is 60 s before the slow retry: only the wake makes it due.
        assert rp._retry_uncommitted_halves(queues, _later(7)) == 1

    def test_a_woken_half_is_unparked_with_fresh_retries(self):
        """A wake UNPARKS (part-2272442): WAKE_RETRIES (10) fresh retries,
        then, with a majority reachable, given up as a contention loser."""
        rp, queues, net_q = _cohort()
        _park(rp, queues, net_q)
        _catch_up(rp, queues, 1)
        assert rp._retry_uncommitted_halves(queues, _later(7)) == 1
        assert rp.parked_count() == 0
        assert len(rp.awaiting_commit) == 1
        _catch_up(rp, queues, 2)
        assert rp.parked_count() == 0
        alice = rp.protocol.peers.all[0]
        resent = 0
        for i in range(8, 18):
            rp.note_heard(alice, _later(i))
            resent += rp._retry_uncommitted_halves(queues, _later(i))
        assert resent == 9
        assert len(rp.awaiting_commit) == 0

    def test_a_parked_half_expires_or_is_forgotten(self):
        rp, queues, net_q = _cohort()
        task = _park(rp, queues, net_q)
        assert rp._retry_uncommitted_halves(
            queues, _later(6) + rp.PARK_TTL + 60.0) == 0
        assert str(task) not in rp.awaiting_commit

        task = _park(rp, queues, net_q)
        rp.history.update(task, rp.identity.uuid, 0.9)
        assert rp._retry_uncommitted_halves(queues, _later(8)) == 0
        assert str(task) not in rp.awaiting_commit

    def test_a_half_a_majority_reached_is_dropped_not_parked(self):
        """Contention, not a partition: alice (with us, a majority of three)
        is reachable and it still never committed. Given up as before
        §2.60."""
        rp, queues, net_q = _cohort()
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))
        alice = rp.protocol.peers.all[0]
        for i in range(1, 7):
            rp.note_heard(alice, _later(i))
            rp._retry_uncommitted_halves(queues, _later(i))
        assert rp.parked_count() == 0
        assert str(task) not in rp.awaiting_commit

    def test_a_peer_heard_on_a_retired_ballot_still_counts(self):
        """THE REGRESSION (part-2136648): reach is any frame from the peer,
        not an answer to one of the half's own rounds. A grant for a ballot
        the retry already retired lands nowhere; alice is merely heard."""
        rp, queues, net_q = _cohort()
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))
        stale = next(reversed(rp.my_requests))
        for i in range(1, 6):
            rp._retry_uncommitted_halves(queues, _later(i))
        alice = rp.protocol.peers.all[0]
        ack = ((stale[0], stale[1], rp.identity.uuid),
               (None, len(rp.history)), None)
        rp.handle_grant(queues, Message(CfgIds.reputation,
                                        ReputationProtocol.grant,
                                        to_yaml_string(ack), from_whom=alice))
        rp.note_heard(alice, _later(6))
        rp._retry_uncommitted_halves(queues, _later(6))
        assert rp.parked_count() == 0

    def test_a_minority_island_parks_its_half(self):
        """Of five, only alice is reachable (two of five, counting us), and
        whoever was heard before the split is stale."""
        rp, queues, net_q = _cohort()
        rp.protocol.peers.all = rp.protocol.peers.all + [
            _make_mock_peer(nickname='carol'), _make_mock_peer(nickname='dave')]
        alice, bob, carol, dave = rp.protocol.peers.all
        rp._start_paxos(queues, TransactionScore(uuid4(), 0.9))
        for peer in (bob, carol, dave):
            rp.note_heard(peer, _later(5))
        for i in range(1, 7):
            rp.note_heard(alice, _later(i))
            rp._retry_uncommitted_halves(queues, _later(i))
        assert rp.parked_count() == 1


class TestProbeBackpressure:
    """ISSUES §2.60, part-2314213. Mirrors the probe tests in
    rep_commit_retry_test.c."""

    @staticmethod
    def _probe(rp, queues):
        """A NEW probe half through the local entry point. Admitted?"""
        before = len(rp.awaiting_commit)
        rp.forward_transaction(queues, TransactionScore(
            uuid4(), 0.9, capability_name='at.handshake'))
        return len(rp.awaiting_commit) == before + 1

    def test_probe_halves_are_capped_app_halves_are_not(self):
        rp, queues, net_q = _cohort()
        for _ in range(4):
            assert self._probe(rp, queues)
        assert not self._probe(rp, queues)
        assert len(rp.awaiting_commit) == 4
        assert rp.admit_new_half(TransactionScore(uuid4(), 0.9,
                                                  capability_name='agora-post'))
        assert rp.admit_new_half(TransactionScore(uuid4(), 0.9))

    def test_probes_yield_to_a_pending_app_half(self):
        """bob's reaction lost 24 rounds in a row to probes in part-2314213."""
        rp, queues, net_q = _cohort()
        assert self._probe(rp, queues)
        task = uuid4()
        rp._start_paxos(queues, TransactionScore(task, 0.9))  # the app half
        assert not self._probe(rp, queues)
        _requests(net_q)
        assert rp._retry_uncommitted_halves(queues, _later(1)) == 1
        idx = _grant_all(rp, queues)
        _accept_all(rp, queues, idx)
        assert str(task) not in rp.awaiting_commit
        assert rp._retry_uncommitted_halves(queues, _later(2)) == 1
        assert self._probe(rp, queues)
