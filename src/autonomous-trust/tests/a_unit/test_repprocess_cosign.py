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
"""A member co-signs the proposed RANGE, and signs late rather than never
(ISSUES §2.29).

A member used to co-sign only when its WHOLE window matched the proposal on
arrival, so a signer one entry ahead or behind declined and nothing looked
again. Partition cohort part-3592107 had four nodes propose the same root and
none finalize. Mirrors C test/rep_cosign_test.c (whose first two tests, the
§2.28 send retry, are C only: Python's queues are unbounded).
"""
import queue
from uuid import uuid4

from autonomous_trust.core.reputation.reputation import Checkpoint
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.system import CfgIds, now
from autonomous_trust.core.config import to_json_string, from_json_string

from .test_repprocess_checkpoint import _identity, _make_rep_process


def _seed(n):
    return [(uuid4(), uuid4(), uuid4()) for _ in range(n)]


def _commit(rp, entries):
    for tid, p1, p2 in entries:
        rp.history.update(tid, p1, 0.7)
        rp.history.update(tid, p2, 0.5)


def _root_of(entries):
    """What a proposer holding exactly ``entries`` proposes."""
    other = _make_rep_process()
    _commit(other, entries)
    return other.history.window_root()


def _member():
    proposer = _identity('proposer')
    member = _make_rep_process()
    member.protocol.peers.all = [proposer]
    net_q = queue.Queue()
    return member, proposer, {CfgIds.network: net_q}, net_q


def _propose(member, proposer, queues, root, epoch=7, count=3):
    ck = Checkpoint(proposer_uuid=proposer.uuid, root=root, epoch=epoch,
                    first_index=0, count=count)
    msg = Message(CfgIds.reputation, ReputationProtocol.checkpoint_propose,
                  to_json_string(ck), member.group, from_whom=proposer)
    msg.verified = True
    assert member.handle_checkpoint_propose(queues, msg) is True
    return ck


def _signs(net_q):
    out = []
    while not net_q.empty():
        m = net_q.get_nowait()
        if m.function == ReputationProtocol.checkpoint_sign:
            out.append(from_json_string(m.obj))
    return out


class TestRangeCosign:
    def test_a_signer_ahead_of_the_proposal_signs_its_range(self):
        """THE REGRESSION (part-3592107)."""
        member, proposer, queues, net_q = _member()
        seed = _seed(4)
        root = _root_of(seed[:3])
        _commit(member, seed)
        assert member.history.window_root() != root, \
            'precondition: the whole-window rule would decline'
        ck = _propose(member, proposer, queues, root)
        (ack,) = _signs(net_q)
        _tgt, epoch, voter, sig, _chain = ack
        assert epoch == 7
        assert member._verify_cosignature(ck.designation, voter, sig)
        assert not member._cosigns_parked

    def test_a_signer_behind_signs_once_it_catches_up(self):
        member, proposer, queues, net_q = _member()
        seed = _seed(4)
        root = _root_of(seed[:3])
        _commit(member, seed[:2])
        present = now().timestamp()
        _propose(member, proposer, queues, root)
        assert _signs(net_q) == []
        assert len(member._cosigns_parked) == 1

        assert member._recheck_parked_cosigns(queues, present) == 0
        assert _signs(net_q) == []

        _commit(member, seed[2:])
        assert member._recheck_parked_cosigns(queues, present) == 1
        (ack,) = _signs(net_q)
        assert ack[1] == 7
        assert not member._cosigns_parked
        assert member._recheck_parked_cosigns(queues, present) == 0

    def test_a_diverged_range_is_never_signed_and_expires(self):
        member, proposer, queues, net_q = _member()
        root = _root_of(_seed(3))
        _commit(member, _seed(4))
        present = now().timestamp()
        _propose(member, proposer, queues, root)
        assert _signs(net_q) == []
        assert len(member._cosigns_parked) == 1
        assert member._recheck_parked_cosigns(queues, present) == 0
        later = present + member.CHECKPOINT_INTERVAL + 1
        assert member._recheck_parked_cosigns(queues, later) == 0
        assert not member._cosigns_parked
        assert _signs(net_q) == []

    def test_a_proposers_newer_epoch_replaces_its_parked_one(self):
        member, proposer, queues, net_q = _member()
        seed = _seed(3)
        root = _root_of(seed)
        for epoch in (7, 8, 7):
            _propose(member, proposer, queues, root, epoch=epoch)
        assert len(member._cosigns_parked) == 1
        _commit(member, seed)
        assert member._recheck_parked_cosigns(queues, now().timestamp()) == 1
        (ack,) = _signs(net_q)
        assert ack[1] == 8

    def test_an_exact_window_match_signs_on_arrival(self):
        member, proposer, queues, net_q = _member()
        seed = _seed(3)
        _commit(member, seed)
        _propose(member, proposer, queues, _root_of(seed))
        assert len(_signs(net_q)) == 1
        assert not member._cosigns_parked
