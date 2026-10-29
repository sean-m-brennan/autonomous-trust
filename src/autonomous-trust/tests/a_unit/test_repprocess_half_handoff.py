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
"""Our pending halves reach a member that joined after we committed them
(ISSUES §2.62).

Stele rt-2404254: the verifier committed its half of a probe before the auditor
and the observer joined, the join carried only bilateral entries, and the
owner's half committed later. The late pair held the owner's half alone, the
chains forked two and two, and no checkpoint ever reached a quorum. Mirrors C
test/rep_half_handoff_test.c.
"""
import queue
from uuid import uuid4

from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.system import CfgIds, now
from autonomous_trust.core.config import from_json_string

from .test_repprocess import _make_rep_process, _make_mock_peer


def _frames(q):
    """Drain the network queue; the `committed` frames it carried."""
    out = []
    while not q.empty():
        msg = q.get_nowait()
        if msg.function == ReputationProtocol.committed:
            out.append(msg)
    return out


def _cohort():
    rp = _make_rep_process()
    alice = _make_mock_peer(nickname='alice', address='10.0.0.2')
    carol = _make_mock_peer(nickname='carol', address='10.0.0.3')
    rp.protocol.peers.all = [alice]
    net_q = queue.Queue()
    return rp, {CfgIds.network: net_q}, net_q, alice, carol


class TestPendingHalvesAreHandedToJoiners:
    def test_a_half_committed_before_a_join_reaches_the_joiner(self):
        """THE REGRESSION's sending side (rt-2404254)."""
        rp, queues, net_q, alice, carol = _cohort()
        me = rp.identity.uuid
        mine, both, theirs = uuid4(), uuid4(), uuid4()
        rp.history.record_half(mine, me, 900, 'probe')
        rp.history.record_half(both, me, 900)
        rp.history.record_half(both, alice.uuid, 900)
        rp.history.record_half(theirs, alice.uuid, 900)

        t0 = now().timestamp()
        assert rp._hand_off_pending_halves(queues, t0) == 0
        rp.protocol.peers.all = [alice, carol]
        assert rp._hand_off_pending_halves(queues, t0 + 1) == 0
        assert rp._hand_off_pending_halves(queues, t0 + 4) == 0

        assert rp._hand_off_pending_halves(queues, t0 + 6) == 2
        frames = _frames(net_q)
        assert sorted(f.to_whom.nickname for f in frames) == ['alice', 'carol']
        for f in frames:
            task, peer, score, group, channel = from_json_string(f.obj)[:5]
            assert str(task) == str(mine) and str(peer) == str(me)
            assert score == 900 and group is None and channel == 'probe'
        assert rp._hand_off_pending_halves(queues, t0 + 6) == 0

        # A late tick past both remaining passes sends once, not twice.
        assert rp._hand_off_pending_halves(queues, t0 + 100) == 2
        assert rp._hand_off_pending_halves(queues, t0 + 200) == 0

    def test_a_returning_peer_is_handed_them_again(self):
        rp, queues, net_q, alice, _ = _cohort()
        t0 = now().timestamp()
        assert rp._hand_off_pending_halves(queues, t0) == 0
        assert rp._hand_off_pending_halves(queues, t0 + 100) == 0  # none pending

        rp.history.record_half(uuid4(), rp.identity.uuid, 900)
        rp.protocol.peers.all = []
        assert rp._hand_off_pending_halves(queues, t0 + 400) == 0  # alice left
        rp.protocol.peers.all = [alice]
        assert rp._hand_off_pending_halves(queues, t0 + 401) == 0  # first seen
        assert rp._hand_off_pending_halves(queues, t0 + 406) == 1
        assert [f.to_whom.nickname for f in _frames(net_q)] == ['alice']
