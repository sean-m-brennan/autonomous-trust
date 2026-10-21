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
"""Local soft-absence (doc/architecture/peer-presence.md).

The network process's presence tracker: when a peer counts as absent, when this
node owes the group a heartbeat, and what negotiation and the app are told.
Times are passed in, so nothing here sleeps. Mirrors C test/net_presence_test.c.
"""
import logging
import queue
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

from autonomous_trust.core.capabilities import Capability
from autonomous_trust.core.negotiation.negotiation import Status, Task, TaskParameters
from autonomous_trust.core.negotiation.protocol import NegotiationProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.network.netprocess import NetworkProcess
from autonomous_trust.core.network.presence import (
    ABSENT_DEFAULT_SEC, HEARTBEAT_DEFAULT_SEC, PRESENCE_FUNCTION,
    PRESENCE_PROCESS, PeerPresence, PresenceTracker)
from autonomous_trust.core.app_verbs import AppEvent
from autonomous_trust.core.protocol import Protocol
from autonomous_trust.core.system import CfgIds

from .test_group_key_convergence import _new_identity
from .test_negprocess import _make_mock_peer, _make_neg_process

T0 = 1_000_000.0


def _roster(n):
    return [str(uuid4()) for _ in range(n)]


class TestTracker:
    def test_a_peer_is_absent_only_after_the_threshold(self):
        t = PresenceTracker(30.0, 90.0)
        r = _roster(2)
        assert t.tick(r, T0)[1] == []            # joining starts the grace
        t.heard(r[1], T0 + 60.0)
        assert t.tick(r, T0 + 90.0)[1] == []     # exactly the threshold
        changes = t.tick(r, T0 + 91.0)[1]
        assert changes == [PeerPresence(r[0], False, 0.0)]
        assert t.tick(r, T0 + 92.0)[1] == []     # reported once
        assert t.tick(r, T0 + 151.0)[1] == [PeerPresence(r[1], False, T0 + 60.0)]
        t.heard(r[0], T0 + 152.0)
        assert t.tick(r, T0 + 153.0)[1] == [PeerPresence(r[0], True, T0 + 152.0)]

    def test_a_frame_from_a_stranger_is_not_evidence(self):
        t = PresenceTracker(30.0, 90.0)
        r, stranger = _roster(1), str(uuid4())
        t.tick(r, T0)
        t.heard(stranger, T0 + 10.0)
        rows = t.snapshot(r + [stranger])
        assert rows[1] == PeerPresence(stranger, True, 0.0)

    def test_a_heartbeat_is_owed_only_after_silence_toward_someone(self):
        t = PresenceTracker(30.0, 90.0)
        r = _roster(2)
        assert not t.tick(r, T0)[0]
        assert not t.tick(r, T0 + 29.0)[0]
        t.sent(r[0], T0 + 29.0)                  # one member says nothing to the other
        assert t.tick(r, T0 + 30.0)[0]
        t.sent(None, T0 + 30.0)                  # a group frame reaches everyone
        assert not t.tick(r, T0 + 59.0)[0]
        assert t.tick(r, T0 + 60.0)[0]
        for s in range(60, 200, 10):             # a busy node never owes one
            t.sent(None, T0 + s)
            assert not t.tick(r, T0 + s + 5.0)[0]

    def test_a_peer_off_the_roster_is_forgotten(self):
        t = PresenceTracker(30.0, 90.0)
        r = _roster(2)
        t.tick(r, T0)
        assert [c.peer_uuid for c in t.tick(r[:1], T0 + 200.0)[1]] == [r[0]]
        assert t.tick(r, T0 + 201.0)[1] == []    # back: a fresh grace

    def test_the_thresholds_keep_absent_above_the_heartbeat(self, monkeypatch):
        assert PresenceTracker(60.0, 10.0).absent_sec == 60.0
        t = PresenceTracker(-1.0, 0.0)
        assert (t.heartbeat_sec, t.absent_sec) == (HEARTBEAT_DEFAULT_SEC, ABSENT_DEFAULT_SEC)
        monkeypatch.setenv('AT_PRESENCE_HEARTBEAT_SEC', '5')
        monkeypatch.setenv('AT_PRESENCE_ABSENT_SEC', 'nonsense')
        t = PresenceTracker()
        assert (t.heartbeat_sec, t.absent_sec) == (5.0, ABSENT_DEFAULT_SEC)

    def test_presence_is_an_app_event(self):
        # The main loop forwards any AppEvent to the app; that is the whole
        # app-side path, as PEER_PRESENCE is in C.
        assert isinstance(PeerPresence('x', False), AppEvent)


class TestSiblingAndNegotiation:
    def test_a_sibling_tracks_absent_peers(self):
        p = Protocol(CfgIds.negotiation, logging.getLogger('test'), None)
        q = {CfgIds.negotiation: queue.Queue()}
        assert p.run_message_handlers(q, PeerPresence('a', False))
        assert p.absent_peers == {'a'}
        assert p.run_message_handlers(q, PeerPresence('a', True))
        assert p.absent_peers == set()

    def _start(self, np, peers, to_whom=None, cap_name='video'):
        np.protocol.peer_capabilities.items = MagicMock(
            return_value=[(cap_name, [p.uuid for p in peers])])
        np.protocol.peers.find_by_uuid = MagicMock(
            side_effect=lambda u: next((p for p in peers if p.uuid == u), None))
        task = Task(TaskParameters(Capability(cap_name),
                                   when=datetime(2020, 1, 1, tzinfo=UTC)), peers[0])
        task.to_json_string = MagicMock(return_value='task')
        msg = Message(CfgIds.negotiation, NegotiationProtocol.start, task, to_whom=to_whom)
        net_q, main_q = queue.Queue(), queue.Queue()
        assert np.start_task({CfgIds.network: net_q, CfgIds.main: main_q}, msg)
        sent = []
        while not net_q.empty():
            whom = net_q.get_nowait().to_whom
            sent.append(whom[0] if isinstance(whom, list) else whom)
        return task, sent, main_q

    def test_an_absent_peer_is_not_invited(self):
        np = _make_neg_process()
        a = _make_mock_peer(nickname='a', address='10.0.0.1')
        b = _make_mock_peer(nickname='b', address='10.0.0.2')
        np.protocol.absent_peers = {str(b.uuid)}
        _, sent, _ = self._start(np, [a, b])
        assert sent == [a]
        np.protocol.absent_peers = set()
        _, sent, _ = self._start(np, [a, b])
        assert sent == [a, b]                    # back: invited again

    def test_a_probe_to_an_absent_peer_is_not_issued_or_scored(self):
        np = _make_neg_process()
        a = _make_mock_peer(nickname='a')
        np.protocol.absent_peers = {str(a.uuid)}
        task, sent, main_q = self._start(np, [a], to_whom=a, cap_name='at.handshake')
        assert sent == []
        assert main_q.empty()                    # a no_peers result would be scored
        assert task.uuid not in np.my_tasks

    def test_an_app_task_with_only_absent_peers_still_gets_an_answer(self):
        np = _make_neg_process()
        a = _make_mock_peer(nickname='a')
        np.protocol.absent_peers = {str(a.uuid)}
        _, sent, main_q = self._start(np, [a])
        assert sent == []
        assert main_q.get_nowait().result == Status.no_peers


def _net_proc(members, group_private=True):
    """A NetworkProcess stand-in carrying what presence touches, with the real
    methods bound to it."""
    proc = MagicMock(spec=NetworkProcess)
    proc.name = CfgIds.network
    proc.q_cadence = 0
    proc.logger = logging.getLogger('test.net.presence')
    proc._presence = PresenceTracker(30.0, 90.0)
    proc._presence_last_step = 0
    roster = MagicMock()
    roster.all = members
    proc.peers = roster
    proc.group = MagicMock()
    proc.group._public_only = not group_private
    for name in ('_presence_step', '_emit_presence', '_emit_all_presence',
                 '_msg_to_queue'):
        setattr(proc, name, getattr(NetworkProcess, name).__get__(proc))
    proc._foreign_format_counts = {}
    proc._crosses_gateway.return_value = False
    return proc


def _queues():
    return {CfgIds.network: queue.Queue(), CfgIds.negotiation: queue.Queue(),
            CfgIds.main: queue.Queue(), CfgIds.identity: queue.Queue()}


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


class TestNetworkProcess:
    def test_a_presence_frame_is_heard_and_consumed(self):
        member = _new_identity('m', '10.0.0.9')
        proc = _net_proc([member])
        proc._presence.tick([member.uuid], T0)
        qs = _queues()
        wire = bytes(Message(PRESENCE_PROCESS, PRESENCE_FUNCTION, '', from_whom=member))
        proc._msg_to_queue(wire, member, qs, 'group')
        assert all(q.empty() for q in qs.values())          # routed nowhere
        assert proc._presence.snapshot([member.uuid])[0].last_heard > 0.0

    def test_a_step_reports_changes_and_queues_one_heartbeat(self, monkeypatch):
        member = _make_mock_peer(nickname='m')
        proc = _net_proc([member])
        qs = _queues()
        clock = {'t': T0}
        monkeypatch.setattr('autonomous_trust.core._python.network.netprocess.time.time',
                            lambda: clock['t'])
        proc._presence_step(qs)
        assert _drain(qs[CfgIds.network]) == []              # nothing owed yet
        clock['t'] = T0 + 30.0
        proc._presence_step(qs)
        beat = _drain(qs[CfgIds.network])
        assert len(beat) == 1
        assert (beat[0].process, beat[0].function) == (PRESENCE_PROCESS, PRESENCE_FUNCTION)
        assert beat[0].to_whom is proc.group
        clock['t'] = T0 + 31.0
        proc._presence_step(qs)
        assert _drain(qs[CfgIds.network]) == []              # stamped: not every second

        clock['t'] = T0 + 91.0
        proc._presence_step(qs)
        expect = PeerPresence(str(member.uuid), False, 0.0)
        assert _drain(qs[CfgIds.negotiation]) == [expect]
        assert _drain(qs[CfgIds.main]) == [expect]
        assert _drain(qs[CfgIds.identity]) == []

    def test_no_heartbeat_without_the_group_key(self, monkeypatch):
        member = _make_mock_peer(nickname='m')
        proc = _net_proc([member], group_private=False)
        qs = _queues()
        monkeypatch.setattr('autonomous_trust.core._python.network.netprocess.time.time',
                            lambda: T0 + 60.0)
        proc._presence.tick([member.uuid], T0)
        proc._presence_step(qs)
        assert _drain(qs[CfgIds.network]) == []

    def test_the_roster_pull_answers_presence_for_everyone(self):
        a, b = _make_mock_peer(nickname='a'), _make_mock_peer(nickname='b')
        proc = _net_proc([a, b])
        qs = _queues()
        proc._emit_all_presence(qs)
        rows = _drain(qs[CfgIds.main])
        assert [r.peer_uuid for r in rows] == [str(a.uuid), str(b.uuid)]
        assert all(r.present for r in rows)
