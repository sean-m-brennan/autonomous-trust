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
"""A group frame sent under a key the network process has not installed yet.

Identity adopts a rotated key before the network process installs it, and a
one-shot group send in that gap failed to decrypt and was lost (Stele
tm-3882043, the team roster). The frame is now held and tried again once a
different key is installed. Twin of C net_held_group_test.c.
"""
from collections import deque
from types import SimpleNamespace
from unittest.mock import MagicMock

from autonomous_trust.core.identity import Group
from autonomous_trust.core._python.network import netprocess
from autonomous_trust.core._python.network.netprocess import NetworkProcess

SENDER = '10.0.0.2'


def _rotated(group):
    nxt = Group.from_canonical(group.to_canonical())
    nxt.rotate_key()
    return nxt


def _node(group):
    node = object.__new__(NetworkProcess)
    node.logger = MagicMock()
    node._crypto_error_counts = {}
    node._held_group_frames = deque()
    node.current = group
    node.reject_message = lambda addr: False
    node._groups_containing = lambda addr: [node.current]
    node._group_for_sender = lambda addr: node.current
    node.protocol = SimpleNamespace(peers=SimpleNamespace(
        find_by_address=lambda addr: SimpleNamespace(nickname='officer')))
    node._msg_to_queue = MagicMock()
    node._signal_partition = MagicMock()
    return node


def _frame(group, text=b'roster'):
    return bytes(group.encrypt(text, group))


def test_a_frame_under_a_key_not_yet_installed_opens_once_it_is():
    ours = Group.initialize({'me': '10.0.0.1'}, 'cohort')
    nxt = _rotated(ours)
    node = _node(ours)
    node._inbound_group({}, _frame(nxt), SENDER)
    assert node._msg_to_queue.call_count == 0
    assert len(node._held_group_frames) == 1
    # No key change yet: nothing to try, and the frame stays.
    assert node._retry_held_group_frames({}) == 0
    assert len(node._held_group_frames) == 1
    # The network process installs identity's key.
    node.current = nxt
    assert node._retry_held_group_frames({}) == 1
    assert node._msg_to_queue.call_count == 1
    assert node._msg_to_queue.call_args.args[0] == b'roster'
    assert len(node._held_group_frames) == 0


def test_a_frame_that_still_does_not_open_is_dropped():
    ours = Group.initialize({'me': '10.0.0.1'}, 'cohort')
    nxt, other = _rotated(ours), _rotated(ours)
    node = _node(ours)
    node._inbound_group({}, _frame(other), SENDER)
    node.current = nxt
    assert node._retry_held_group_frames({}) == 1
    assert node._msg_to_queue.call_count == 0
    assert len(node._held_group_frames) == 0


def test_a_frame_under_our_key_is_not_held():
    ours = Group.initialize({'me': '10.0.0.1'}, 'cohort')
    node = _node(ours)
    node._inbound_group({}, _frame(ours), SENDER)
    assert node._msg_to_queue.call_count == 1
    assert len(node._held_group_frames) == 0


def test_the_hold_is_bounded_and_keeps_the_newest():
    ours = Group.initialize({'me': '10.0.0.1'}, 'cohort')
    nxt, other = _rotated(ours), _rotated(ours)
    node = _node(ours)
    n = netprocess.NET_HELD_GROUP_FRAMES
    for i in range(n + 4):
        node._inbound_group({}, _frame(other if i < n else nxt), SENDER)
    assert len(node._held_group_frames) == n
    node.current = nxt
    assert node._retry_held_group_frames({}) == n
    assert node._msg_to_queue.call_count == 4


def test_a_frame_held_past_the_window_is_dropped(monkeypatch):
    ours = Group.initialize({'me': '10.0.0.1'}, 'cohort')
    node = _node(ours)
    node._inbound_group({}, _frame(_rotated(ours)), SENDER)
    clock = netprocess.time.monotonic() + netprocess.NET_HELD_GROUP_FRAME_SEC + 1
    monkeypatch.setattr(netprocess.time, 'monotonic', lambda: clock)
    assert node._retry_held_group_frames({}) == 0
    assert len(node._held_group_frames) == 0


def _injecting(node):
    """Let ``node`` take an extension's injection from the officer."""
    officer = SimpleNamespace(uuid='0ff1ce00-0000-4000-8000-000000000002',
                              address=SENDER, nickname='officer')
    node.protocol.peers.find_by_uuid = lambda u: officer \
        if str(u).lower() == officer.uuid else None
    node.is_excluded = lambda uuid, key=None: False
    node._via_ext = False
    seen = []
    node._msg_to_queue.side_effect = lambda *a, **k: seen.append(node._via_ext)
    return officer, seen


def test_an_injected_frame_keeps_its_mark_when_retried():
    """A held frame an extension injected is still one when it opens on retry:
    it is routed marked, so it never stamps transport liveness."""
    ours = Group.initialize({'me': '10.0.0.1'}, 'cohort')
    nxt = _rotated(ours)
    node = _node(ours)
    officer, seen = _injecting(node)
    assert NetworkProcess.inject_inbound(node, {}, 'group', _frame(nxt), officer.uuid)
    assert len(node._held_group_frames) == 1 and node._via_ext is False
    node.current = nxt
    assert node._retry_held_group_frames({}) == 1
    assert seen == [True]
    assert node._via_ext is False


def test_an_injected_frame_retried_from_outside_the_group_raises_no_signal():
    ours = Group.initialize({'me': '10.0.0.1'}, 'cohort')
    node = _node(ours)
    officer, _ = _injecting(node)
    assert NetworkProcess.inject_inbound(node, {}, 'group', _frame(_rotated(ours)),
                                         officer.uuid)
    # The sender has left the group by the time it is retried.
    node._group_for_sender = lambda addr: None
    node._groups_containing = lambda addr: []
    assert node._retry_held_group_frames({}) == 1
    node._signal_partition.assert_not_called()
    # The same frame heard by the transport does raise one.
    node._group_for_sender = lambda addr: node.current
    node._groups_containing = lambda addr: [node.current]
    node._inbound_group({}, _frame(_rotated(ours)), SENDER)
    node._group_for_sender = lambda addr: None
    node._groups_containing = lambda addr: []
    assert node._retry_held_group_frames({}) == 1
    node._signal_partition.assert_called_once()
