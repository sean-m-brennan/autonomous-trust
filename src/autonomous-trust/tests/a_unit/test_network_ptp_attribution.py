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

"""Inbound attribution (doc/architecture/network-connection-pooling.md, the
attribution-miss item): the point-to-point drain must attribute inbound frames
against the LIVE roster (``self.peers``), never the bootstrap ``Peers`` object
in ``configs[CfgIds.peers]``.

That config holds only the welcomer's address, so consulting it missed ~every
inbound message; each one then detoured through the mystery defer/retry path
and a share of them aged out and were dropped. The fix was one line, nothing
pinned it, and the two objects are interchangeable at a glance -- which is
exactly the shape of bug that comes back.
"""
import queue
import threading
from collections import deque
from unittest.mock import MagicMock, patch

import pytest

from autonomous_trust.core.network.netprocess import NetworkProcess


KNOWN_ADDR = '10.0.4.21'


def _drain_proc(live_roster, bootstrap_roster):
    """A NetworkProcess stand-in carrying just what the ptp drain touches,
    with the real `process` bound to it. One loop pass, then stop."""
    proc = MagicMock(spec=NetworkProcess)
    proc.name = 'network'
    proc.q_cadence = 0
    proc.socket_timeout = 0.1
    proc.stop = False
    # Off: the diplomat branch would bind a real PingAT socket.
    proc.diplomat = False
    proc.ping_at_server = None
    proc.reject_message.return_value = False   # nobody is excluded
    proc.peer_messages = deque()
    proc.group_messages = deque()
    proc.unknown_messages = deque()
    proc.encrypted_messages = deque()
    proc.group = None                          # skips the group drain
    proc.logger = MagicMock()
    # Set in __init__, so not on the class spec -- assign them explicitly.
    proc.recv_ptp_sock = MagicMock()
    proc.recv_grp_sock = MagicMock()
    proc.recv_cast_sock = MagicMock()
    proc.myself = MagicMock()

    # The two rosters the drain could consult. `peers` is the live one.
    proc.peers = live_roster
    proc.configs = {'peers': bootstrap_roster}

    # keep_running: exactly one pass.
    passes = {'n': 0}

    def _once(_signal):
        passes['n'] += 1
        return passes['n'] == 1

    proc.keep_running.side_effect = _once

    proc.process = NetworkProcess.process.__get__(proc)
    return proc


def _empty_queue():
    q = MagicMock()
    q.get.side_effect = queue.Empty
    return q


def _run_drain(proc):
    # The real process() spawns two daemon threads on mocked targets; harmless,
    # but keep them from doing anything by making Thread a no-op recorder.
    with patch.object(threading, 'Thread'):
        proc.process({'network': _empty_queue()}, MagicMock())


def _roster(known=()):
    r = MagicMock()
    r.listing = {a: MagicMock() for a in known}

    def find(address):
        return r.listing.get(address)

    r.find_by_address.side_effect = find
    return r


def test_known_peer_is_attributed_from_the_live_roster():
    live = _roster([KNOWN_ADDR])
    bootstrap = _roster()           # welcomer only -- does not know this peer
    proc = _drain_proc(live, bootstrap)
    proc.peer_messages.append((b'ciphertext', KNOWN_ADDR))

    _run_drain(proc)

    live.find_by_address.assert_any_call(KNOWN_ADDR)
    # attributed => decrypted against that peer, not deferred
    proc.myself.decrypt.assert_called_once()
    assert proc.myself.decrypt.call_args[0][1] is live.listing[KNOWN_ADDR]
    assert len(proc.encrypted_messages) == 0, \
        'an attributable frame must not reach the mystery defer path'


def test_bootstrap_roster_is_never_consulted():
    """The regression itself: `configs[CfgIds.peers]` must not be the roster
    the drain attributes against."""
    live = _roster([KNOWN_ADDR])
    bootstrap = _roster()
    proc = _drain_proc(live, bootstrap)
    proc.peer_messages.append((b'ciphertext', KNOWN_ADDR))

    _run_drain(proc)

    bootstrap.find_by_address.assert_not_called()


def test_genuinely_unknown_sender_still_defers():
    """The other half: a frame we cannot attribute AND cannot parse as
    plaintext is still deferred rather than dropped -- that path is what the
    bootstrap/late-joiner handshake relies on."""
    live = _roster()                # knows nobody
    proc = _drain_proc(live, _roster())
    proc.peer_messages.append((b'\xff\xfe ciphertext', '10.0.4.99'))
    proc._msg_to_queue.side_effect = UnicodeDecodeError(
        'utf-8', b'\xff', 0, 1, 'invalid start byte')

    _run_drain(proc)

    assert len(proc.encrypted_messages) == 1
    assert proc.encrypted_messages[0][1] == '10.0.4.99'


def _real_msg_to_queue(proc):
    """Bind the real `_msg_to_queue` (the other tests mock it) plus the one
    instance attribute it keeps state in."""
    proc._foreign_format_counts = {}
    proc._msg_to_queue = NetworkProcess._msg_to_queue.__get__(proc)
    return proc


def test_unknown_sender_ciphertext_opening_with_the_proto_marker_defers():
    """Ciphertext is uniform bytes, so one deferred frame in 256 opens with
    NET_WIRE_PROTO_MAGIC by chance. On the unknown-sender path that byte does
    NOT mean a foreign cohort -- it means "not a plaintext JSON envelope", the
    same verdict a UnicodeDecodeError carries -- so the frame must be deferred
    for the sender's admission, not dropped. Dropping it made
    tests/b_integration/test_two_node.py fail intermittently with a
    'Dropping point-to-point frame ... refusing a proto envelope' error, and
    C's handle_inbound_peer defers every parse failure on this path.
    """
    live = _roster()                # knows nobody yet
    proc = _real_msg_to_queue(_drain_proc(live, _roster()))
    proc.peer_messages.append((b'\xabciphertext that is not an envelope', '10.0.4.99'))

    _run_drain(proc)

    assert len(proc.encrypted_messages) == 1, \
        'a 0xAB-leading frame from an unknown sender must reach the mystery ' \
        'defer path, not the foreign-format drop'
    assert proc.encrypted_messages[0][1] == '10.0.4.99'
    assert not proc.logger.error.called


def test_foreign_format_frame_from_a_placed_sender_is_still_dropped():
    """The other side of it: once the bytes ARE known to be an envelope (a
    decrypted frame, or the multicast channel, where nothing is ever
    ciphertext), a foreign marker is the real diagnosis and keeps its
    rate-limited error -- `opaque` must not relax the gate everywhere."""
    proc = _real_msg_to_queue(_drain_proc(_roster(), _roster()))

    proc._msg_to_queue(b'\xab\x01proto envelope', '10.0.4.99', {},
                       'multicast', validate=False)

    assert proc._foreign_format_counts['10.0.4.99'] == 1
    proc.logger.error.assert_called_once()
    assert 'refusing a proto envelope' in str(proc.logger.error.call_args[0][3])
