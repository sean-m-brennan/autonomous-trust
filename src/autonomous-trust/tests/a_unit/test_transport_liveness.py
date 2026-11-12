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
"""When a peer was last heard through the node's own transport, kept apart
from frames an extension delivered some other way."""
import time
import types
import uuid as uuid_mod

import pytest

from autonomous_trust.core._python.network import netprocess
from autonomous_trust.core._python.network.liveness import TransportLiveness
from autonomous_trust.core._python.network.netprocess import NetworkProcess

#: The network process's monotonic clock, pinned by the ``clock`` fixture.
NOW = 100.0


class _PinnedClock:
    """The time module, with monotonic() pinned to NOW."""
    monotonic = staticmethod(lambda: NOW)

    def __getattr__(self, name):
        return getattr(time, name)


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(netprocess, 'time', _PinnedClock())


def test_never_heard_counts_from_start():
    lv = TransportLiveness(100.0)
    assert lv.quiet_for(uuid_mod.uuid4(), 130.0) == 30.0


def test_heard_resets_quiet_and_older_is_ignored():
    lv = TransportLiveness(100.0)
    a = uuid_mod.uuid4()
    lv.heard(a, 140.0)
    assert lv.quiet_for(a, 150.0) == 10.0
    lv.heard(a, 120.0)
    assert lv.quiet_for(str(a).upper(), 150.0) == 10.0


def test_quiet_is_never_negative():
    lv = TransportLiveness(100.0)
    a = uuid_mod.uuid4()
    lv.heard(a, 200.0)
    assert lv.quiet_for(a, 150.0) == 0.0


def test_full_table_forgets_the_longest_quiet():
    lv = TransportLiveness(0.0)
    first = uuid_mod.uuid4()
    lv.heard(first, 1.0)
    for i in range(TransportLiveness.MAX - 1):
        lv.heard(uuid_mod.uuid4(), 10.0 + i)
    extra = uuid_mod.uuid4()
    lv.heard(extra, 5000.0)
    assert lv.quiet_for(extra, 5000.0) == 0.0
    assert lv.quiet_for(first, 5000.0) == 5000.0


def test_transport_frames_stamp_and_extension_frames_do_not(clock):
    stub = types.SimpleNamespace(_liveness=TransportLiveness(0.0), _via_ext=False)
    a, b = uuid_mod.uuid4(), uuid_mod.uuid4()
    NetworkProcess._note_transport_heard(stub, a)
    stub._via_ext = True
    NetworkProcess._note_transport_heard(stub, b)
    assert NetworkProcess.transport_quiet_for(stub, a) == 0.0
    assert NetworkProcess.transport_quiet_for(stub, b) == NOW


def test_quiet_before_the_process_runs_is_zero():
    stub = types.SimpleNamespace(_liveness=None)
    assert NetworkProcess.transport_quiet_for(stub, uuid_mod.uuid4()) == 0.0


def _routing_proc():
    """A NetworkProcess stand-in with the real router and liveness stamp."""
    import logging
    from unittest.mock import MagicMock
    from autonomous_trust.core._python.network.presence import PresenceTracker
    proc = MagicMock(spec=NetworkProcess)
    proc.name = 'network'
    proc.q_cadence = 0
    proc.logger = logging.getLogger('test.net.liveness')
    proc._presence = PresenceTracker(30.0, 90.0)
    proc._liveness = TransportLiveness(0.0)
    proc._via_ext = False
    proc._foreign_format_counts = {}
    proc._crosses_gateway.return_value = False
    for name in ('_msg_to_queue', '_note_transport_heard', 'transport_quiet_for'):
        setattr(proc, name, getattr(NetworkProcess, name).__get__(proc))
    return proc


def test_only_member_paths_stamp_a_claimed_uuid(clock):
    """A stranger, a relayed stranger or the broadcast channel can claim a
    member's uuid in its envelope; only a frame from a peer we hold (the peer
    and group paths) says the transport reaches that peer."""
    import queue
    from autonomous_trust.core.identity import Identity
    from autonomous_trust.core.network.message import Message
    bob = Identity.initialize('bob', 'bob', '10.0.0.2')
    wire = bytes(Message('identity', 'request_access', '{}', from_whom=bob))
    key = str(bob.uuid).lower()
    for frm, rcvd_by in (('10.0.0.9', 'point-to-point'), ('10.0.0.9', 'multicast'),
                         ('relay:' + key, 'relay')):
        proc = _routing_proc()
        proc._msg_to_queue(wire, frm, {'identity': queue.Queue()}, rcvd_by,
                           validate=False)
        assert proc.transport_quiet_for(key) == NOW, rcvd_by
    for rcvd_by in ('point-to-point', 'group'):
        proc = _routing_proc()
        proc._msg_to_queue(bytes(Message('identity', 'peer_dm', '{}', from_whom=bob)),
                           bob, {'identity': queue.Queue()}, rcvd_by, validate=False)
        assert proc.transport_quiet_for(key) == 0.0, rcvd_by
