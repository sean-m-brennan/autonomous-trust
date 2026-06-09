# ******************
#  Copyright 2026 Sean M. Brennan and contributors
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

"""Unit tests for IdentityProcess._periodic_caps_resync — the periodic
backstop for the late-joiner capability-loss UDP case
(feedback_late_joiner_caps).

The confirm-time directed caps_query recovers a peer whose announce was
lost, but it is a one-shot; if that query or its response is also dropped,
the peer stays in self.peers yet absent from peer_capabilities. The sweep
re-queries every cap-less admitted peer until its caps arrive.

These build a minimal IdentityProcess via object.__new__ (mirrors
test_partition_recovery.py) so the real method runs without a config tree.
"""

import logging
from unittest.mock import MagicMock, patch

from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.capabilities import PeerCapabilities
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core._python.protocol import Protocol


_MOCK_ADDRESSES = {
    'ip4': '192.168.1.1',
    'ip6': '::1',
    'mac': '00:11:22:33:44:55',
    'ip4_subnet': '255.255.255.0',
    'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'mac_bcast': 'ff:ff:ff:ff:ff:ff',
}


def _new_identity(name, address):
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_MOCK_ADDRESSES):
        return Identity.initialize(name, name, address)


class _FakeQueue:
    def __init__(self):
        self.items = []

    def put(self, item, block=True, timeout=None):
        self.items.append(item)

    def put_nowait(self, item):
        self.items.append(item)

    def __len__(self):
        return len(self.items)


def _build_process(identity, peers, peer_capabilities=None):
    proc = object.__new__(IdentityProcess)
    proc.identity = identity
    proc.group = object()  # non-None sentinel; sweep only checks `is None`
    proc.peers = peers
    proc.peer_capabilities = peer_capabilities or PeerCapabilities()
    proc.protocol = Protocol(CfgIds.identity, logging.getLogger('test'), None)
    proc.name = CfgIds.identity
    proc.logger = logging.getLogger('test.idproc.capresync')
    proc.q_cadence = 0.01
    proc.phase = 3
    proc.choosing = False
    proc.lock = MagicMock()
    proc.lock.__enter__ = MagicMock(return_value=proc.lock)
    proc.lock.__exit__ = MagicMock(return_value=False)
    proc.report_exception = lambda err, where: \
        proc.logger.exception('%s: %s' % (where, err))
    return proc


def _queues():
    return {CfgIds.network: _FakeQueue()}


def _caps_queries(queues):
    return [m for m in queues[CfgIds.network].items
            if m.function == IdentityProtocol.caps_query]


def _target_uuid(msg):
    """Message normalizes to_whom to a list; pull the single recipient uuid."""
    to = msg.to_whom
    if isinstance(to, (list, tuple)):
        to = to[0]
    return str(to.uuid)


def test_capless_peers_each_requeried():
    me = _new_identity('coord', '10.0.0.1')
    a = _new_identity('alice', '10.0.0.2')
    b = _new_identity('bob', '10.0.0.3')
    peers = Peers()
    peers.add(a)
    peers.add(b)
    proc = _build_process(me, peers)  # no caps registered for anyone
    queues = _queues()

    proc._periodic_caps_resync(queues)

    queried = _caps_queries(queues)
    assert len(queried) == 2
    targets = {_target_uuid(m) for m in queried}
    assert targets == {str(a.uuid), str(b.uuid)}


def test_peer_with_any_cap_is_skipped():
    me = _new_identity('coord', '10.0.0.1')
    a = _new_identity('alice', '10.0.0.2')
    b = _new_identity('bob', '10.0.0.3')
    peers = Peers()
    peers.add(a)
    peers.add(b)
    pc = PeerCapabilities()
    pc.register(a.uuid, ['airquality_stream'])  # alice known, bob cap-less
    proc = _build_process(me, peers, pc)
    queues = _queues()

    proc._periodic_caps_resync(queues)

    queried = _caps_queries(queues)
    assert len(queried) == 1
    assert _target_uuid(queried[0]) == str(b.uuid)


def test_record_peers_reliably_puts_to_main():
    # Regression (dod-coordinator-partition-nonconvergence.md layer 3):
    # _remember_activity's update() fan-put uses the 10ms q_cadence timeout
    # and silently DROPS the Peers broadcast under main-proc queue contention
    # (the dod_mission coordinator drowning in rep_resp traffic), so the main
    # proc's self.peers stayed at 1 while group membership grew -> consensus
    # reputations could never be named -> dashboard stuck "forming…".
    # _record_peers now does a reliable 1s-timeout put of self.peers to the
    # main queue, mirroring handle_caps_response's peer_capabilities fix.
    me = _new_identity('coord', '10.0.0.1')
    a = _new_identity('alice', '10.0.0.2')
    peers = Peers()
    peers.add(a)
    proc = _build_process(me, peers)
    # Isolate the new explicit main-put from _remember_activity's file I/O.
    proc._remember_activity = lambda *args, **kwargs: None
    queues = {CfgIds.network: _FakeQueue(), CfgIds.main: _FakeQueue()}

    proc._record_peers(queues)

    main_puts = [m for m in queues[CfgIds.main].items if isinstance(m, Peers)]
    assert len(main_puts) == 1
    assert main_puts[0] is proc.peers


def test_record_peers_without_main_queue_is_safe():
    # A process whose queue map omits CfgIds.main must not raise.
    me = _new_identity('coord', '10.0.0.1')
    proc = _build_process(me, Peers())
    proc._remember_activity = lambda *args, **kwargs: None
    queues = {CfgIds.network: _FakeQueue()}
    proc._record_peers(queues)  # no CfgIds.main -> no-op, no raise


def test_converged_group_emits_nothing():
    me = _new_identity('coord', '10.0.0.1')
    a = _new_identity('alice', '10.0.0.2')
    peers = Peers()
    peers.add(a)
    pc = PeerCapabilities()
    pc.register(a.uuid, ['sensor_validation'])
    proc = _build_process(me, peers, pc)
    queues = _queues()

    proc._periodic_caps_resync(queues)

    assert _caps_queries(queues) == []


def test_self_is_never_queried():
    me = _new_identity('coord', '10.0.0.1')
    peers = Peers()  # only self in the world
    proc = _build_process(me, peers)
    queues = _queues()

    proc._periodic_caps_resync(queues)

    assert _caps_queries(queues) == []


def test_sweep_bounded_per_run():
    me = _new_identity('coord', '10.0.0.1')
    peers = Peers()
    n = IdentityProcess._CAPS_RESYNC_MAX_PER_SWEEP + 5
    for i in range(n):
        peers.add(_new_identity('p%d' % i, '10.0.1.%d' % i))
    proc = _build_process(me, peers)
    queues = _queues()

    proc._periodic_caps_resync(queues)

    queried = _caps_queries(queues)
    assert len(queried) == IdentityProcess._CAPS_RESYNC_MAX_PER_SWEEP


def test_suppressed_when_not_operational():
    me = _new_identity('coord', '10.0.0.1')
    a = _new_identity('alice', '10.0.0.2')
    peers = Peers()
    peers.add(a)

    # phase != 3
    proc = _build_process(me, peers)
    proc.phase = 1
    queues = _queues()
    proc._periodic_caps_resync(queues)
    assert _caps_queries(queues) == []

    # still choosing a group
    proc = _build_process(me, peers)
    proc.choosing = True
    queues = _queues()
    proc._periodic_caps_resync(queues)
    assert _caps_queries(queues) == []

    # no group yet
    proc = _build_process(me, peers)
    proc.group = None
    queues = _queues()
    proc._periodic_caps_resync(queues)
    assert _caps_queries(queues) == []
