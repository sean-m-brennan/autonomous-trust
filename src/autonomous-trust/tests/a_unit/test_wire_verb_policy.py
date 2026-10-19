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
"""What an inbound wire frame may carry, by the path it came in on (ISSUES
§2.17).

A handler's local-origin check reads from_whom, and a stranger chooses what
its envelope claims, so the refusal is made on the frame's NAMES before
routing: never an ``app_*`` verb, never a command to the network process but a
remote stats_req, and from a sender we do not hold only the plaintext (or, on
the multicast channel, the broadcast) verbs. Mirrors the C twin,
test/net_route_policy_test.c.
"""
import logging
import queue
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.network.netprocess import NetworkProcess
from autonomous_trust.core._python.network.netprocess import (
    PATH_BROADCAST, PATH_GROUP, PATH_PEER, PATH_RELAY_STRANGER, PATH_STRANGER,
    wire_verb_admitted)
from autonomous_trust.core._python.network.presence import PresenceTracker
from autonomous_trust.core.system import CfgIds

ALL_PATHS = (PATH_PEER, PATH_STRANGER, PATH_RELAY_STRANGER, PATH_BROADCAST,
             PATH_GROUP)


def _ok(process, function, path):
    return wire_verb_admitted(process, function, path)[0]


class TestPolicy:
    @pytest.mark.parametrize('path', ALL_PATHS)
    def test_an_app_verb_is_never_routed_from_the_wire(self, path):
        for fn in ('app_send_dm', 'app_block', 'app_roster_request'):
            assert not _ok(CfgIds.identity, fn, path)
        assert not _ok(CfgIds.reputation, 'app_roster_request', path)

    def test_the_peer_verbs_are_ordinary_traffic(self):
        assert _ok(CfgIds.identity, 'peer_dm', PATH_PEER)
        assert _ok(CfgIds.identity, 'peer_dm', PATH_GROUP)
        assert _ok(CfgIds.reputation, 'transaction', PATH_PEER)

    def test_the_network_process_takes_only_stats_req(self):
        assert _ok(CfgIds.network, 'stats_req', PATH_PEER)
        for fn in ('exclude', 'readmit', 'relay_route', 'stats_resp', 'peer_dm'):
            assert not _ok(CfgIds.network, fn, PATH_PEER)
        assert not _ok(CfgIds.network, 'readmit', PATH_GROUP)

    @pytest.mark.parametrize('path', (PATH_STRANGER, PATH_RELAY_STRANGER))
    def test_a_stranger_sends_only_plaintext_verbs(self, path):
        assert _ok(CfgIds.identity, 'access_granted', path)
        assert _ok(CfgIds.identity, 'subtree_roster_response', path)
        for fn in ('peer_dm', 'full_history', 'group_key_update'):
            assert not _ok(CfgIds.identity, fn, path)
        assert not _ok(CfgIds.reputation, 'transaction', path)

    def test_the_broadcast_channel_carries_discovery_only(self):
        for fn in ('request_access', 'peer_identity_query', 'peer_identity_response',
                   'group_partition_probe', 'group_partition_response',
                   'group_key_update', 'peer_accepted', 'propose_peer'):
            assert _ok(CfgIds.identity, fn, PATH_BROADCAST)
        assert not _ok(CfgIds.identity, 'peer_dm', PATH_BROADCAST)
        assert not _ok(CfgIds.reputation, 'transaction', PATH_BROADCAST)


def _identity(name, address):
    return Identity.initialize(name, name, address)


def _net_proc():
    """A NetworkProcess stand-in carrying what _msg_to_queue touches, with the
    real method bound to it (as test_peer_presence does)."""
    proc = MagicMock(spec=NetworkProcess)
    proc.name = CfgIds.network
    proc.q_cadence = 0
    proc.logger = logging.getLogger('test.net.wire_policy')
    proc._presence = PresenceTracker(30.0, 90.0)
    proc._msg_to_queue = NetworkProcess._msg_to_queue.__get__(proc)
    proc._foreign_format_counts = {}
    proc._crosses_gateway.return_value = False
    return proc


def _queues():
    return {name: queue.Queue() for name in (CfgIds.network, CfgIds.identity,
                                             CfgIds.reputation)}


def _routed(qs):
    out = []
    for q in qs.values():
        while not q.empty():
            out.append(q.get_nowait().function)
    return out


def _frame(fn, sender, process=CfgIds.identity):
    return bytes(Message(process, fn, '{}', from_whom=sender))


class TestMsgToQueue:
    me = _identity('me', '10.0.0.1')
    bob = _identity('bob', '10.0.0.2')

    def test_a_stranger_claiming_us_is_refused_an_app_verb(self):
        proc, qs = _net_proc(), _queues()
        proc._msg_to_queue(_frame('app_block', self.me), '10.0.0.9', qs,
                           'point-to-point', validate=False)
        proc._msg_to_queue(_frame('peer_dm', self.me), '10.0.0.9', qs,
                           'point-to-point', validate=False)
        assert _routed(qs) == []
        proc._msg_to_queue(_frame('access_granted', self.bob), '10.0.0.9', qs,
                           'point-to-point', validate=False)
        assert _routed(qs) == ['access_granted']

    def test_the_multicast_channel_carries_discovery_only(self):
        proc, qs = _net_proc(), _queues()
        proc._msg_to_queue(_frame('peer_dm', self.bob), '10.0.0.9', qs,
                           'multicast', validate=False)
        assert _routed(qs) == []
        proc._msg_to_queue(_frame('request_access', self.bob), '10.0.0.9', qs,
                           'multicast', validate=False)
        assert _routed(qs) == ['request_access']

    def test_a_relayed_stranger_sends_only_plaintext(self):
        proc, qs = _net_proc(), _queues()
        proc._msg_to_queue(_frame('peer_dm', self.bob), 'relay:' + str(self.bob.uuid),
                           qs, 'relay', validate=False)
        assert _routed(qs) == []

    def test_a_peer_may_not_command_us(self):
        proc, qs = _net_proc(), _queues()
        proc._msg_to_queue(_frame('app_send_dm', self.bob), self.bob, qs,
                           'point-to-point', validate=False)
        proc._msg_to_queue(_frame('exclude', self.bob, CfgIds.network), self.bob,
                           qs, 'point-to-point', validate=False)
        assert _routed(qs) == []
        proc._msg_to_queue(_frame('peer_dm', self.bob), self.bob, qs,
                           'point-to-point', validate=False)
        assert _routed(qs) == ['peer_dm']
