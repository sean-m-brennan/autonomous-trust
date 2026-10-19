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
"""Two founders bridged by a common joiner (Stele st-284840, 2026-10-02).

Both founded a group, the observer was admitted by both and adopted one, and
nobody told the other founder, so the two never met. A node that holds one
group but was admitted into another now sends the other group's members its
history, once per group; a self-bootstrapped founder merges on it through
receive_history -> _merge_to_mesh. Twin of C bridged_group_test.c.
"""
import threading
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

from autonomous_trust.core.identity import Group, Identity
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.system import CfgIds


_ADDR = iter(range(1, 250))


def _peer(nick):
    return Identity.initialize(nick, nick, '10.0.0.%d' % next(_ADDR))


def _node(me, peers):
    node = object.__new__(IdentityProcess)
    node.name = 'identity'
    node.logger = MagicMock()
    node.lock = threading.RLock()
    node.q_cadence = 0.1
    node._told_bridged = []
    node.group = Group(uuid.uuid4(), {str(me.uuid): me.address}, 'ours', None)
    by_uuid = {str(p.uuid): p for p in peers}
    node.peers = SimpleNamespace(find_by_uuid=lambda u: by_uuid.get(str(u).lower()))
    node._history_payload = lambda: 'history'
    return node


def _queues():
    return {CfgIds.network: MagicMock()}


def _sent(queues):
    return [c.args[0] for c in queues[CfgIds.network].put.call_args_list]


def _canonical(members):
    return {'uuid': str(uuid.uuid4()),
            'address_map': {str(m.uuid): m.address for m in members}}


def test_a_node_admitted_by_two_groups_tells_the_other_one_once():
    me, ver = _peer('observer'), _peer('verifier')
    node = _node(me, [ver])
    queues = _queues()
    other = _canonical([ver, me])
    assert node._tell_bridged_group(queues, other) == 1
    sent = _sent(queues)
    assert len(sent) == 1
    assert sent[0].function == IdentityProtocol.history
    assert sent[0].to_whom == [ver]
    assert node._tell_bridged_group(queues, other) == 0
    assert len(_sent(queues)) == 1


def test_our_own_group_and_shared_members_are_not_told():
    me, own = _peer('observer'), _peer('owner')
    node = _node(me, [own])
    node.group.add_address(str(own.uuid), own.address)
    queues = _queues()
    assert node._tell_bridged_group(queues, node.group) == 0
    assert node._tell_bridged_group(queues, _canonical([own, me])) == 0
    assert _sent(queues) == []


def test_a_member_we_do_not_hold_as_a_peer_is_not_told():
    me, ver = _peer('observer'), _peer('verifier')
    node = _node(me, [])
    queues = _queues()
    assert node._tell_bridged_group(queues, _canonical([ver])) == 0
    assert _sent(queues) == []


def test_choosing_between_two_groups_tells_the_one_not_adopted():
    """The shape st-284840 had: both founders' histories arrive while the
    observer chooses. It adopts the first group and tells the second's
    member."""
    me, own, ver = _peer('observer'), _peer('owner'), _peer('verifier')
    node = _node(me, [own, ver])
    node.choosing = False
    node.configs = {}
    node.cadence = 0.01
    node.init_timeout = 5
    node.phase = 2
    node._record_group = MagicMock()
    node._populate_peers_from_history = MagicMock()
    node._history = MagicMock()
    node._history.catch_up.return_value = []
    node.report_exception = MagicMock(side_effect=AssertionError)
    first = Group.initialize({own.uuid: own.address, me.uuid: me.address}, 'first')
    second = Group.initialize({ver.uuid: ver.address, me.uuid: me.address}, 'second')
    node.histories = [(first.to_canonical(), ['step'], []),
                      (second.to_canonical(), ['step'], [])]
    queues = _queues()
    node.choose_group(queues)
    assert str(node.group.uuid) == str(first.uuid)
    told = [m for m in _sent(queues) if m.function == IdentityProtocol.history]
    assert len(told) == 1 and told[0].to_whom == [ver]
