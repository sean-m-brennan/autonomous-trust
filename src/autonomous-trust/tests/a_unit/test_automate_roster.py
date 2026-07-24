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
"""Unit coverage for the app-facing subtree-roster walk in automate.py.

The requestor-side breadth-first enumeration is unrolled across message
ticks: request_subtree_roster seeds the first roster_req, and each
roster_resp is folded in by _consume_roster_resp, which fans out a
roster_req to every newly-named child gateway. These tests drive that
state machine directly with an in-memory network queue and a peer table.

See doc/architecture/gateway-reputation-tree.md.
"""
import queue
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from autonomous_trust.core.automate import AutonomousTrust
from autonomous_trust.core.identity.identity import Identity
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import to_json_string

_MOCK_ADDRESSES = {'mac_bcast': 'ff:ff:ff:ff:ff:ff'}


def _new_identity(name, address):
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_MOCK_ADDRESSES):
        return Identity.initialize(name, name, address)


class _Peers:
    def __init__(self, by_uuid):
        self._by_uuid = {str(k): v for k, v in by_uuid.items()}

    def find_by_uuid(self, uuid):
        return self._by_uuid.get(str(uuid))


def _auto(self_id, peers):
    auto = AutonomousTrust.__new__(AutonomousTrust)
    auto.identity = self_id
    auto.peers = peers
    auto.logger = MagicMock()
    auto.subtree_roster = {}
    auto.subtree_roster_complete = True
    auto.subtree_roster_private = []
    auto._roster_visited = set()
    auto._roster_pending = set()
    return auto


def _resp(responder, members, child_gateways, private=False):
    obj = to_json_string({
        'members': [{'uuid': str(u), 'nickname': None, 'address': None} for u in members],
        'child_gateways': [str(c) for c in child_gateways],
        'private': private})
    return Message(CfgIds.identity, IdentityProtocol.roster_resp, obj,
                   to_whom=None, from_whom=responder, encrypt=False)


def _drain_reqs(q):
    """Pull all roster_req messages off the network queue, returning the
    uuid each was addressed to."""
    targets = []
    while True:
        try:
            msg = q.get_nowait()
        except queue.Empty:
            break
        assert msg.function == IdentityProtocol.roster_req
        # to_whom is a 1-element list of Identity
        targets.append(str(msg.to_whom[0].uuid))
    return targets


def test_request_seeds_first_roster_req():
    me = _new_identity('me', '10.2.0.9')
    top = _new_identity('top', '10.2.0.1')
    auto = _auto(me, _Peers({top.uuid: top}))
    q = queue.Queue()
    auto.request_subtree_roster({CfgIds.network: q}, top)
    assert _drain_reqs(q) == [str(top.uuid)]
    assert auto._roster_pending == {str(top.uuid)}
    assert auto._roster_visited == {str(top.uuid)}
    assert auto.subtree_roster_complete is True


def test_request_by_uuid_resolves_via_peers():
    me = _new_identity('me', '10.2.0.9')
    top = _new_identity('top', '10.2.0.1')
    auto = _auto(me, _Peers({top.uuid: top}))
    q = queue.Queue()
    auto.request_subtree_roster({CfgIds.network: q}, str(top.uuid))  # uuid, not Identity
    assert _drain_reqs(q) == [str(top.uuid)]


def test_request_unroutable_top_is_incomplete():
    me = _new_identity('me', '10.2.0.9')
    auto = _auto(me, _Peers({}))
    q = queue.Queue()
    auto.request_subtree_roster({CfgIds.network: q}, 'ghost-uuid')
    assert auto.subtree_roster_complete is False
    assert _drain_reqs(q) == []


def test_full_walk_three_levels():
    me = _new_identity('me', '10.2.0.9')
    top = _new_identity('top', '10.2.0.1')
    mid = _new_identity('mid', '10.2.0.2')
    leaf = _new_identity('leaf', '10.2.0.3')
    T, M, L = str(top.uuid), str(mid.uuid), str(leaf.uuid)
    auto = _auto(me, _Peers({top.uuid: top, mid.uuid: mid, leaf.uuid: leaf}))
    q = queue.Queue()
    queues = {CfgIds.network: q}

    auto.request_subtree_roster(queues, top)
    assert _drain_reqs(q) == [T]

    auto._consume_roster_resp(queues, _resp(top, [T, M], [M]))
    assert _drain_reqs(q) == [M]                 # fanned out to mid
    assert auto._roster_pending == {M}

    auto._consume_roster_resp(queues, _resp(mid, [M, L], [L]))
    assert _drain_reqs(q) == [L]                 # fanned out to leaf
    assert auto._roster_pending == {L}

    auto._consume_roster_resp(queues, _resp(leaf, [L, 'm1', 'm2'], []))
    assert _drain_reqs(q) == []                  # nothing left to pursue
    assert auto._roster_pending == set()         # walk settled
    assert auto.subtree_roster_complete is True
    assert sorted(auto.subtree_roster) == sorted([T, M, L, 'm1', 'm2'])


def test_private_gateway_stops_the_walk_without_failure():
    me = _new_identity('me', '10.2.0.9')
    top = _new_identity('top', '10.2.0.1')
    mid = _new_identity('mid', '10.2.0.2')
    T, M = str(top.uuid), str(mid.uuid)
    auto = _auto(me, _Peers({top.uuid: top, mid.uuid: mid}))
    q = queue.Queue()
    queues = {CfgIds.network: q}

    auto.request_subtree_roster(queues, top)
    _drain_reqs(q)
    auto._consume_roster_resp(queues, _resp(top, [T, M], [M]))
    _drain_reqs(q)
    # mid opted out: no members, no children, private marker
    auto._consume_roster_resp(queues, _resp(mid, [], [], private=True))
    assert _drain_reqs(q) == []                  # no recursion behind mid
    assert auto._roster_pending == set()
    assert auto.subtree_roster_complete is True  # privacy != failure
    assert auto.subtree_roster_private == [M]
    assert sorted(auto.subtree_roster) == sorted([T, M])


def test_unroutable_child_marks_incomplete_but_continues():
    me = _new_identity('me', '10.2.0.9')
    top = _new_identity('top', '10.2.0.1')
    known = _new_identity('known', '10.2.0.2')
    T, K = str(top.uuid), str(known.uuid)
    auto = _auto(me, _Peers({top.uuid: top, known.uuid: known}))
    q = queue.Queue()
    queues = {CfgIds.network: q}

    auto.request_subtree_roster(queues, top)
    _drain_reqs(q)
    # top names one routable child (known) and one we cannot resolve (ghost)
    auto._consume_roster_resp(queues, _resp(top, [T], [K, 'ghost']))
    assert _drain_reqs(q) == [K]                 # pursued the routable one
    assert auto.subtree_roster_complete is False  # ...but flagged the ghost
