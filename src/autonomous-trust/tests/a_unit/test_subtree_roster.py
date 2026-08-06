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
"""Unit coverage for hierarchy-aware subtree member-roster enumeration.

Exercises the three pieces of the lean membership capability:
  * ``enumerate_local_members`` — a node's own contribution (self + primary
    group + each gatewayed child group), deduped and sorted;
  * ``handle_roster_request`` — the non-blocking reply carrying local members
    plus the child gateways to recurse into;
  * ``aggregate_subtree_roster`` — the requestor-side breadth-first flatten of
    the whole cohort tree over an injected per-gateway fetch.

See doc/architecture/gateway-reputation-tree.md.
"""
import logging
import queue
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from autonomous_trust.core.identity.idprocess import (
    IdentityProcess, aggregate_subtree_roster,
)
from autonomous_trust.core.identity.identity import Identity
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import from_json_string, to_json_string

_MOCK_ADDRESSES = {'mac_bcast': 'ff:ff:ff:ff:ff:ff'}


def _new_identity(name, address):
    """A real Identity (Message validates to_whom/from_whom are Identities)."""
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_MOCK_ADDRESSES):
        return Identity.initialize(name, name, address)


def _group(uuid, members):
    """members: dict uuid_str -> address."""
    return SimpleNamespace(uuid=uuid, _address_map=dict(members),
                           addresses=list(members.values()),
                           nickname='grp-%s' % uuid)


class _Peers:
    def __init__(self, names):  # uuid_str -> nickname
        self._names = names

    def find_by_uuid(self, uuid):
        nick = self._names.get(str(uuid))
        return SimpleNamespace(nickname=nick) if nick else None


def _node(identity_uuid, primary=None, child_groups=None, child_gateways=None,
          names=None, identity=None):
    proc = IdentityProcess.__new__(IdentityProcess)
    proc.identity = identity if identity is not None else SimpleNamespace(
        uuid=identity_uuid, address='addr-%s' % identity_uuid,
        nickname='node-%s' % identity_uuid)
    proc.group = primary
    proc.child_groups = child_groups or {}
    proc.child_gateways = child_gateways or {}
    proc.roster_private = False
    proc.peers = _Peers(names or {})
    proc.name = CfgIds.identity
    proc.q_cadence = 0.01
    proc.logger = MagicMock()
    proc.report_exception = MagicMock()
    return proc


def _uuids(roster):
    return sorted(m['uuid'] for m in roster)


# --- enumerate_local_members ------------------------------------------------

def test_local_members_leaf_is_self_plus_primary_group():
    node = _node('gw', primary=_group('g0', {'a': 'addr-a', 'b': 'addr-b'}))
    members = node.enumerate_local_members()
    assert _uuids(members) == ['a', 'b', 'gw']
    # sorted by uuid, deduped, self included
    assert members == sorted(members, key=lambda m: m['uuid'])


def test_local_members_gateway_includes_child_groups():
    node = _node(
        'gw',
        primary=_group('g0', {'a': 'addr-a'}),
        child_groups={'g1': _group('g1', {'c': 'addr-c', 'd': 'addr-d'})},
    )
    assert _uuids(node.enumerate_local_members()) == ['a', 'c', 'd', 'gw']


def test_local_members_dedup_and_name_enrichment():
    # 'a' is in both the primary and a child group, and known in peers.
    node = _node(
        'gw',
        primary=_group('g0', {'a': 'addr-a'}),
        child_groups={'g1': _group('g1', {'a': 'addr-a', 'e': 'addr-e'})},
        names={'a': 'alice'},
    )
    members = node.enumerate_local_members()
    assert _uuids(members) == ['a', 'e', 'gw']
    a = next(m for m in members if m['uuid'] == 'a')
    assert a['nickname'] == 'alice' and a['address'] == 'addr-a'


# --- handle_roster_request --------------------------------------------------

def test_handle_roster_request_replies_local_members_and_child_gateways():
    gw_ident = _new_identity('gw', '10.0.0.1')
    node = _node(
        None,
        primary=_group('g0', {'a': 'addr-a'}),
        child_groups={'g1': _group('g1', {'c': 'addr-c'})},
        child_gateways={'g1': 'child-gw'},
        identity=gw_ident,
    )
    q = queue.Queue()
    queues = {CfgIds.network: q}
    requestor = _new_identity('requestor', '10.0.0.9')
    msg = Message(CfgIds.identity, IdentityProtocol.roster_req,
                  to_json_string({'requestor': str(requestor.uuid)}),
                  to_whom=None, from_whom=requestor, encrypt=False)
    assert node.handle_roster_request(queues, msg) is True

    reply = q.get_nowait()
    assert reply.function == IdentityProtocol.roster_resp
    payload = from_json_string(reply.obj)
    # local members = self (gw) + primary 'a' + child 'c'
    assert _uuids(payload['members']) == sorted(['a', 'c', str(gw_ident.uuid)])
    assert payload['child_gateways'] == ['child-gw']
    # reply is addressed back to the requestor (Message wraps a lone
    # Identity in a list)
    assert reply.to_whom == [requestor]


def test_handle_roster_request_replies_to_the_requestors_named_process():
    """The reply must reach the process that will actually consume it.

    Inbound messages are routed by Message.process alone, and the breadth-first
    aggregation lives in the requestor's MAIN loop — its identity process
    registers no roster_resp handler. Answering to our own process name
    stranded every reply there, so the walk never completed on a real
    multiprocess node while still passing single-process tests.
    """
    node = _node('gw', primary=_group('g0', {'a': 'addr-a'}))
    q = queue.Queue()
    requestor = _new_identity('requestor', '10.0.0.9')
    msg = Message(CfgIds.identity, IdentityProtocol.roster_req,
                  to_json_string({'requestor': str(requestor.uuid),
                                  'requesting_process': CfgIds.main}),
                  to_whom=None, from_whom=requestor, encrypt=False)
    assert node.handle_roster_request({CfgIds.network: q}, msg) is True
    assert q.get_nowait().process == CfgIds.main


def test_handle_roster_request_honors_a_non_main_requesting_process():
    # An inspector bridge (or any non-main requestor) gets its answer where it
    # asked for it — the same freedom rep_req's requesting_process gives.
    node = _node('gw', primary=_group('g0', {'a': 'addr-a'}))
    q = queue.Queue()
    requestor = _new_identity('requestor', '10.0.0.9')
    msg = Message(CfgIds.identity, IdentityProtocol.roster_req,
                  to_json_string({'requestor': str(requestor.uuid),
                                  'requesting_process': 'inspector'}),
                  to_whom=None, from_whom=requestor, encrypt=False)
    assert node.handle_roster_request({CfgIds.network: q}, msg) is True
    assert q.get_nowait().process == 'inspector'


def test_handle_roster_request_defaults_to_main_for_an_older_requestor():
    # A requestor that predates requesting_process still gets a usable answer:
    # main is where the aggregation lives, so the default is the right home
    # rather than a guess.
    node = _node('gw', primary=_group('g0', {'a': 'addr-a'}))
    q = queue.Queue()
    requestor = _new_identity('requestor', '10.0.0.9')
    msg = Message(CfgIds.identity, IdentityProtocol.roster_req,
                  to_json_string({'requestor': str(requestor.uuid)}),
                  to_whom=None, from_whom=requestor, encrypt=False)
    assert node.handle_roster_request({CfgIds.network: q}, msg) is True
    assert q.get_nowait().process == CfgIds.main


def test_send_roster_req_names_the_main_loop_as_the_return_process():
    """The requestor half of the contract: _send_roster_req must SAY where the
    answer goes, or the responder can only guess."""
    from autonomous_trust.core.automate import AutonomousTrust

    class _Req:
        proc_name = CfgIds.main
        _send_roster_req = AutonomousTrust._send_roster_req

        def __init__(self):
            self.identity = _new_identity('me', '10.0.0.1')
            self.logger = logging.getLogger('test.roster.req')
            self._roster_pending = set()
            self.subtree_roster_complete = True

    q = queue.Queue()
    gateway = _new_identity('gw', '10.0.0.2')
    assert _Req()._send_roster_req({CfgIds.network: q}, gateway) is True
    sent = q.get_nowait()
    assert sent.function == IdentityProtocol.roster_req
    assert from_json_string(sent.obj)['requesting_process'] == CfgIds.main


def test_handle_roster_request_ignores_other_functions():
    node = _node('gw', primary=_group('g0', {}))
    msg = Message(CfgIds.identity, IdentityProtocol.id_query, '{}')
    assert node.handle_roster_request({}, msg) is False


# --- rank-based child-gateway discovery -------------------------------------
# The recursion target for each gatewayed child group is DISCOVERED as the
# highest-rank member (excluding self), ties broken by the lexicographically
# greater uuid — an explicit child_gateways[cg] entry overrides discovery.
# Mirrors the C twin (test/subtree_roster_test.c). See gateway-reputation-tree.md.

_U_LOW = '11111111-1111-1111-1111-111111111111'
_U_HIGH = '99999999-9999-9999-9999-999999999999'


class _RankPeers:
    """Peers that carry rank (as C peers do not — the parity of the two rank
    seams is what these tests pin). ranks: uuid_str -> effective_rank."""
    def __init__(self, ranks):
        self._ranks = ranks

    def find_by_uuid(self, uuid):
        u = str(uuid)
        if u not in self._ranks:
            return None
        return SimpleNamespace(nickname=None, effective_rank=self._ranks[u])


def _disc_node(self_uuid, child_members, ranks, gateway=None):
    cg = 'cg1'
    node = _node(
        self_uuid,
        primary=_group('g0', {self_uuid: 'addr-self'}),
        child_groups={cg: _group(cg, {u: 'addr-%s' % u for u in child_members})},
        child_gateways={cg: gateway} if gateway else None,
    )
    node.peers = _RankPeers(ranks)
    return node


def test_discover_gateway_prefers_higher_rank():
    # U_LOW has the lower uuid but the higher rank -> rank dominates.
    node = _disc_node('top', [_U_LOW, _U_HIGH], {_U_LOW: 5, _U_HIGH: 1})
    assert node._child_gateway_uuids() == [_U_LOW]


def test_discover_gateway_uuid_tiebreak():
    # No ranks (both 0) -> the lexicographically greater uuid wins.
    node = _disc_node('top', [_U_LOW, _U_HIGH], {})
    assert node._child_gateway_uuids() == [_U_HIGH]


def test_explicit_gateway_overrides_discovery():
    node = _disc_node('top', [_U_LOW, _U_HIGH], {_U_HIGH: 99}, gateway='pinned-gw')
    assert node._child_gateway_uuids() == ['pinned-gw']


def test_discover_gateway_excludes_self():
    # Self sits in the child group with the highest rank, yet must never be
    # its own recursion target.
    node = _disc_node('top', ['top', _U_HIGH], {'top': 100, _U_HIGH: 1})
    assert node._child_gateway_uuids() == [_U_HIGH]


# --- aggregate_subtree_roster (requestor-side BFS) --------------------------

def _tree_fetch(tree):
    """tree: gateway_uuid -> (member_uuids, child_gateway_uuids[, private])."""
    def fetch(gw):
        entry = tree[gw]
        members, children = entry[0], entry[1]
        private = entry[2] if len(entry) > 2 else False
        return {'members': [{'uuid': u, 'nickname': None, 'address': None} for u in members],
                'child_gateways': list(children), 'private': private}
    return fetch


def test_aggregate_flattens_three_level_tree():
    tree = {
        'top': (['top', 'a'], ['mid']),
        'mid': (['mid', 'b'], ['leaf']),
        'leaf': (['leaf', 'c'], []),
    }
    members, complete, private = aggregate_subtree_roster('top', _tree_fetch(tree))
    assert complete is True
    assert private == []
    assert _uuids(members) == ['a', 'b', 'c', 'leaf', 'mid', 'top']


def test_aggregate_dedups_across_branches():
    tree = {
        'top': (['top', 'shared'], ['l', 'r']),
        'l': (['l', 'shared', 'x'], []),
        'r': (['r', 'shared', 'y'], []),
    }
    members, complete, private = aggregate_subtree_roster('top', _tree_fetch(tree))
    assert complete is True
    assert _uuids(members) == ['l', 'r', 'shared', 'top', 'x', 'y']
    assert sum(1 for m in members if m['uuid'] == 'shared') == 1


def test_aggregate_partial_when_a_child_is_unreachable():
    tree = {'top': (['top'], ['down'])}  # 'down' has no entry

    def fetch(gw):
        if gw not in tree:
            raise RuntimeError('unreachable')
        members, children = tree[gw]
        return {'members': [{'uuid': u} for u in members], 'child_gateways': list(children)}

    members, complete, private = aggregate_subtree_roster('top', fetch)
    assert complete is False           # a fetch failed
    assert private == []               # ...unreachability is NOT privacy
    assert _uuids(members) == ['top']  # but the reachable part is returned


def test_aggregate_terminates_on_cycle():
    tree = {
        'a': (['a'], ['b']),
        'b': (['b'], ['a']),  # cycle back to a
    }
    members, complete, private = aggregate_subtree_roster('a', _tree_fetch(tree))
    assert complete is True            # visited-guard, not a failure
    assert _uuids(members) == ['a', 'b']


def test_aggregate_node_cap_marks_incomplete():
    # A long chain exceeding the cap returns partial + incomplete.
    tree = {str(i): ([str(i)], [str(i + 1)]) for i in range(10)}
    tree['9'] = (['9'], [])
    members, complete, private = aggregate_subtree_roster('0', _tree_fetch(tree), max_nodes=4)
    assert complete is False
    assert len(members) <= 4


# --- opt-out / private boundaries -------------------------------------------

def test_aggregate_private_gateway_is_an_opaque_boundary():
    # 'mid' opted out: its own members AND everything below it are hidden,
    # but the enumeration is still COMPLETE (privacy is intentional, not a
    # failure) and 'mid' is named as the boundary.
    tree = {
        'top': (['top', 'a'], ['mid']),
        'mid': (['mid', 'secret'], ['leaf'], True),  # private
        'leaf': (['leaf', 'c'], []),
    }
    members, complete, private = aggregate_subtree_roster('top', _tree_fetch(tree))
    assert complete is True             # privacy != incompleteness
    assert private == ['mid']
    # nothing at or below 'mid' leaks; 'leaf' is never even queried
    assert _uuids(members) == ['a', 'top']


def test_aggregate_private_top_yields_empty_but_complete_roster():
    # A fully private network: the TOP gateway opts out, so the whole tree
    # is unmappable — an empty roster that is nonetheless complete.
    tree = {'top': (['top', 'a'], ['mid'], True)}
    members, complete, private = aggregate_subtree_roster('top', _tree_fetch(tree))
    assert complete is True
    assert members == []
    assert private == ['top']


def test_handle_roster_request_private_node_discloses_nothing():
    gw_ident = _new_identity('gw', '10.0.0.1')
    node = _node(
        None,
        primary=_group('g0', {'a': 'addr-a'}),
        child_groups={'g1': _group('g1', {'c': 'addr-c'})},
        child_gateways={'g1': 'child-gw'},
        identity=gw_ident,
    )
    node.roster_private = True  # opt out (AT_ROSTER_PRIVATE)
    q = queue.Queue()
    queues = {CfgIds.network: q}
    requestor = _new_identity('requestor', '10.0.0.9')
    msg = Message(CfgIds.identity, IdentityProtocol.roster_req,
                  to_json_string({'requestor': str(requestor.uuid)}),
                  to_whom=None, from_whom=requestor, encrypt=False)
    assert node.handle_roster_request(queues, msg) is True

    reply = q.get_nowait()
    payload = from_json_string(reply.obj)
    assert payload['private'] is True
    assert payload['members'] == []          # members withheld
    assert payload['child_gateways'] == []   # subtree withheld


# --- integration: a seeded >=3-level cohort, real handlers + aggregator ------
#
# Wires several real IdentityProcess instances into a 3-level gateway tree and
# drives the enumeration end-to-end through the actual handle_roster_request
# (building real Message/roster_resp objects) feeding aggregate_subtree_roster.
# This is the in-process integration of all three pieces across a real tree —
# no subprocesses, deterministic — including the private-subtree case.

def _wire_fetch(nodes_by_uuid, requestor):
    """A per-gateway fetch that delivers a real roster_req to the target
    node's handler and returns its parsed roster_resp — the synchronous
    stand-in for the network round-trip the live requestor performs."""
    def fetch(gw_uuid):
        node = nodes_by_uuid[str(gw_uuid)]
        q = queue.Queue()
        msg = Message(CfgIds.identity, IdentityProtocol.roster_req,
                      to_json_string({'requestor': str(requestor.uuid)}),
                      to_whom=None, from_whom=requestor, encrypt=False)
        assert node.handle_roster_request({CfgIds.network: q}, msg) is True
        return from_json_string(q.get_nowait().obj)
    return fetch


def _build_cohort_tree():
    """top -> mid -> leaf, with two extra members at the leaf.

    Returns (nodes_by_uuid, uuids-dict, requestor). Each gateway lists the
    next level's gateway as a member of its child group AND as a child
    gateway to recurse into."""
    top_id = _new_identity('top', '10.1.0.1')
    mid_id = _new_identity('mid', '10.1.0.2')
    leaf_id = _new_identity('leaf', '10.1.0.3')
    m1_id = _new_identity('m1', '10.1.0.4')
    m2_id = _new_identity('m2', '10.1.0.5')
    T, M, L = str(top_id.uuid), str(mid_id.uuid), str(leaf_id.uuid)
    M1, M2 = str(m1_id.uuid), str(m2_id.uuid)

    top = _node(None, identity=top_id,
                primary=_group('gt', {T: 'a-top'}),
                child_groups={'c1': _group('c1', {M: 'a-mid'})},
                child_gateways={'c1': M})
    mid = _node(None, identity=mid_id,
                primary=_group('gm', {M: 'a-mid'}),
                child_groups={'c2': _group('c2', {L: 'a-leaf'})},
                child_gateways={'c2': L})
    leaf = _node(None, identity=leaf_id,
                 primary=_group('gl', {L: 'a-leaf', M1: 'a-m1', M2: 'a-m2'}))
    nodes = {T: top, M: mid, L: leaf}
    requestor = _new_identity('enumerator', '10.1.0.9')
    return nodes, dict(T=T, M=M, L=L, M1=M1, M2=M2), requestor


def test_integration_three_level_cohort_full_roster():
    nodes, u, requestor = _build_cohort_tree()
    members, complete, private = aggregate_subtree_roster(
        u['T'], _wire_fetch(nodes, requestor))
    assert complete is True
    assert private == []
    # every member across all three levels is surfaced
    assert _uuids(members) == sorted([u['T'], u['M'], u['L'], u['M1'], u['M2']])


def test_integration_private_mid_hides_its_subtree():
    nodes, u, requestor = _build_cohort_tree()
    nodes[u['M']].roster_private = True  # the mid gateway opts out
    members, complete, private = aggregate_subtree_roster(
        u['T'], _wire_fetch(nodes, requestor))
    assert complete is True              # privacy is not incompleteness
    assert private == [u['M']]
    # 'mid' is still visible (top discloses its OWN members), but everything
    # BEHIND mid (leaf, m1, m2) is hidden
    assert _uuids(members) == sorted([u['T'], u['M']])
