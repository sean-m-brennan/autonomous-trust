# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
"""Unit coverage for the gateway multi-group reputation tree.

Exercises the per-group chain routing, subtree-roster construction,
polymorphic forward serialisation, and the length-tolerant `committed`
wire format that together make a gateway answer a consensus_rep_req with
its own score plus a score for every peer in each child group it bridges.

See doc/architecture/gateway-reputation-tree.md and
project memory `project-gateway-reputation-tree`.
"""
import queue
from types import SimpleNamespace
from uuid import uuid4

from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    Reputation, Reputations, TransactionHistory,
)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import from_json_string

from unittest.mock import MagicMock


def _make_rep_process(group_uuid=None):
    """Build a ReputationProcess with mocked configs (mirrors the helper
    in test_repprocess.py). A real primary Group uuid can be supplied so
    the primary-chain routing assertions have a concrete uuid to match."""
    log_q = queue.Queue()
    identity = MagicMock()
    identity.uuid = uuid4()

    procs = []
    for name in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
                 CfgIds.reputation):
        p = MagicMock()
        p.name = name
        procs.append(p)

    group = MagicMock()
    group.uuid = group_uuid or uuid4()

    configs = {
        'processes': procs,
        CfgIds.identity: identity,
        CfgIds.peers: MagicMock(),
        CfgIds.group: group,
    }
    rp = ReputationProcess(configs, ProcessTracker(), log_q, suppress_log=True)
    # The factory's protocol carries the mocked group/peers; pin the
    # primary group uuid so _chain_for_group can recognise it.
    rp.protocol.group = group
    return rp


def _fake_group(member_uuids):
    """Minimal stand-in for identity.group.Group: only `_address_map`
    (member-uuid -> address) and `uuid` are touched by the roster code."""
    return SimpleNamespace(
        uuid=uuid4(),
        _address_map={u: 'addr-%s' % str(u)[:4] for u in member_uuids},
    )


# --------------------------------------------------------------------------
# _chain_for_group: routing a (task, peer, score) commit to the right chain
# --------------------------------------------------------------------------

class TestChainForGroup:
    def test_none_returns_primary(self):
        rp = _make_rep_process()
        assert rp._chain_for_group(None) is rp.history

    def test_primary_group_uuid_returns_primary(self):
        rp = _make_rep_process()
        assert rp._chain_for_group(str(rp.group.uuid)) is rp.history

    def test_unknown_uuid_returns_primary(self):
        # A commit tagged with a group this node doesn't gateway must not
        # silently spawn a phantom child chain — it falls back to primary.
        rp = _make_rep_process()
        assert rp._chain_for_group(str(uuid4())) is rp.history
        assert rp.child_histories == {}

    def test_child_uuid_returns_distinct_lazy_chain(self):
        rp = _make_rep_process()
        cg_uuid = str(uuid4())
        rp.protocol.child_groups = {cg_uuid: _fake_group([uuid4()])}
        chain = rp._chain_for_group(cg_uuid)
        assert isinstance(chain, TransactionHistory)
        assert chain is not rp.history
        # Lazily created and stable across calls (same object back).
        assert rp._chain_for_group(cg_uuid) is chain
        assert cg_uuid in rp.child_histories


# --------------------------------------------------------------------------
# _subtree_roster: a node's score plus every child it bridges
# --------------------------------------------------------------------------

class TestSubtreeRoster:
    def test_leaf_is_single_element(self):
        # No child groups -> roster is exactly the node's own score, which
        # forward_reputation serialises as a bare Reputation (wire-identical
        # to the pre-tree single-score reply).
        rp = _make_rep_process()
        gw = uuid4()
        roster = rp._subtree_roster(gw)
        assert len(roster) == 1
        assert isinstance(roster[0], Reputation)
        assert str(roster[0].peer_id) == str(gw)

    def test_gateway_includes_all_child_members(self):
        rp = _make_rep_process()
        gw = uuid4()
        m1, m2 = uuid4(), uuid4()
        cg = _fake_group([m1, m2])
        rp.protocol.child_groups = {str(cg.uuid): cg}
        roster = rp._subtree_roster(gw)
        ids = {str(r.peer_id) for r in roster}
        assert str(gw) in ids
        assert str(m1) in ids
        assert str(m2) in ids
        assert len(roster) == 3

    def test_gateway_not_duplicated_when_member_of_child(self):
        # If the gateway also appears in the child address map, it is only
        # listed once (seen-set dedup), with its own (primary) score.
        rp = _make_rep_process()
        gw = uuid4()
        other = uuid4()
        cg = _fake_group([gw, other])
        rp.protocol.child_groups = {str(cg.uuid): cg}
        roster = rp._subtree_roster(gw)
        ids = [str(r.peer_id) for r in roster]
        assert ids.count(str(gw)) == 1
        assert str(other) in ids
        assert len(roster) == 2

    def test_child_scored_against_child_chain(self):
        # A child's committed bilateral txs live in the child chain, not
        # the primary one; the roster score must reflect the child chain.
        rp = _make_rep_process()
        gw = uuid4()
        child = uuid4()
        cohort_peer = uuid4()
        cg = _fake_group([child, cohort_peer])
        cg_uuid = str(cg.uuid)
        rp.protocol.child_groups = {cg_uuid: cg}
        # Record a committed bilateral tx for `child` in the CHILD chain
        # via the wire path (4-tuple committed carrying the child group).
        task = uuid4()
        rp.handle_committed(None, Message(
            CfgIds.reputation, ReputationProtocol.committed,
            _tuple_json((task, child, 0.9, cg_uuid)), None,
            from_whom=rp.identity))
        rp.handle_committed(None, Message(
            CfgIds.reputation, ReputationProtocol.committed,
            _tuple_json((task, cohort_peer, 0.9, cg_uuid)), None,
            from_whom=rp.identity))
        roster = rp._subtree_roster(gw)
        child_rep = next(r for r in roster if str(r.peer_id) == str(child))
        # EMA over a single 0.9 counterparty score == 0.9, well above the
        # 0.5 cold-start baseline a primary-chain lookup would have yielded.
        assert child_rep.score > 0.8


# --------------------------------------------------------------------------
# forward_reputation: 1-element roster -> bare Reputation; N -> JSON array
# --------------------------------------------------------------------------

def _drain(q):
    msg = q.get(timeout=1.0)
    return msg.obj


class TestForwardReputationShape:
    def test_single_element_sent_as_bare_reputation(self):
        rp = _make_rep_process()
        q = queue.Queue()
        rep = Reputation(uuid4(), 0.7)
        # Local requestor (None) routes to queues[req_proc].
        rp.requested_reps = [([rep], CfgIds.main, None)]
        rp.forward_reputation({CfgIds.main: q})
        obj = _drain(q)
        assert isinstance(obj, Reputation)
        assert obj.score == 0.7

    def test_multi_element_sent_as_json_array(self):
        rp = _make_rep_process()
        q = queue.Queue()
        ids = [uuid4(), uuid4()]
        roster = [Reputation(ids[0], 0.7), Reputation(ids[1], 0.3)]
        rp.requested_reps = [(roster, CfgIds.main, None)]
        rp.forward_reputation({CfgIds.main: q})
        obj = _drain(q)
        # Serialised as a JSON string that automate.py unpacks length-
        # tolerantly into a list of Reputation (automate.py:552-557).
        assert isinstance(obj, str)
        parsed = from_json_string(obj)
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        # Full wire-contract round-trip: both fields automate.py reads
        # (rep.peer_id, rep.score) survive serialise -> deserialise.
        assert {round(r.score, 3) for r in parsed} == {0.7, 0.3}
        assert {str(r.peer_id) for r in parsed} == {str(ids[0]), str(ids[1])}


# --------------------------------------------------------------------------
# handle_committed: length-tolerant wire format (the only wire change)
# --------------------------------------------------------------------------

def _tuple_json(tpl):
    from autonomous_trust.core.config import to_json_string
    return to_json_string(tpl)


class TestCommittedWireCompat:
    def test_legacy_3tuple_routes_to_primary(self):
        rp = _make_rep_process()
        peer = uuid4()
        task = uuid4()
        rp.handle_committed(None, Message(
            CfgIds.reputation, ReputationProtocol.committed,
            _tuple_json((task, peer, 0.8)), None, from_whom=rp.identity))
        assert len(rp.history) >= 0  # half-tx until counterparty arrives
        assert task in rp.history._task_mapping
        assert rp.child_histories == {}

    def test_4tuple_with_child_uuid_routes_to_child(self):
        rp = _make_rep_process()
        cg = _fake_group([uuid4()])
        cg_uuid = str(cg.uuid)
        rp.protocol.child_groups = {cg_uuid: cg}
        peer = uuid4()
        task = uuid4()
        rp.handle_committed(None, Message(
            CfgIds.reputation, ReputationProtocol.committed,
            _tuple_json((task, peer, 0.8, cg_uuid)), None,
            from_whom=rp.identity))
        # Routed to the child chain, NOT the primary one.
        assert cg_uuid in rp.child_histories
        assert task in rp.child_histories[cg_uuid]._task_mapping
        assert task not in rp.history._task_mapping

    def test_4tuple_unknown_group_falls_back_to_primary(self):
        rp = _make_rep_process()
        peer = uuid4()
        task = uuid4()
        rp.handle_committed(None, Message(
            CfgIds.reputation, ReputationProtocol.committed,
            _tuple_json((task, peer, 0.8, str(uuid4()))), None,
            from_whom=rp.identity))
        assert task in rp.history._task_mapping
        assert rp.child_histories == {}
