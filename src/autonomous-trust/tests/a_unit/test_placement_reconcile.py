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
"""Catch-up, reconcile and warm start under ordered placement
(doc/architecture/reputation.md, "Agreeing on an order").

A placed chain carries its placement certificates (on each placement's last
entry, with the index the placement began at), so a node catching up can check
every placement it is handed. Then a placement decides, not a length: nothing
below our own placed end is rewritten, a certified segment past it wins
whatever the lengths, two certified values at one index are equivocation, and
a certified placement may carry a node across a gap.
"""
import copy
import json
from types import SimpleNamespace
from uuid import UUID

from autonomous_trust.core.config import from_json_string, to_json_string
from autonomous_trust.core.reputation.reputation import (
    ReconcileResult, TransactionHistory, evidence_from_dict, evidence_to_dict,
    placement_entry)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.system import CfgIds

from tests.a_unit.test_commit_certificates import _ident, _node, _roster
from tests.a_unit.test_placement_sim import Sim

A = UUID('aaaaaaaa-0000-4000-8000-000000000001')
B = UUID('bbbbbbbb-0000-4000-8000-000000000002')
SIGS = {'voter': 'sig'}


def _task(n):
    return UUID('00000000-0000-4000-8000-%012d' % n)


def _items(*ns):
    hist = TransactionHistory()
    for n in ns:
        hist.record_half(_task(n), A, 600)
        hist.record_half(_task(n), B, 800)
    return hist.ready_items()


def _placed(*batches):
    """A history built only from placements, each a tuple of task numbers."""
    hist = TransactionHistory()
    for batch in batches:
        hist.apply_placed(hist.next_index, _items(*batch), SIGS)
    return hist


def _legacy(*ns):
    hist = TransactionHistory()
    for n in ns:
        hist.update(_task(n), A, 600)
        hist.update(_task(n), B, 800)
    return hist


def _seg(hist):
    return copy.deepcopy(list(hist))


def _all(seg):
    return {t.index for t in seg}


def _tasks(hist):
    return [t.task_id for t in hist]


class TestCertificateOnTheChain:
    def test_the_last_entry_of_a_placement_carries_it(self):
        hist = _placed((1, 2), (3,))
        last_of_first = hist._chain[1]
        assert last_of_first.place_from == 0 and last_of_first.place_sigs == SIGS
        assert hist._chain[0].place_sigs is None
        assert hist._chain[2].place_from == 2
        assert hist.placed_end == 3

    def test_it_is_outside_the_entry_hash(self):
        hist = _placed((1,))
        tx = hist._chain[0]
        bare = copy.copy(tx)
        bare.place_from, bare.place_sigs = None, None
        assert tx.entry_hash() == bare.entry_hash()

    def test_it_travels_the_catch_up_wire(self):
        hist = _placed((1, 2))
        back = from_json_string(to_json_string(list(hist)))
        assert back[1].place_from == 0 and back[1].place_sigs == SIGS
        assert 'place_sigs' not in back[0].to_dict()

    def test_it_survives_a_restart(self):
        hist = _placed((1, 2), (3,))
        doc = json.loads(json.dumps(evidence_to_dict(hist)))
        assert doc['chain'][1]['place_from'] == 0
        chain, _ = evidence_from_dict(doc)
        restored = TransactionHistory(_chain=chain)
        assert restored.placed_end == 3
        assert restored._chain[2].place_sigs == SIGS

    def test_a_placement_entry_sheds_it(self):
        hist = _placed((1,))
        assert placement_entry(hist._chain[0]).place_sigs is None


class TestPlacementBatches:
    def test_a_segment_names_its_placements(self):
        hist = _placed((1, 2), (3,))
        batches = TransactionHistory().placement_batches(_seg(hist))
        assert [(k, len(e)) for k, e, _s in batches] == [(0, 2), (2, 1)]

    def test_a_placement_begun_before_the_segment_borrows_ours(self):
        theirs = _placed((1, 2, 3))
        ours = _placed((1, 2, 3))
        tail = _seg(theirs)[2:]
        (k, entries, _s), = ours.placement_batches(tail)
        assert k == 0 and [e.index for e in entries] == [0, 1, 2]
        (_k, missing, _s), = TransactionHistory().placement_batches(tail)
        assert missing is None


class TestReconcileUnderPlacement:
    def test_a_certified_extension_is_taken(self):
        ours = _placed((1,))
        theirs = _placed((1,), (2, 3))
        res = ours.reconcile(_seg(theirs), certified=_all(theirs))
        assert res.status == ReconcileResult.EXTENDED
        assert _tasks(ours) == _tasks(theirs)
        assert ours.placed_end == 3 and ours.head_hash == theirs.head_hash

    def test_a_certified_segment_beats_a_longer_uncertified_one(self):
        ours = _legacy(7, 8, 9)
        theirs = _placed((1,))
        res = ours.reconcile(_seg(theirs), certified=_all(theirs))
        assert res.status == ReconcileResult.ADOPTED
        assert _tasks(ours) == [_task(1)]
        assert [t.task_id for t in res.dropped] == [_task(7), _task(8), _task(9)]

    def test_without_placement_the_longer_chain_still_wins(self):
        ours = _legacy(7, 8, 9)
        res = ours.reconcile(_seg(_placed((1,))))
        assert res.status == ReconcileResult.KEPT

    def test_nothing_below_our_placed_end_is_rewritten(self):
        ours = _placed((1, 2))
        theirs = _legacy(5, 6, 7, 8)
        res = ours.reconcile(_seg(theirs), certified=set())
        assert res.status == ReconcileResult.KEPT
        assert _tasks(ours) == [_task(1), _task(2)]

    def test_two_certified_values_at_one_index_are_equivocation(self):
        ours = _placed((1, 2))
        theirs = _placed((3, 4), (5,))
        res = ours.reconcile(_seg(theirs), certified=_all(theirs))
        assert res.status == ReconcileResult.EQUIVOCATION
        assert res.fork == 0
        assert _tasks(ours) == [_task(1), _task(2)]

    def test_an_uncertified_tail_is_cut_off(self):
        ours = _placed((1,))
        theirs = _placed((1,), (2,))
        theirs.update(_task(9), A, 600)
        theirs.update(_task(9), B, 800)        # written outside any placement
        res = ours.reconcile(_seg(theirs), certified={0, 1})
        assert res.status == ReconcileResult.EXTENDED
        assert _tasks(ours) == [_task(1), _task(2)]

    def test_an_uncertified_segment_cannot_pass_our_placed_end(self):
        ours = _placed((1,))
        theirs = copy.deepcopy(ours)
        theirs.update(_task(9), A, 600)
        theirs.update(_task(9), B, 800)
        res = ours.reconcile(_seg(theirs), certified=set())
        assert res.status == ReconcileResult.NONE
        assert len(ours) == 1

    def test_a_certified_placement_carries_us_across_a_gap(self):
        theirs = _placed((1,), (2,), (3, 4))
        ours = _placed((1,))
        far = _seg(theirs)[2:]                 # indices 2..3: the (3, 4) placement
        res = ours.reconcile(far, certified={2, 3})
        assert res.status == ReconcileResult.ADOPTED
        assert _tasks(ours) == [_task(3), _task(4)]
        assert ours.next_index == 4 and ours.head_hash == theirs.head_hash
        # What we held below the gap cannot come back.
        assert ours.record_half(_task(1), A, 600) == 'tombstoned'

    def test_a_gap_without_a_certified_start_is_rejected(self):
        theirs = _placed((1,), (2,), (3, 4))
        ours = _legacy(1)
        # Index 3 closes a placement begun at 2, which the segment lacks.
        res = ours.reconcile(_seg(theirs)[3:], certified=set())
        assert res.status == ReconcileResult.REJECTED

    def test_what_is_taken_leaves_the_pool(self):
        ours = TransactionHistory()
        ours.record_half(_task(1), A, 600)
        ours.record_half(_task(1), B, 800)
        theirs = _placed((1,))
        ours.reconcile(_seg(theirs), certified=_all(theirs))
        assert ours.pooled(_task(1)) is None


# --- the process --------------------------------------------------------------

def _process(n=4):
    idents = [_ident('r%d' % i, i + 1) for i in range(n)]
    rp, q = _node(idents[0], _roster(idents[0], idents))
    peers = rp.protocol.peers.all
    rp.protocol.peers.find_top_n = lambda k, peers=peers: list(peers)[:k]
    from tests.a_unit.test_placement_acceptor import _roster_of
    rp.history.roster_anchor = _roster_of(idents)   # the group's roster in force
    return rp, q, idents


def _signed(hist, idents):
    """A copy of `hist` whose placement certificates are real signatures."""
    from autonomous_trust.core.reputation.reputation import (
        place_designation, place_value_digest)
    out = copy.deepcopy(hist)
    for k, entries, _sigs in hist.placement_batches(list(hist)):
        desig = place_designation(k, entries[0].prev_hash or b'',
                                  place_value_digest(entries, k))
        last = out._chain[entries[-1].index - out._first_index]
        last.place_sigs = {str(s.uuid): ReputationProcess._detached_sig(s, desig)
                           for s in idents}
    return out


def _who(ident):
    return SimpleNamespace(nickname='peer', uuid=ident.uuid)


class TestProcessCatchUp:
    def test_verified_placements_are_certified(self):
        rp, _q, idents = _process()
        theirs = _signed(_placed((1, 2), (3,)), idents)
        assert rp._placement_certified_indices(
            rp.history, list(theirs), None) == {0, 1, 2}

    def test_a_sub_quorum_certificate_certifies_nothing_and_refuses_all(self):
        rp, _q, idents = _process()
        theirs = _signed(_placed((1,)), idents[:2])   # two of four
        assert rp._placement_certified_indices(
            rp.history, list(theirs), None) is None

    def test_a_forged_segment_is_refused_whole(self):
        rp, q, idents = _process()
        theirs = _placed((1,))                         # SIGS: not signatures
        res = rp._reconcile_into(q, '', _seg(theirs), 'peer')
        assert res is None and len(rp.history) == 0

    def test_dropped_entries_go_back_to_the_pool(self):
        rp, q, idents = _process()
        rp.history.update(_task(7), A, 600, certificate={'x': 'y'})
        rp.history.update(_task(7), B, 800, certificate={'x': 'y'})
        theirs = _signed(_placed((1,)), idents)
        res = rp._reconcile_into(q, '', _seg(theirs), 'peer')
        assert res.status == ReconcileResult.ADOPTED
        assert _tasks(rp.history) == [_task(1)]
        back = rp.history.pooled(_task(7))
        assert back is not None and len(back) == 2

    def test_a_child_chain_is_asked_for_by_group(self):
        rp, q, idents = _process()
        rp._request_update(q, n=2, key='')
        bare = q[CfgIds.network].get_nowait()
        assert bare.obj == '0'                 # the primary chain: a bare length
        child = str(idents[2].uuid)
        rp.protocol.child_groups = {child: SimpleNamespace(
            uuid=child, addresses=[idents[2].address])}
        while not q[CfgIds.network].empty():
            q[CfgIds.network].get_nowait()
        rp._request_update(q, n=2, key=child)
        asked = q[CfgIds.network].get_nowait()
        assert json.loads(asked.obj) == {'from': 0, 'group': child}
        to = asked.to_whom[0] if isinstance(asked.to_whom, list) else asked.to_whom
        assert str(to.uuid) == str(idents[2].uuid)

    def test_an_outdated_for_a_chain_we_do_not_keep_is_ignored(self):
        rp, q, idents = _process()
        msg = SimpleNamespace(function=ReputationProtocol.outdated,
                              from_whom=idents[1],
                              obj=json.dumps({'from': 0, 'group': 'nobody'}))
        assert rp.handle_outdated(q, msg) is True
        assert q[CfgIds.network].empty()

    def test_our_unpaired_pool_halves_are_handed_to_a_newcomer(self):
        rp, q, idents = _process()
        me = rp.identity.uuid
        rp.history.record_half(_task(5), me, 700, certificate={'x': 'y'})
        first = idents[1]
        rp.handoff = {str(p.uuid): [0.0, 0] for p in rp.peers.all}
        sent = rp._hand_off_pending_halves(q, 100.0)
        assert sent >= 1
        frames = []
        while not q[CfgIds.network].empty():
            frames.append(q[CfgIds.network].get_nowait())
        assert any(str(_task(5)) in str(f.obj) for f in frames)
        assert first is not None


def test_a_minority_catches_up_after_the_heal(tmp_path, monkeypatch):
    sim = Sim(5, 5, tmp_path, monkeypatch)
    sim.island = {3, 4}
    tasks = [sim.complete(0, 1), sim.complete(1, 2), sim.complete(0, 2)]
    sim.run(30)
    assert sim.chains({3, 4}) == [[], []]
    majority = sim.chains({0, 1, 2})
    assert all(c == majority[0] for c in majority)
    assert sorted(map(str, majority[0])) == sorted(map(str, tasks))
    sim.island = None
    sim.run(30)
    chains = sim.chains()
    assert all(c == chains[0] for c in chains), chains
    assert len({rp.history.head_hash for rp, _q in sim.nodes}) == 1
    # The minority's own copies of those tasks left its pools.
    for i in (3, 4):
        rp = sim.nodes[i][0]
        assert not rp.history.ready_items()
