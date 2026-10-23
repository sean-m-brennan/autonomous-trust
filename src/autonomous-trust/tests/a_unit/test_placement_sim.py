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
"""Ordered placement end to end, in process (doc/architecture/reputation.md,
"Agreeing on an order").

Real ReputationProcess nodes with real keys exchange real messages through a
bus that shuffles and drops them, under a fake clock. Completed tasks reach
each node's pool in a different order, and every node may try to place them.
Whatever the interleaving, every node must end with the same chain, holding
each task exactly once. A minority island must place nothing, and the
majority must go on placing without it.
"""
import os
import queue
import random
from collections import Counter
from types import SimpleNamespace
from uuid import uuid4

import pytest

import autonomous_trust.core._python.reputation.placement as placement_mod
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.reputation.reputation import (commit_designation,
                                                         half_designation)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.system import CfgIds

from tests.a_unit.test_commit_certificates import _ident, _node, _roster


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t

    def time(self):
        return 1_800_000_000.0 + self.t


class Sim:
    def __init__(self, n, seed, tmp_path, monkeypatch, drop=0.0, joined=None):
        self.rng = random.Random(seed)
        self.clock = _Clock()
        monkeypatch.setattr(placement_mod, 'time', self.clock)
        monkeypatch.setattr(placement_mod, 'random', self.rng)
        os.makedirs(tmp_path / 'etc' / 'at', exist_ok=True)
        self.idents = [_ident('n%d' % i, i + 1) for i in range(n)]
        self.nodes = []
        for i, me in enumerate(self.idents):
            rp, q = _node(me, _roster(me, self.idents))
            peers = rp.protocol.peers.all
            rp.protocol.peers.find_top_n = lambda k, peers=peers: list(peers)[:k]
            where = tmp_path / ('n%d' % i)
            os.makedirs(where, exist_ok=True)
            rp._placement_path = lambda key, where=where: str(
                where / ('placement-%s.json' % (key or 'primary')))
            self.nodes.append((rp, q))
        self.drop = drop
        self.island = None          # set of node indexes cut off, or None
        self.sent = Counter()       # (sender index, function) -> messages sent
        # Members admitted so far: the others have no peers, nobody lists
        # them, and they neither run nor hear anything until join().
        self.joined = set(range(n)) if joined is None else set(joined)
        for i, (rp, _q) in enumerate(self.nodes):
            rp.protocol.peers.all[:] = [self.idents[j] for j in sorted(self.joined)
                                        if j != i] if i in self.joined else []
        # The group founds its chain while every member is connected: a
        # genesis roster, decided by every member it lists.
        self.settle(lambda: all(self.nodes[i][0].history.latest_roster() is not None
                                for i in self.joined))
        self.sent.clear()

    def settle(self, done, limit=1200):
        """Tick until `done()` holds; fail after `limit` ticks."""
        for _ in range(limit):
            self.tick()
            if done():
                return
        assert done()

    def join(self, i):
        """Admit node i: it and every member now list each other, as an
        identity admission would leave them."""
        self.joined.add(i)
        for j, (rp, _q) in enumerate(self.nodes):
            if j in self.joined:
                rp.protocol.peers.all[:] = [self.idents[m] for m in sorted(self.joined)
                                            if m != j]

    def roster_of(self, i):
        r = self.nodes[i][0].history.latest_roster()
        return None if r is None else sorted(u for u, _k in r.roster_members)

    def uuids(self, which):
        return sorted(str(self.idents[i].uuid).lower() for i in which)

    def _reachable(self, a, b):
        if a not in self.joined or b not in self.joined:
            return False
        if self.island is None:
            return True
        return (a in self.island) == (b in self.island)

    def deliver(self, rounds=200):
        """Move messages until the network is quiet, shuffled, some dropped."""
        for _ in range(rounds):
            batch = []
            for i, (_rp, q) in enumerate(self.nodes):
                net = q[CfgIds.network]
                while not net.empty():
                    batch.append((i, net.get_nowait()))
            if not batch:
                return
            self.rng.shuffle(batch)
            for src, msg in batch:
                self.sent[(src, msg.function)] += 1
                # A group target is a broadcast; an identity, one node.
                to = (msg.to_whom.uuid if isinstance(msg.to_whom, Identity)
                      else None)
                for j, (rp, q) in enumerate(self.nodes):
                    if j == src or not self._reachable(src, j):
                        continue
                    if to is not None and str(to) != str(rp.identity.uuid):
                        continue
                    if self.rng.random() < self.drop:
                        continue
                    msg.verified = True
                    rp.protocol.run_message_handlers(q, msg)

    def tick(self, seconds=0.1):
        self.clock.t += seconds
        order = sorted(self.joined)
        self.rng.shuffle(order)
        for i in order:
            rp, q = self.nodes[i]
            rp._maybe_place(q)
        self.deliver()

    def run(self, seconds):
        for _ in range(int(seconds / 0.1)):
            self.tick()

    def complete(self, a, b, at=None):
        """A task between members a and b, both halves certified by everyone
        else, reaching the pools of `at` (default every node) in a random
        order."""
        task = uuid4()
        ia, ib = self.idents[a], self.idents[b]
        others = [x for x in self.idents if x is not ia and x is not ib]
        halves = []
        for who, other, score in ((ia, ib, 0.9), (ib, ia, 0.6)):
            cert = {str(s.uuid): ReputationProcess._detached_sig(
                s, commit_designation(who.uuid, task, score)) for s in others}
            sig = ReputationProcess._detached_sig(
                who, half_designation(task, who.uuid, other.uuid, score))
            halves.append((who.uuid, other.uuid, score, cert, sig))
        for i in (at if at is not None else range(len(self.nodes))):
            rp, _q = self.nodes[i]
            for who, other, score, cert, sig in self.rng.sample(halves, 2):
                rp.history.record_half(task, who, score, certificate=cert,
                                       counterparty=other, half_sig=sig)
        return task

    def index_of(self, uuid_str):
        return next(i for i, (rp, _q) in enumerate(self.nodes)
                    if str(rp.identity.uuid).lower() == uuid_str)

    def asked(self, i=None):
        """How many `place request`s node i (default any) has sent."""
        return sum(n for (src, fn), n in self.sent.items()
                   if fn == ReputationProtocol.place_request
                   and (i is None or src == i))

    def chains(self, which=None):
        out = []
        for i, (rp, _q) in enumerate(self.nodes):
            if which is None or i in which:
                out.append([tx.task_id for tx in rp.history if not tx.is_roster])
        return out


@pytest.mark.parametrize('seed', range(6))
def test_every_node_holds_the_same_chain(tmp_path, monkeypatch, seed):
    sim = Sim(5, seed, tmp_path, monkeypatch, drop=0.05)
    tasks = []
    for _ in range(12):
        a, b = sim.rng.sample(range(5), 2)
        tasks.append(sim.complete(a, b))
        sim.run(sim.rng.choice((0.1, 0.5, 1.0)))
    sim.run(60)
    chains = sim.chains()
    assert all(c == chains[0] for c in chains), chains
    assert sorted(map(str, chains[0])) == sorted(map(str, tasks))
    heads = {rp.history.head_hash for rp, _q in sim.nodes}
    assert len(heads) == 1


def test_a_burst_is_placed_in_few_instances(tmp_path, monkeypatch):
    sim = Sim(4, 7, tmp_path, monkeypatch)
    for _ in range(40):
        a, b = sim.rng.sample(range(4), 2)
        sim.complete(a, b)
    sim.run(30)
    rp, _q = sim.nodes[0]
    assert len(rp.history) == 41            # with the genesis
    # Batches of up to PLACE_BATCH_MAX, so a handful of placements (and the
    # genesis).
    assert len(rp.history.place_certs) <= 5


def test_a_minority_island_places_nothing(tmp_path, monkeypatch):
    sim = Sim(5, 3, tmp_path, monkeypatch)
    sim.island = {3, 4}
    minority = sim.complete(3, 4, at=(3, 4))
    majority = sim.complete(0, 1, at=(0, 1, 2))
    sim.run(30)
    assert sim.chains({3, 4}) == [[], []]
    assert sim.chains({0, 1, 2}) == [[majority]] * 3
    # The heal: the minority's halves reach the majority, which places them.
    sim.island = None
    for i in (0, 1, 2):
        rp, _q = sim.nodes[i]
        held = sim.nodes[3][0].history.pooled(minority)
        for who, score in ((held.p1_id, held.p1_score),
                           (held.p2_id, held.p2_score)):
            rp.history.record_half(minority, who, score,
                                   certificate=held.certificate_of(who),
                                   counterparty=held.counterparty_of(who),
                                   half_sig=held.half_sig_of(who))
    sim.run(30)
    assert sim.chains({0, 1, 2}) == [[majority, minority]] * 3


def test_a_proposer_that_goes_quiet_is_taken_over(tmp_path, monkeypatch):
    sim = Sim(4, 11, tmp_path, monkeypatch)
    first = sim.complete(0, 1)
    sim.run(20)
    placer = sim.nodes[0][0]._place_vars()['_placers'].get('')
    assert placer is not None
    gone = next(i for i, (rp, _q) in enumerate(sim.nodes)
                if str(rp.identity.uuid).lower() == placer)
    sim.island = {gone}          # the leader drops off
    second = sim.complete(*[i for i in range(4) if i != gone][:2],
                          at=[i for i in range(4) if i != gone])
    sim.run(30)
    live = {i for i in range(4) if i != gone}
    assert sim.chains(live) == [[first, second]] * 3


def test_the_leader_places_the_next_instance_without_asking(tmp_path, monkeypatch):
    sim = Sim(4, 5, tmp_path, monkeypatch)
    first = sim.complete(0, 1)
    sim.run(20)
    asked = sim.asked()
    assert asked >= 1
    second = sim.complete(2, 3)
    sim.run(20)
    third = sim.complete(1, 2)
    sim.run(20)
    assert sim.chains() == [[first, second, third]] * 4
    # The ballot a majority promised for the first instance carried the
    # other two: nobody asked again.
    assert sim.asked() == asked


def test_a_leader_outranked_since_asks_again(tmp_path, monkeypatch):
    sim = Sim(4, 9, tmp_path, monkeypatch)
    first = sim.complete(0, 1)
    sim.run(20)
    v = sim.nodes[0][0]._place_vars()
    leader = sim.index_of(v['_placers'][''])
    # Another member asks for the next instance under a higher ballot, with
    # nothing to place, while the leader cannot hear it: the other three now
    # promise that ballot, and the leader still holds its own.
    other = (leader + 1) % 4
    sim.island = {leader}
    rp, q = sim.nodes[other]
    rp._start_place_round(q, '', rp.history)
    sim.deliver()
    sim.island = None
    lead = sim.nodes[leader][0]
    assert lead._place_vars()['_place_lead'].get('') is not None
    asked = sim.asked(leader)
    second = sim.complete(2, 3)
    sim.tick()
    # Its unasked `place` is refused, and the lead with it.
    assert sim.sent[(leader, ReputationProtocol.place)] == 2
    assert lead._place_vars()['_place_lead'].get('') is None
    sim.run(30)
    assert sim.chains() == [[first, second]] * 4
    assert sim.asked(leader) > asked


# --- Who is in the group (doc/architecture/reputation.md) ------------------

def test_founders_joining_one_at_a_time_share_one_roster(tmp_path, monkeypatch):
    sim = Sim(5, 21, tmp_path, monkeypatch, joined={0, 1})
    assert sim.roster_of(0) == sim.uuids({0, 1})
    for i in (2, 3, 4):
        sim.join(i)
        sim.settle(lambda: all(sim.roster_of(j) == sim.uuids(sim.joined)
                               for j in sim.joined))
    tasks = [sim.complete(0, 3), sim.complete(2, 4)]
    sim.run(30)
    chains = sim.chains()
    assert all(c == chains[0] for c in chains)
    assert sorted(map(str, chains[0])) == sorted(map(str, tasks))
    assert len({rp.history.head_hash for rp, _q in sim.nodes}) == 1


@pytest.mark.parametrize('seed', range(4))
def test_a_member_joining_mid_placement_cannot_split_the_chain(tmp_path, monkeypatch,
                                                              seed):
    """part-3546034: a placement decided under one roster, learned by members
    that have since added someone. Every node must still converge."""
    sim = Sim(4, seed, tmp_path, monkeypatch, joined={0, 1, 2})
    tasks = []
    for step in range(6):
        tasks.append(sim.complete(*sim.rng.sample(sorted(sim.joined), 2),
                                  at=sorted(sim.joined)))
        sim.tick(sim.rng.choice((0.1, 0.2)))
        if step == 2:
            sim.join(3)
    sim.settle(lambda: sim.roster_of(3) == sim.uuids({0, 1, 2, 3})
               and len({tuple(c) for c in sim.chains()}) == 1
               and len(sim.chains()[0]) == len(tasks), limit=3000)
    assert sorted(map(str, sim.chains()[0])) == sorted(map(str, tasks))


def test_a_majority_island_admits_a_member_a_minority_cannot(tmp_path, monkeypatch):
    sim = Sim(6, 9, tmp_path, monkeypatch, joined={0, 1, 2, 3, 4})
    sim.island = {3, 4}
    sim.join(5)                 # inside the majority island
    sim.settle(lambda: all(sim.roster_of(i) == sim.uuids({0, 1, 2, 3, 4, 5})
                           for i in (0, 1, 2, 5)), limit=3000)
    # Four of six now decide: 0, 1, 2 and the newcomer.
    task = sim.complete(0, 5, at=(0, 1, 2, 5))
    sim.run(30)
    assert sim.chains({0, 1, 2, 5}) == [[task]] * 4
    # The minority (two of five) placed nothing, and kept the old roster.
    stuck = sim.complete(3, 4, at=(3, 4))
    sim.run(30)
    assert sim.chains({3, 4}) == [[], []]
    assert sim.roster_of(3) == sim.uuids({0, 1, 2, 3, 4})
    del stuck


def test_a_roster_change_drops_the_leaders_skip(tmp_path, monkeypatch):
    sim = Sim(4, 13, tmp_path, monkeypatch, joined={0, 1, 2})
    first = sim.complete(0, 1, at=(0, 1, 2))
    sim.run(20)
    sim.join(3)
    sim.settle(lambda: all(sim.roster_of(i) == sim.uuids({0, 1, 2, 3})
                           for i in range(4)), limit=3000)
    leads = [rp._place_vars()['_place_lead'].get('') for rp, _q in sim.nodes]
    assert all(lead is None for lead in leads)
    asked = sim.asked()
    second = sim.complete(2, 3)
    sim.run(30)
    assert sim.chains() == [[first, second]] * 4
    assert sim.asked() > asked          # the new roster was asked first


def test_a_late_joiner_catches_up_on_a_restated_roster(tmp_path, monkeypatch):
    """With a window of 12, the roster is restated every six placements, so
    the roster in force never leaves it; a member admitted after the genesis
    has long gone anchors on the restatement and catches up."""
    sim = Sim(4, 17, tmp_path, monkeypatch, joined={0, 1, 2})
    for rp, _q in sim.nodes:
        rp.history.max_chain_len = 12
    tasks = []
    for _ in range(20):
        tasks.append(sim.complete(*sim.rng.sample([0, 1, 2], 2), at=[0, 1, 2]))
        sim.run(1)
    hist = sim.nodes[0][0].history
    assert hist.next_index > 20 and hist._first_index > 0      # genesis gone
    assert any(t.roster_op == 'restate' for t in hist if t.is_roster)
    sim.join(3)
    sim.settle(lambda: sim.roster_of(3) == sim.uuids({0, 1, 2, 3})
               and len({rp.history.head_hash for rp, _q in sim.nodes}) == 1,
               limit=3000)
