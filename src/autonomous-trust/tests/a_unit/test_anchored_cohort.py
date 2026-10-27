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
"""The anchored cohort, identity's half (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 6,
D8 (b)): forming, consent, the coordinator, persistence. The C twin is
src/c/test/anchored_cohort_test.c.
"""
import json
import uuid

import pytest

from autonomous_trust.core._python.identity import anchored_cohort as ac
from autonomous_trust.core._python.identity.group import Group
from autonomous_trust.core._python.identity.join_policy import (
    AnchoredCohort, JoinPolicy)
from autonomous_trust.core._python.identity.peers import Peers
from autonomous_trust.core._python.identity.protocol import IdentityProtocol
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core.system import CfgIds

from tests.a_unit.test_late_joiner_caps_resync import (_build_process,
                                                       _new_identity, _queues)

ON = JoinPolicy(enabled=True, anchors=frozenset({'verified_contact'}))


class _Net:
    """Nodes by uuid, and delivery of what they put on the network queue."""

    def __init__(self, tmp_path, names, policy=ON):
        self.ids = {n: _new_identity(n, '10.9.0.%d' % (i + 1))
                    for i, n in enumerate(names)}
        # Ordered so the lowest uuid is predictable in the tests.
        members = {str(i.uuid).lower(): i.address for i in self.ids.values()}
        primary = Group(uuid.uuid4(), dict(members), 'cohort',
                        Encryptor.generate(), False)
        self.procs = {}
        self.trust = {n: set() for n in names}     # whom each counts an anchor
        self.published = {n: [] for n in names}
        for n, me in self.ids.items():
            peers = Peers()
            for other in self.ids.values():
                if other is not me:
                    peers.add(other)
            proc = _build_process(me, peers)
            proc.group = primary
            proc.join_policy = policy
            proc._cohort_init()
            proc.is_anchored = (lambda who, n=n:
                                who.nickname in self.trust[n])
            proc.update = (lambda msg, queues, n=n:
                           self.published[n].append(msg))
            path = tmp_path / ('%s.cohort.json' % n)
            proc._cohort_path = (lambda path=path: str(path))
            proc.queues = _queues()
            self.procs[n] = proc

    def by_uuid(self, u):
        return next(n for n, i in self.ids.items()
                    if str(i.uuid).lower() == str(u).lower())

    def lowest(self, names):
        return min(names, key=lambda n: str(self.ids[n].uuid).lower())

    def tick(self, name):
        self.procs[name]._maybe_form_anchored_cohort(self.procs[name].queues)

    def deliver(self, rounds=6):
        """Hand every queued identity message to its recipient's handler."""
        for _ in range(rounds):
            moved = False
            for n, proc in self.procs.items():
                items = proc.queues[CfgIds.network].items
                proc.queues[CfgIds.network].items = []
                for msg in items:
                    moved = True
                    for to in msg.to_whom:
                        dest = self.procs[self.by_uuid(to.uuid)]
                        msg.from_whom = self.ids[n]
                        handler = (dest.handle_anchored_cohort_invite
                                   if msg.function == IdentityProtocol.cohort_invite
                                   else dest.handle_anchored_cohort_reply)
                        assert handler(dest.queues, msg)
            if not moved:
                return

    def cohort(self, name):
        return self.procs[name].anchored_cohort

    def members(self, name):
        return {self.by_uuid(u) for u in ac.member_uuids(self.cohort(name))}


def _mutual(net, *names):
    for a in names:
        net.trust[a] |= set(names) - {a}


def test_mutual_anchors_form_one_cohort(tmp_path):
    net = _Net(tmp_path, ['a', 'b', 'c'])
    _mutual(net, 'a', 'b')
    for n in ('a', 'b', 'c'):
        net.tick(n)
    net.deliver()
    assert net.cohort('a') is not None
    assert str(net.cohort('a').uuid) == str(net.cohort('b').uuid)
    assert net.members('a') == {'a', 'b'} == net.members('b')
    assert net.cohort('c') is None                 # nobody's anchor
    assert net.cohort('a').owns_private_key and net.cohort('b').owns_private_key
    # Published to the sibling processes, and persisted.
    assert isinstance(net.published['b'][-1], AnchoredCohort)
    saved = json.load(open(net.procs['b']._cohort_path()))
    assert saved['uuid'] == str(net.cohort('b').uuid)


def test_only_the_lowest_uuid_forms_it(tmp_path):
    net = _Net(tmp_path, ['a', 'b'])
    _mutual(net, 'a', 'b')
    high = 'b' if net.lowest(['a', 'b']) == 'a' else 'a'
    net.tick(high)
    assert net.cohort(high) is None
    assert net.procs[high].queues[CfgIds.network].items == []


def test_the_policy_off_forms_nothing_and_ignores_invites(tmp_path):
    net = _Net(tmp_path, ['a', 'b'], policy=JoinPolicy())
    _mutual(net, 'a', 'b')
    net.tick(net.lowest(['a', 'b']))
    assert net.cohort('a') is None and net.cohort('b') is None


def test_anchored_cohort_min_is_honoured(tmp_path):
    net = _Net(tmp_path, ['a', 'b', 'c'],
               policy=JoinPolicy(enabled=True, anchored_cohort_min=2))
    _mutual(net, 'a', 'b')
    low = net.lowest(['a', 'b'])
    net.tick(low)
    assert net.cohort(low) is None                # one anchor, two needed
    _mutual(net, 'a', 'b', 'c')
    net.tick(net.lowest(['a', 'b', 'c']))
    net.deliver()
    assert all(net.members(n) == {'a', 'b', 'c'} for n in 'abc')


def test_an_invite_listing_a_stranger_is_refused_and_dropped(tmp_path):
    """b counts a and c as anchors, but c counts only... nobody but b; c
    refuses (a is not its anchor), and the coordinator drops it."""
    net = _Net(tmp_path, ['a', 'b', 'c'])
    low = net.lowest(['a', 'b', 'c'])
    others = sorted(set('abc') - {low})
    net.trust[low] = set(others)
    net.trust[others[0]] = {low, others[1]}
    net.trust[others[1]] = {others[0]}             # not the coordinator
    net.tick(low)
    net.deliver()
    assert net.cohort(others[1]) is None
    assert net.members(low) == {low, others[0]}
    assert net.members(others[0]) == {low, others[0]}
    assert net.cohort(low).key_epoch == 1          # rotated on the drop


def test_a_late_anchor_is_added_by_rotation(tmp_path):
    net = _Net(tmp_path, ['a', 'b', 'c'])
    low = net.lowest(['a', 'b', 'c'])
    rest = sorted(set('abc') - {low})
    _mutual(net, low, rest[0])
    net.tick(low)
    net.deliver()
    assert net.members(low) == {low, rest[0]}
    _mutual(net, 'a', 'b', 'c')
    net.tick(low)
    net.deliver()
    assert all(net.members(n) == {'a', 'b', 'c'} for n in 'abc')
    assert all(net.cohort(n).key_epoch == 1 for n in 'abc')


def test_an_update_adding_a_non_anchor_settles_without_both(tmp_path):
    """mid does not count high an anchor, so an update listing both is one
    mid refuses (leaving), and high, which does not count mid, refuses too.
    Which refusal the coordinator reads first decides who ends up in with it,
    and either is right; what must hold is that mid and high never share the
    cohort, every member agrees on it, and it then stays put (no peer is
    offered the membership it refused, so the two do not trade places)."""
    net = _Net(tmp_path, ['a', 'b', 'c'])
    low = net.lowest(['a', 'b', 'c'])
    mid, high = sorted(set('abc') - {low})
    _mutual(net, low, mid)
    net.tick(low)
    net.deliver()
    net.trust[low].add(high)
    net.trust[high].add(low)                       # mid does not count high
    for _ in range(3):
        net.tick(low)
        net.deliver()
    settled = net.members(low)
    assert low in settled and not {mid, high} <= settled
    for n in settled:
        assert net.members(n) == settled
    for _ in range(4):
        net.tick(low)
        net.deliver()
    assert net.members(low) == settled


def test_a_member_that_never_answers_is_dropped(tmp_path, monkeypatch):
    net = _Net(tmp_path, ['a', 'b'])
    _mutual(net, 'a', 'b')
    low = net.lowest(['a', 'b'])
    net.tick(low)
    net.procs[low].queues[CfgIds.network].items = []     # lost
    clock = [1000.0]
    monkeypatch.setattr(ac.time, 'time', lambda: clock[0])
    net.procs[low]._cohort_pending = {k: 0.0 for k in net.procs[low]._cohort_pending}
    net.tick(low)
    assert net.members(low) == {low}


def test_a_stale_invite_is_ignored(tmp_path):
    net = _Net(tmp_path, ['a', 'b'])
    _mutual(net, 'a', 'b')
    low = net.lowest(['a', 'b'])
    high = 'b' if low == 'a' else 'a'
    net.tick(low)
    first = list(net.procs[low].queues[CfgIds.network].items)
    net.deliver()
    held = net.cohort(high).key_epoch
    msg = first[0]
    msg.from_whom = net.ids[low]
    net.procs[high].handle_anchored_cohort_invite(net.procs[high].queues, msg)
    assert net.cohort(high).key_epoch == held
    assert net.procs[high].queues[CfgIds.network].items == []


def test_a_restart_restores_the_cohort(tmp_path):
    net = _Net(tmp_path, ['a', 'b'])
    _mutual(net, 'a', 'b')
    net.tick(net.lowest(['a', 'b']))
    net.deliver()
    held = net.cohort('b')
    net.procs['b']._cohort_init()
    net.procs['b']._cohort_load(net.procs['b'].queues)
    assert str(net.cohort('b').uuid) == str(held.uuid)
    assert net.cohort('b').owns_private_key
