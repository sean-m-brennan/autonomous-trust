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
"""Own entries outlive the chain window.

Hostile-join runs without the policy, 2026-11-04: the primary chain keeps 200
resident entries, and ten nodes' probes and tasks evicted a joiner's own
transactions with its contact within minutes (35 fell to 2). An evicted entry
this node is a party to now moves to a bounded store beside the window
(TransactionHistory.retained_by_peer), which the scorers read before the
resident entries. The window, its root, catch-up and the wire are unchanged.
The C twin is src/c/test/rep_retained_test.c.
"""
import json
import os
from uuid import uuid4

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.reputation.reputation import (
    TransactionHistory, score_to_milli)
from autonomous_trust.core._python.reputation.reputation import (
    RETAINED_PER_PEER, evidence_to_dict)
from tests.a_unit.test_repprocess import _make_rep_process


@pytest.fixture(autouse=True)
def _cfg_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)


def _pair(h, a, a_score, b, b_score):
    task = uuid4()
    h.update(task, a, score_to_milli(a_score))
    h.update(task, b, score_to_milli(b_score))
    return task


def _history(me, cap=4):
    h = TransactionHistory(max_chain_len=cap)
    h.keep_party = str(me)
    return h


def test_an_evicted_own_entry_is_retained():
    me, peer, x, y = uuid4(), uuid4(), uuid4(), uuid4()
    h = _history(me)
    own = [_pair(h, me, 0.9, peer, 0.8) for _ in range(3)]
    for _ in range(4):
        _pair(h, x, 0.5, y, 0.5)
    assert len(h) == 4
    assert [t.task_id for t in h.retained_by_peer(peer)] == own
    assert [t.task_id for t in h.retained_by_peer(me)] == own


def test_a_third_partys_entry_is_not_retained():
    me, peer, x, y = uuid4(), uuid4(), uuid4(), uuid4()
    h = _history(me)
    for _ in range(3):
        _pair(h, x, 0.5, peer, 0.5)
    for _ in range(4):
        _pair(h, x, 0.5, y, 0.5)
    assert h.retained_by_peer(peer) == []


def test_without_a_party_to_keep_nothing_is_retained():
    me, peer, x, y = uuid4(), uuid4(), uuid4(), uuid4()
    h = TransactionHistory(max_chain_len=4)
    for _ in range(3):
        _pair(h, me, 0.9, peer, 0.8)
    for _ in range(4):
        _pair(h, x, 0.5, y, 0.5)
    assert h.retained_by_peer(peer) == []


def test_the_bounds_drop_the_oldest():
    me, a, b, x, y = uuid4(), uuid4(), uuid4(), uuid4(), uuid4()
    h = _history(me)
    h.retained_per_peer = 2
    h.retained_max = 3
    a_tasks = [_pair(h, me, 0.9, a, 0.9) for _ in range(3)]
    b_tasks = [_pair(h, me, 0.9, b, 0.9) for _ in range(2)]
    for _ in range(4):
        _pair(h, x, 0.5, y, 0.5)
    # a's oldest goes to the per-peer bound, then the overall oldest (a's
    # second) to the total.
    assert [t.task_id for t in h.retained_by_peer(a)] == a_tasks[2:]
    assert [t.task_id for t in h.retained_by_peer(b)] == b_tasks
    assert RETAINED_PER_PEER == 64
    assert TransactionHistory(max_chain_len=7).retained_max == 28


def test_the_window_is_unchanged():
    me, peer, x, y = uuid4(), uuid4(), uuid4(), uuid4()
    plain, kept = TransactionHistory(max_chain_len=4), _history(me)
    tasks = [uuid4() for _ in range(7)]
    for h in (plain, kept):
        for i, task in enumerate(tasks):
            a, b = (me, peer) if i < 3 else (x, y)
            h.update(task, a, 900)
            h.update(task, b, 800)
    assert len(plain) == len(kept) == 4
    assert [t.entry_hash() for t in plain] == [t.entry_hash() for t in kept]
    assert [t.task_id for t in plain.era(0)] == [t.task_id for t in kept.era(0)]
    with pytest.raises(KeyError):
        kept.by_peer(peer)


def test_the_process_keeps_its_own_entries():
    rp = _make_rep_process()
    assert rp.history.keep_party == str(rp.identity.uuid)


def test_ctft_and_own_evidence_read_the_retained_entries():
    rp = _make_rep_process()
    me = rp.identity.uuid
    rp.history = rp._own_history(max_chain_len=4)
    peer, x, y = uuid4(), uuid4(), uuid4()
    for _ in range(3):
        _pair(rp.history, me, 0.9, peer, 0.9)
    for _ in range(4):
        _pair(rp.history, x, 0.5, y, 0.5)
    assert rp._contrite_tit_for_tat(peer) == pytest.approx((2.7 + 0.6) / 6)
    assert rp._own_count(peer) == 3


def test_the_live_flush_no_longer_costs_the_contact():
    """35 transactions with the contact at 0.9, then 200 of the cohort's own:
    the contact still reads its record, (31.5 + 0.6) / 38."""
    rp = _make_rep_process()
    me = rp.identity.uuid
    contact, x, y = uuid4(), uuid4(), uuid4()
    for _ in range(35):
        _pair(rp.history, me, 0.9, contact, 0.9)
    for _ in range(200):
        _pair(rp.history, x, 0.5, y, 0.5)
    assert len(rp.history) == 200
    assert rp._contrite_tit_for_tat(contact) == pytest.approx(32.1 / 38)


def test_a_reset_keeps_the_store():
    rp = _make_rep_process()
    me = rp.identity.uuid
    rp.history = rp._own_history(max_chain_len=4)
    peer, x, y = uuid4(), uuid4(), uuid4()
    for _ in range(3):
        _pair(rp.history, me, 0.9, peer, 0.9)
    for _ in range(4):
        _pair(rp.history, x, 0.5, y, 0.5)
    assert rp._reset_pre_roster_chain('')
    assert len(rp.history) == 0
    assert rp.history.keep_party == str(me)
    assert len(rp.history.retained_by_peer(peer)) == 3


def test_the_store_round_trips_a_restart():
    rp = _make_rep_process()
    me = rp.identity.uuid
    rp.history = rp._own_history(max_chain_len=4)
    peer, x, y = uuid4(), uuid4(), uuid4()
    own = [_pair(rp.history, me, 0.9, peer, 0.9) for _ in range(3)]
    for _ in range(4):
        _pair(rp.history, x, 0.5, y, 0.5)
    rp._persist_retained('')
    with open(rp._retained_path('')) as f:
        doc = json.load(f)
    # A foreign entry, and one already resident, are dropped on load.
    resident = rp.history.era(0)[-1]
    foreign = TransactionHistory(max_chain_len=9)
    _pair(foreign, x, 0.5, peer, 0.5)
    doc['chain'] += (evidence_to_dict(list(foreign))['chain']
                     + evidence_to_dict([resident])['chain'])
    with open(rp._retained_path(''), 'w') as f:
        json.dump(doc, f)
    fresh = rp._own_history(max_chain_len=4)
    for t in rp.history.era(0):
        fresh._load_incoming([t])
    rp.history = fresh
    rp._load_retained('')
    assert [t.task_id for t in rp.history.retained_by_peer(peer)] == own
    assert rp.history.retained_by_peer(x) == []
