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
"""The placement pool and the in-order write of decided placements
(doc/architecture/reputation.md, "Agreeing on an order").

Committed halves wait in a pool, by task, and reach the chain only through a
decided placement, which writes its entries at the next index exactly as
given. So every node that applies the same placements in the same order holds
the same chain, whatever order the halves reached it in.
"""
from uuid import UUID

import pytest

from autonomous_trust.core.reputation.reputation import (
    PLACE_BATCH_MAX, Transaction, TransactionHistory, attest_task_id,
    place_designation, place_value_bytes, place_value_digest, placement_entry)

A = UUID('aaaaaaaa-0000-4000-8000-000000000001')
B = UUID('bbbbbbbb-0000-4000-8000-000000000002')
C = UUID('cccccccc-0000-4000-8000-000000000003')


def _task(n):
    return UUID('00000000-0000-4000-8000-%012d' % n)


_SCORES = {A: 0.6, B: 0.8, C: 0.5}


def _ready(hist, n, first=B, second=A):
    hist.record_half(_task(n), first, _SCORES[first])
    assert hist.record_half(_task(n), second, _SCORES[second]) == 'ready'


class TestRecordHalf:
    def test_one_half_is_pending_and_two_are_ready(self):
        hist = TransactionHistory()
        assert hist.record_half(_task(1), A, 0.8) == 'pending'
        assert hist.record_half(_task(1), B, 0.6) == 'ready'

    def test_the_same_scorer_again_is_a_duplicate(self):
        hist = TransactionHistory()
        hist.record_half(_task(1), A, 0.8)
        assert hist.record_half(_task(1), A, 0.8) == 'dup'

    def test_a_third_half_is_a_duplicate(self):
        hist = TransactionHistory()
        _ready(hist, 1)
        assert hist.record_half(_task(1), C, 0.5) == 'dup'

    def test_the_pool_is_not_the_chain(self):
        hist = TransactionHistory()
        _ready(hist, 1)
        assert len(hist) == 0
        assert _task(1) not in hist
        with pytest.raises(KeyError):
            hist.by_peer(A)

    def test_a_placed_task_is_not_pooled_again(self):
        hist = TransactionHistory()
        _ready(hist, 1)
        assert hist.apply_placed(0, hist.ready_items()) == 'applied'
        assert hist.record_half(_task(1), A, 0.8) == 'placed'

    def test_an_evicted_task_is_tombstoned(self):
        hist = TransactionHistory(max_chain_len=1)
        _ready(hist, 1)
        hist.apply_placed(0, hist.ready_items())
        _ready(hist, 2)
        hist.apply_placed(1, hist.ready_items())
        assert hist.record_half(_task(1), C, 0.5) == 'tombstoned'

    def test_a_certificate_is_kept_with_its_half(self):
        hist = TransactionHistory()
        hist.record_half(_task(1), A, 0.8, certificate={'v': 'sig'})
        assert hist.pooled(_task(1)).certificate_of(A) == {'v': 'sig'}

    def test_the_pool_keeps_the_newest_chain_length_of_tasks(self):
        hist = TransactionHistory(max_chain_len=2)
        for n in (1, 2, 3):
            hist.record_half(_task(n), A, 0.8)
        assert hist.pooled(_task(1)) is None
        assert hist.pooled(_task(3)) is not None


class TestReadyItems:
    def test_ready_items_are_by_task_and_skip_pending(self):
        hist = TransactionHistory()
        _ready(hist, 3)
        hist.record_half(_task(2), A, 0.8)
        _ready(hist, 1)
        assert [e.task_id for e in hist.ready_items()] == [_task(1), _task(3)]

    def test_ready_items_are_capped(self):
        hist = TransactionHistory()
        for n in range(PLACE_BATCH_MAX + 3):
            _ready(hist, n)
        assert len(hist.ready_items()) == PLACE_BATCH_MAX
        assert len(hist.ready_items(2)) == 2

    def test_halves_are_ordered_by_scorer_whichever_came_first(self):
        one, two = TransactionHistory(), TransactionHistory()
        _ready(one, 1, first=B, second=A)
        _ready(two, 1, first=A, second=B)
        e1, e2 = one.ready_items()[0], two.ready_items()[0]
        assert (e1.p1_id, e1.p1_score, e1.p2_id) == (A, 0.6, B)
        assert e1._canonical_bytes() == e2._canonical_bytes()


def _attested(verifier=A, subject=B, digest='ab' * 32):
    return Transaction(attest_task_id(verifier, subject, digest),
                       p1_id=verifier, p1_score=0.3, p1_channel='probe',
                       attested=True, subject_id=subject,
                       evidence_digest=digest)


class TestAttested:
    def test_a_well_formed_attestation_is_ready(self):
        hist = TransactionHistory()
        tx = _attested()
        assert hist.pool_attested(tx, {'v': 'sig'})
        (entry,) = hist.ready_items()
        assert entry.attested and entry.p1_id == A
        hist.apply_placed(0, [entry])
        assert hist.attest_certs[tx.task_id] == {'v': 'sig'}

    def test_an_attestation_is_pooled_once(self):
        hist = TransactionHistory()
        assert hist.pool_attested(_attested())
        assert not hist.pool_attested(_attested())

    def test_a_malformed_attestation_is_refused(self):
        hist = TransactionHistory()
        tx = _attested()
        tx.subject_id = A
        assert not hist.pool_attested(tx)


class TestApplyPlaced:
    def test_entries_take_the_next_indices_linked_to_the_head(self):
        hist = TransactionHistory()
        _ready(hist, 1)
        _ready(hist, 2)
        assert hist.apply_placed(0, hist.ready_items(), {'v': 's'}) == 'applied'
        assert [tx.index for tx in hist] == [0, 1]
        assert hist.verify_links()
        assert hist.ready_items() == []
        assert hist.by_peer(A)

    def test_a_placement_ahead_waits_for_the_one_before_it(self):
        hist = TransactionHistory()
        _ready(hist, 1)
        _ready(hist, 2)
        first, second = hist.ready_items()
        assert hist.apply_placed(1, [second]) == 'buffered'
        assert len(hist) == 0
        assert hist.apply_placed(0, [first]) == 'applied'
        assert [tx.task_id for tx in hist] == [_task(1), _task(2)]

    def test_a_placement_behind_the_chain_is_old(self):
        hist = TransactionHistory()
        _ready(hist, 1)
        hist.apply_placed(0, hist.ready_items())
        assert hist.apply_placed(0, [placement_entry(hist[_task(1)])]) == 'old'
        assert len(hist) == 1

    def test_an_empty_placement_writes_nothing(self):
        assert TransactionHistory().apply_placed(0, []) == 'empty'

    def test_two_nodes_applying_the_same_placements_hold_the_same_chain(self):
        one, two = TransactionHistory(), TransactionHistory()
        for n in (1, 2, 3):
            _ready(one, n, first=A, second=B)
        for n in (3, 1, 2):
            _ready(two, n, first=B, second=A)
        batch = one.ready_items()
        one.apply_placed(0, batch)
        two.apply_placed(0, batch)
        assert one.head_hash == two.head_hash

    def test_the_certificate_sits_on_the_last_entry(self):
        hist = TransactionHistory()
        _ready(hist, 1)
        _ready(hist, 2)
        assert hist.placed_end is None
        hist.apply_placed(0, hist.ready_items(), {'v': 's'})
        assert hist.place_certs == {_task(2): {'v': 's'}}
        assert hist.placed_end == 2

    def test_eviction_drops_the_certificate(self):
        hist = TransactionHistory(max_chain_len=1)
        _ready(hist, 1)
        hist.apply_placed(0, hist.ready_items(), {'v': 's'})
        _ready(hist, 2)
        hist.apply_placed(1, hist.ready_items())
        assert hist.place_certs == {}
        assert hist.placed_end is None


class TestPlacementBytes:
    def _entries(self):
        hist = TransactionHistory()
        _ready(hist, 1)
        _ready(hist, 2)
        return hist.ready_items()

    def test_the_value_covers_each_entry_at_its_index(self):
        entries = self._entries()
        raw = place_value_bytes(entries, 5)
        assert raw.startswith(b'AT-PLACE-VALUE\x00')
        lines = raw[len(b'AT-PLACE-VALUE\x00'):].split(b'\n')
        assert [line.split(b'|')[5] for line in lines] == [b'5', b'6']

    def test_the_digest_moves_with_the_index_and_the_order(self):
        entries = self._entries()
        d = place_value_digest(entries, 0)
        assert len(d) == 64
        assert d != place_value_digest(entries, 1)
        assert d != place_value_digest(list(reversed(entries)), 0)

    def test_the_designation_names_index_predecessor_and_value(self):
        assert place_designation(7, b'ff' * 32, b'ab' * 32) == (
            b'AT-PLACE\x007|' + b'ff' * 32 + b'|' + b'ab' * 32)
        assert place_designation(0, b'', 'cd' * 32) == (
            b'AT-PLACE\x000||' + b'cd' * 32)
