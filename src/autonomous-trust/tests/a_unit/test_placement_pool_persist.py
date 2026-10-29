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
"""The placement pool survives a restart (doc/architecture/reputation.md,
"Agreeing on an order").

A committed half waits in the pool until a placement writes its entry. Its
round is over, so nobody proposes it again: were every holder to restart
before it is placed, it would be gone. Each placing chain's pool is written to
reputation-pool[-<chain>].cfg.json whenever it changes, and put back at boot
through record_half and pool_attested, so what was placed or tombstoned
meanwhile stays out.
"""
import json
import os
from uuid import UUID

from autonomous_trust.core.reputation.reputation import (
    Transaction, TransactionHistory, attest_task_id)

from tests.a_unit.test_placement_acceptor import (_entry, _placing, _pool,
                                                  four)  # noqa: F401

A = UUID('aaaaaaaa-0000-4000-8000-000000000001')
B = UUID('bbbbbbbb-0000-4000-8000-000000000002')
T1 = UUID('00000000-0000-4000-8000-000000000001')
T2 = UUID('00000000-0000-4000-8000-000000000002')

# The document both runtimes write for a pending half with its certificate, a
# ready entry with channels, and an attested entry. Pinned so the C twin
# (src/c/test/rep_place_pool_persist_test.c) reads exactly these bytes.
PINNED = (
    '{"schema": 2, "pool": ['
    '{"task": "00000000-0000-4000-8000-000000000001", "halves": ['
    '{"by": "aaaaaaaa-0000-4000-8000-000000000001", "score_milli": 750, '
    '"cert": {"bbbbbbbb-0000-4000-8000-000000000002": "abcd"}}]}, '
    '{"task": "00000000-0000-4000-8000-000000000002", "halves": ['
    '{"by": "bbbbbbbb-0000-4000-8000-000000000002", "score_milli": 500, '
    '"channel": "probe"}, '
    '{"by": "aaaaaaaa-0000-4000-8000-000000000001", "score_milli": 250}]}, '
    '{"task": "%s", "attested": true, '
    '"p1": "aaaaaaaa-0000-4000-8000-000000000001", "p1_score_milli": 250, '
    '"p1_channel": "probe", "subject": "bbbbbbbb-0000-4000-8000-000000000002", '
    '"evidence_digest": "%s", "attest_sigs": {"cccc": "ef01"}}]}'
    % (attest_task_id(A, B, 'ab' * 32), 'ab' * 32))


def _attested():
    return Transaction(attest_task_id(A, B, 'ab' * 32), p1_id=A, p1_score_milli=250,
                       p1_channel='probe', attested=True, subject_id=B,
                       evidence_digest='ab' * 32)


def _pinned_history():
    hist = TransactionHistory()
    hist.record_half(T1, A, 750, certificate={str(B): 'abcd'})
    hist.record_half(T2, B, 500, 'probe')
    hist.record_half(T2, A, 250)
    assert hist.pool_attested(_attested(), {'cccc': 'ef01'})
    return hist


class TestPoolDocument:
    def test_the_document_is_pinned(self):
        assert json.dumps(_pinned_history().pool_to_dict()) == PINNED

    def test_it_round_trips(self):
        hist = TransactionHistory()
        assert hist.pool_from_dict(json.loads(PINNED)) == 3
        assert json.dumps(hist.pool_to_dict()) == PINNED
        assert len(hist.pooled(T1)) == 1 and len(hist.pooled(T2)) == 2
        assert hist.pooled(T1).certificate_of(A) == {str(B): 'abcd'}
        assert [tx.task_id for tx in hist.ready_items()] == sorted(
            [T2, _attested().task_id], key=str)

    def test_what_was_placed_meanwhile_stays_out(self):
        hist = TransactionHistory()
        hist.record_half(T2, B, 500)
        hist.record_half(T2, A, 250)
        hist.apply_placed(0, hist.ready_items())
        hist.pool_from_dict(json.loads(PINNED))
        assert hist.pooled(T2) is None and hist.pooled(T1) is not None

    def test_a_bad_item_is_skipped(self):
        doc = json.loads(PINNED)
        doc['pool'][0]['halves'][0]['score_milli'] = 7000
        doc['pool'][1]['task'] = 'not a uuid'
        hist = TransactionHistory()
        assert hist.pool_from_dict(doc) == 1      # only the attested entry

    def test_every_change_bumps_the_revision(self):
        hist = TransactionHistory()
        revs = [hist.pool_rev]
        hist.record_half(T1, A, 750)
        revs.append(hist.pool_rev)
        hist.record_half(T1, A, 750, certificate={'x': 'y'})
        revs.append(hist.pool_rev)
        hist.record_half(T1, A, 750, certificate={'x': 'y'})   # same again
        assert hist.pool_rev == revs[-1]
        hist.record_half(T1, B, 500)
        revs.append(hist.pool_rev)
        hist.apply_placed(0, hist.ready_items())
        revs.append(hist.pool_rev)
        assert revs == sorted(set(revs))


class TestRestart:
    def test_the_pool_survives_a_restart(self, four):
        me = four[0]
        rp, q = _placing(me, four)
        e = _entry(four, four[1], four[2])
        _pool(rp, e)
        rp.history.record_half(T1, four[3].uuid, 400)
        rp._persist_pools()
        again, _ = _placing(me, four)
        assert again.history.pooled(T1) is not None
        held = again.history.pooled(e.task_id)
        assert len(held) == 2
        for uid in (e.p1_id, e.p2_id):
            assert held.certificate_of(uid) == e.certificate_of(uid)

    def test_an_unchanged_pool_is_not_rewritten(self, four):
        rp, q = _placing(four[0], four)
        rp.history.record_half(T1, four[3].uuid, 400)
        rp._persist_pools()
        os.remove(rp._pool_path(''))
        rp._persist_pools()
        assert not os.path.exists(rp._pool_path(''))
        rp.history.record_half(T1, four[2].uuid, 400)
        rp._persist_pools()
        assert os.path.exists(rp._pool_path(''))

    def test_an_unreadable_pool_starts_empty(self, four):
        rp, q = _placing(four[0], four)
        with open(rp._pool_path(''), 'w') as f:
            f.write('{not json')
        again, _ = _placing(four[0], four)
        assert again.history.pooled_count() == 0
