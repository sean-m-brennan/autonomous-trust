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
"""
Pickle / Manager.Queue round-trip regression test for Message.

History: a production observation suggested manager.Queue was
dropping `from_whom` (2361 puts → 408 gets with NoneType). This
harness was written to characterize that drop and concluded that
pickle/manager.Queue is *not* the cause — every variant preserved
from_whom intact under spawn, forkserver, and concurrent producers.
The actual cause was four producer sites constructing rep_req
without `from_whom=` — fixed in the same series.

This file remains as a regression guard: any future pickle / manager
proxy regression that drops Message attributes will fail here.
"""
from __future__ import annotations

import multiprocessing as mp
import pickle

from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message


# Fork is fragile inside pytest collection on some platforms; keep
# 'spawn' to mirror the AT runtime's forkserver context behavior as
# closely as possible without dragging in the full forkserver setup.
_CTX = mp.get_context('spawn')

# Production uses forkserver and pre-loads autonomous_trust.core. The
# cross-process tests below run a parallel forkserver variant since
# that path is the most likely explanation for the production drop.
_FORK_CTX = mp.get_context('forkserver')
try:
    _FORK_CTX.set_forkserver_preload(['autonomous_trust.core'])
except Exception:
    # Older Pythons / OS combos may not support preload; the tests
    # still exercise the fork without preload, which is informative.
    pass


def _make_identity(seed: int = 0) -> Identity:
    return Identity.initialize(
        f'peer.{seed}.test', f'peer{seed}', f'10.0.0.{seed % 250 + 1}')


def _make_message(sender: Identity, n: int) -> Message:
    return Message(process='reputation', function='rep_resp',
                   obj=f'payload-{n}', from_whom=sender, encrypt=False)


def test_pickle_roundtrip_preserves_from_whom():
    """Plain pickle: from_whom must survive a single bytes round-trip."""
    sender = _make_identity()
    msg = _make_message(sender, 0)
    revived = pickle.loads(pickle.dumps(msg))
    assert revived.from_whom is not None, \
        'pickle dropped from_whom on a single round-trip'
    assert revived.trace_id == msg.trace_id


def test_pickle_roundtrip_preserves_from_whom_at_scale():
    """1000 round-trips: any non-zero drop rate is a bug, not a fluke."""
    sender = _make_identity()
    drops = 0
    for i in range(1000):
        msg = _make_message(sender, i)
        revived = pickle.loads(pickle.dumps(msg))
        if revived.from_whom is None:
            drops += 1
    assert drops == 0, f'{drops}/1000 from_whom drops via plain pickle'


def _drain(q, n: int, out_list):
    for _ in range(n):
        msg = q.get(timeout=10)
        out_list.append((msg.trace_id, msg.from_whom is not None))


def test_manager_queue_same_process_preserves_from_whom():
    """Manager.Queue consumed in the producer process."""
    sender = _make_identity()
    with _CTX.Manager() as mgr:
        q = mgr.Queue()
        sent = []
        for i in range(200):
            m = _make_message(sender, i)
            sent.append(m.trace_id)
            q.put(m)
        seen = []
        _drain(q, 200, seen)
        drops = sum(1 for _, has_from in seen if not has_from)
        assert drops == 0, \
            f'manager.Queue (same-process) dropped from_whom on {drops}/200 messages'
        # Trace IDs must match 1:1 (order may differ if queue reorders,
        # which it shouldn't with a single producer/consumer).
        assert sorted(sent) == sorted(t for t, _ in seen)


def _producer(q, sender, n):
    for i in range(n):
        q.put(_make_message(sender, i))


def _consumer(q, n, result_q):
    drops = 0
    for _ in range(n):
        msg = q.get(timeout=15)
        if msg.from_whom is None:
            drops += 1
    result_q.put(drops)


def test_manager_queue_cross_process_preserves_from_whom():
    """Manager.Queue with producer in main and consumer in a child.
    Closest to the production topology where AT-core processes
    exchange messages via the shared manager."""
    _cross_process_check(_CTX, n=200)


def test_manager_queue_forkserver_cross_process():
    """Same as above, but under the production forkserver context.
    Production currently uses set_forkserver_preload(['autonomous_trust.core'])
    to defeat the per-thread re-import race documented in
    reference_demo_image_rebuild_traps.md trap #3."""
    _cross_process_check(_FORK_CTX, n=200)


def test_manager_queue_concurrent_producers():
    """Multiple producers + one consumer over forkserver. Production
    drops were observed under high concurrency — this approximates
    that condition."""
    sender = _make_identity()
    n_per = 500
    n_producers = 4
    total = n_per * n_producers
    with _FORK_CTX.Manager() as mgr:
        q = mgr.Queue()
        result_q = mgr.Queue()
        consumer = _FORK_CTX.Process(target=_consumer, args=(q, total, result_q))
        consumer.start()
        producers = [_FORK_CTX.Process(target=_producer, args=(q, sender, n_per))
                     for _ in range(n_producers)]
        for p in producers:
            p.start()
        for p in producers:
            p.join(timeout=60)
            assert p.exitcode == 0
        consumer.join(timeout=60)
        assert consumer.exitcode == 0
        drops = result_q.get(timeout=5)
        assert drops == 0, \
            f'concurrent forkserver dropped from_whom on {drops}/{total} messages'


def _cross_process_check(ctx, n: int):
    sender = _make_identity()
    with ctx.Manager() as mgr:
        q = mgr.Queue()
        result_q = mgr.Queue()
        consumer = ctx.Process(target=_consumer, args=(q, n, result_q))
        consumer.start()
        for i in range(n):
            q.put(_make_message(sender, i))
        consumer.join(timeout=30)
        assert consumer.exitcode == 0, \
            f'consumer exited with {consumer.exitcode}'
        drops = result_q.get(timeout=5)
        assert drops == 0, \
            f'manager.Queue ({ctx.get_start_method()}) dropped from_whom on {drops}/{n} messages'
