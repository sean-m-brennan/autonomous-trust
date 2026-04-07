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
"""Tests for _TeeQueue multi-observer fan-out."""

import multiprocessing
import pytest

from autonomous_trust.evaluation.instrumented import _TeeQueue


def _get(q, timeout=2):
    """Get from a multiprocessing.Queue with a timeout.

    multiprocessing.Queue uses an internal feeder thread, so items may not
    be immediately visible to get_nowait() right after a put/put_nowait call.
    Using a short blocking get avoids spurious Empty races in unit tests.
    """
    try:
        return q.get(timeout=timeout)
    except Exception:
        raise AssertionError('Queue was empty after %ss' % timeout)


class TestTeeQueueSingleObserver:
    """Backward compatibility: single observer queue still works."""

    def test_put_copies_to_single_observer(self):
        real_q = multiprocessing.Queue()
        obs_q = multiprocessing.Queue()
        tee = _TeeQueue(real_q, obs_q)
        tee.put('hello')
        assert _get(real_q) == 'hello'
        assert _get(obs_q) == 'hello'

    def test_put_nowait_copies_to_single_observer(self):
        real_q = multiprocessing.Queue()
        obs_q = multiprocessing.Queue()
        tee = _TeeQueue(real_q, obs_q)
        tee.put_nowait('hello')
        assert _get(real_q) == 'hello'
        assert _get(obs_q) == 'hello'


class TestTeeQueueMultipleObservers:
    """Fan-out to multiple observer queues."""

    def test_put_copies_to_all_observers(self):
        real_q = multiprocessing.Queue()
        obs1 = multiprocessing.Queue()
        obs2 = multiprocessing.Queue()
        tee = _TeeQueue(real_q, [obs1, obs2])
        tee.put('hello')
        assert _get(real_q) == 'hello'
        assert _get(obs1) == 'hello'
        assert _get(obs2) == 'hello'

    def test_put_nowait_copies_to_all_observers(self):
        real_q = multiprocessing.Queue()
        obs1 = multiprocessing.Queue()
        obs2 = multiprocessing.Queue()
        tee = _TeeQueue(real_q, [obs1, obs2])
        tee.put_nowait('hello')
        assert _get(real_q) == 'hello'
        assert _get(obs1) == 'hello'
        assert _get(obs2) == 'hello'

    def test_observer_failure_does_not_block(self):
        """If one observer is full, others still receive."""
        real_q = multiprocessing.Queue()
        obs1 = multiprocessing.Queue(maxsize=1)
        obs2 = multiprocessing.Queue()
        obs1.put('filler')  # fill obs1
        tee = _TeeQueue(real_q, [obs1, obs2])
        tee.put('hello')
        assert _get(real_q) == 'hello'
        assert _get(obs2) == 'hello'
        # obs1 still has 'filler', 'hello' was dropped silently

    def test_get_reads_from_real_queue(self):
        real_q = multiprocessing.Queue()
        obs = multiprocessing.Queue()
        tee = _TeeQueue(real_q, [obs])
        real_q.put('direct')
        assert _get(real_q) == 'direct'
