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
"""
Named (layer, event, reason) counters with periodic delta emission.

The bag aggregates in-process; every _EMIT_INTERVAL_SEC the bag is
snapshotted, reset, and emitted as one 'counters'/'snapshot' event.
Downstream tools sum the deltas to recover totals; this keeps the
output file size proportional to event activity rather than to time.
"""
import os
import threading
import time

from . import _writer


_EMIT_INTERVAL_SEC = float(os.environ.get('AT_PROBES_COUNTER_SEC', '5.0'))

_lock = threading.Lock()
_pid: int | None = None
_bag: dict = {}
_last_emit = 0.0


def _check_fork() -> None:
    # Forked children inherit module state but not threads; bag and
    # _last_emit are per-process. Reset on pid change.
    global _pid, _bag, _last_emit
    cur = os.getpid()
    if _pid != cur:
        _pid = cur
        _bag = {}
        _last_emit = time.time()


def counter(layer: str, event: str, reason: str | None = None, n: int = 1) -> None:
    _check_fork()
    snap = None
    with _lock:
        key = (layer, event, reason or '')
        _bag[key] = _bag.get(key, 0) + n
        global _last_emit
        now = time.time()
        if now - _last_emit >= _EMIT_INTERVAL_SEC and _bag:
            snap = list(_bag.items())
            _bag.clear()
            _last_emit = now
    if snap:
        _emit_snapshot(snap)


def flush_bag() -> None:
    """Force-emit the current bag without resetting the interval timer."""
    snap = None
    with _lock:
        if _bag:
            snap = list(_bag.items())
            _bag.clear()
            global _last_emit
            _last_emit = time.time()
    if snap:
        _emit_snapshot(snap)


def _emit_snapshot(snap) -> None:
    items = [{'layer': l, 'event': e, 'reason': r, 'count': c}
             for (l, e, r), c in snap]
    _writer.emit('counters', 'snapshot', items=items)
