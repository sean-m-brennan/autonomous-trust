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
JSONL writer for probe events.

Output goes to a per-process file in $AT_PROBES_DIR (default
/var/at-probes). The shared-volume assumption: every AT process —
peer containers, inspector container, in-process harness — writes
into the same directory so that scripts/probe-tail.py can join
events across hosts.

Writer state is per-process. multiprocessing.forkserver children do
not inherit the writer thread, so we lazily detect a pid change on
first emit and re-initialise. Failures are silent — probes must
never break the run they are observing.
"""
import json
import os
import socket
import threading
import time
from pathlib import Path
from queue import Queue, Empty as _QEmpty


# All processes share this directory; mount it across containers.
_DIR = Path(os.environ.get('AT_PROBES_DIR', '/var/at-probes'))
_FLUSH_INTERVAL_SEC = float(os.environ.get('AT_PROBES_FLUSH_SEC', '2.0'))
_QUEUE_MAX = 10000

_lock = threading.Lock()
_pid: int | None = None
_queue: Queue | None = None
_thread: threading.Thread | None = None
_fh = None
_failed = False
_drop_count = 0


def _hostname() -> str:
    # AT_PEER_NAME is set by disaster_response_compose; falls back to
    # the container hostname for non-compose runs.
    return os.environ.get('AT_PEER_NAME') or socket.gethostname()


def _ensure_started() -> bool:
    global _pid, _queue, _thread, _fh, _failed, _drop_count
    cur = os.getpid()
    if _pid == cur and _queue is not None:
        return True
    if _failed and _pid == cur:
        return False
    with _lock:
        if _pid == cur and _queue is not None:
            return True
        if _failed and _pid == cur:
            return False
        try:
            _DIR.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime('%Y%m%dT%H%M%S')
            name = 'probes_%s_pid%d_%s.jsonl' % (_hostname(), cur, stamp)
            fh = (_DIR / name).open('a', buffering=1)
            q: Queue = Queue(maxsize=_QUEUE_MAX)
            t = threading.Thread(target=_drain_loop, args=(q, fh),
                                 name='at-probes-writer', daemon=True)
            t.start()
            _fh = fh
            _queue = q
            _thread = t
            _pid = cur
            _failed = False
            _drop_count = 0
            return True
        except Exception:
            _failed = True
            _pid = cur
            return False


def _drain_loop(q: Queue, fh) -> None:
    while True:
        time.sleep(_FLUSH_INTERVAL_SEC)
        items = []
        while True:
            try:
                items.append(q.get_nowait())
            except _QEmpty:
                break
        if not items:
            continue
        try:
            for ev in items:
                fh.write(json.dumps(ev, default=str) + '\n')
            fh.flush()
        except Exception:
            return  # writer thread dies silently; main loop survives


def emit(layer: str, event: str, **fields) -> None:
    global _drop_count
    if not _ensure_started():
        return
    record = {
        't': time.time(),
        'pid': os.getpid(),
        'host': _hostname(),
        'layer': layer,
        'event': event,
    }
    record.update(fields)
    try:
        _queue.put_nowait(record)
    except Exception:
        _drop_count += 1


def flush() -> None:
    if not _ensure_started():
        return
    items = []
    while True:
        try:
            items.append(_queue.get_nowait())
        except _QEmpty:
            break
    if not items:
        return
    try:
        for ev in items:
            _fh.write(json.dumps(ev, default=str) + '\n')
        _fh.flush()
    except Exception:
        pass
