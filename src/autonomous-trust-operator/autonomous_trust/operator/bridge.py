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
"""Node bridge — the ONLY coupling between the Textual UI and the AT node.

Mirrors the Inspector frontend pattern (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.7):
an ``OperatorNode`` runs in a background thread via ``run_forever(q_in, q_out)``;
the UI drains ``external_feedback`` (``ResourceDirectory`` snapshots now,
``TaskResult`` in P5) and submits ``Task`` DTOs on ``external_control``. The UI
never imports AT internals — it holds only this bridge plus the DTO types.

The node factory and queues are injectable so the bridge (and the screens that
read it) are testable headless with a fake node that just pushes snapshots —
no multiprocessing pool, no identity, no network.
"""
from __future__ import annotations

import threading
from queue import Empty, Full, Queue
from typing import Any, Callable, List, Optional

# DTO type used only for classifying drained feedback. Imported lazily so the
# package imports even where autonomous_trust.core isn't installed (e.g. a docs
# build); resolved on first poll.
_ResourceDirectory = None


def _resource_directory_cls():
    global _ResourceDirectory
    if _ResourceDirectory is None:
        from autonomous_trust.core.operator.resource_directory import (
            ResourceDirectory)
        _ResourceDirectory = ResourceDirectory
    return _ResourceDirectory


def _default_node_factory():
    """Build a request-only OperatorNode. Lazy import keeps the UI decoupled."""
    from autonomous_trust.core.operator import OperatorNode
    return OperatorNode()


class OperatorNodeBridge:
    """Owns the node thread + the external queues; the UI's single seam.

    :param node_factory: ``callable() -> node`` exposing
        ``run_forever(q_in, q_out)``. Defaults to a real ``OperatorNode``.
    :param control_queue / feedback_queue: thread-safe queues shared with the
        node's main loop (which runs in our background thread, so plain
        ``queue.Queue`` is sufficient — the external queues are touched only by
        the main loop, never the worker subprocesses). Injectable for tests.
    """

    def __init__(self,
                 node_factory: Optional[Callable[[], Any]] = None,
                 control_queue: Optional[Queue] = None,
                 feedback_queue: Optional[Queue] = None,
                 session_provider: Optional[Callable[[], Any]] = None):
        self._node_factory = node_factory or _default_node_factory
        self.control_queue: Queue = control_queue or Queue()
        self.feedback_queue: Queue = feedback_queue or Queue()
        self._session_provider = session_provider
        self._thread: Optional[threading.Thread] = None
        self._node: Any = None
        self._started = False
        self.latest_directory: Any = None
        #: most recent unexpected error from the node thread, if any
        self.node_error: Optional[BaseException] = None

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        """Launch the node in a daemon thread. Idempotent."""
        if self._started:
            return
        self._started = True
        self._thread = threading.Thread(
            target=self._run, name='operator-node', daemon=True)
        self._thread.start()

    def attach_session_provider(self, provider: Callable[[], Any]) -> None:
        """Supply ``callable() -> OperatorSession``, resolved when the node
        starts. A provider (not the session itself) because the UI builds its
        session lazily, often after the bridge exists."""
        self._session_provider = provider

    def _attach_session(self, node: Any) -> None:
        """Hand the live session to the node's main loop so it can answer
        attended-now pulls (ethne D8).

        This is the whole reason the signal works on a real node: the main loop
        runs in OUR thread, sharing the app's address space with the session,
        while the node's identity worker is a separate subprocess that cannot
        see it. Best-effort — a node build without the seam, or no session
        configured, simply leaves attended-now unreported."""
        if self._session_provider is None:
            return
        attach = getattr(node, 'set_operator_session', None)
        if not callable(attach):
            return
        try:
            attach(self._session_provider())
        except Exception:
            pass

    def _run(self) -> None:
        try:
            self._node = self._node_factory()
            self._attach_session(self._node)
            self._node.run_forever(q_in=self.control_queue,
                                   q_out=self.feedback_queue)
        except BaseException as err:  # surfaced to the UI, never silent
            self.node_error = err

    def stop(self, timeout: float = 5.0) -> None:
        """Best-effort shutdown. The node honors SIGTERM/quit; for the daemon
        thread we simply stop draining and let the process exit handle it."""
        node = self._node
        if node is not None:
            stop = getattr(node, 'stop', None) or getattr(node, 'cancel', None)
            if callable(stop):
                try:
                    stop()
                except Exception:
                    pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # -- data flow --------------------------------------------------------

    def submit(self, task: Any) -> bool:
        """Put a ``Task`` on ``external_control`` (P5 request path). Returns
        False if the control queue is full."""
        try:
            self.control_queue.put(task, block=False)
            return True
        except Full:
            return False

    def poll_feedback(self) -> List[Any]:
        """Drain everything currently on ``external_feedback``, updating
        ``latest_directory`` for any ``ResourceDirectory`` seen. Returns the
        raw drained items (newest last) so callers can also handle
        ``TaskResult`` (P5). Non-blocking."""
        drained: List[Any] = []
        rd_cls = None
        try:
            rd_cls = _resource_directory_cls()
        except Exception:
            rd_cls = None
        while True:
            try:
                item = self.feedback_queue.get_nowait()
            except Empty:
                break
            drained.append(item)
            if rd_cls is not None and isinstance(item, rd_cls):
                self.latest_directory = item
        return drained
