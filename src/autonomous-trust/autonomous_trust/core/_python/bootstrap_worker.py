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

"""BootstrapWorker — drives the AT-core bootstrap corpus.

See ``doc/architecture/trust-tiers.md`` §6.4. The worker is a Process
that, once peers are admitted, issues a fixed number of randomly-paired
Task invitations against the three tier-0 bootstrap capabilities
(``at.handshake`` / ``at.time-attest`` / ``at.echo-challenge``) over a
short post-admission window. Each invitation rides the normal
negotiation pipeline; the existing main-loop TaskResult handler in
``automate.py`` submits the resulting TransactionScores. The net effect
is that every admitted peer accumulates enough bilateral history to
graduate from CTFT to pure-reputation before any domain capabilities
fire.

Configuration (all env-overridable):

- ``AT_BOOTSTRAP_DURATION_SEC`` (default 30.0) — wall-clock window
  during which the worker schedules new pairs. After the window
  closes, scheduling stops; in-flight tasks complete normally.
- ``AT_BOOTSTRAP_PAIRS`` (default 20) — total pair-invitations to
  issue across the window.
- ``AT_BOOTSTRAP_DISABLED`` (default unset) — set to ``1`` to skip
  the worker entirely. Honored both at worker-registration time
  (``automate.py.__init__``) and at process-start time (here) so a
  late env change still suppresses the work.
- ``AT_BOOTSTRAP_SEED`` (default unset) — integer seed for the
  worker's ``random.Random`` instance. The conformance scenario
  ``bootstrap/bootstrap-corpus-runs-on-admission.yaml`` and the
  unit tests in ``test_bootstrap_worker.py`` set this so the
  capability/peer sequence is deterministic.
"""

from __future__ import annotations

import os
import queue
import random
from typing import Any

from .bootstrap_capabilities import (
    BOOTSTRAP_CAPABILITY_NAMES, register_bootstrap_capabilities,
)
from .capabilities import Capabilities
from .negotiation.negotiation import Task, TaskParameters
from .negotiation.protocol import NegotiationProtocol
from .network.message import Message
from .processes import Process, ProcMeta
from .system import CfgIds, now


class BootstrapWorker(Process, metaclass=ProcMeta,
                      proc_name='bootstrap_worker',
                      description='AT-core bootstrap corpus driver'):
    """Periodically issues bilateral bootstrap-capability invitations.

    Lifecycle:

    1. Idle until ``self.peers.all`` becomes non-empty. The first
       tick where peers exist opens the window.
    2. Each tick within ``[window_start, window_start + duration]``
       issues at most one Task invitation (so the load is paced over
       the window instead of bursting at t=0). If ``pairs_target`` is
       hit before the window closes, scheduling stops early.
    3. After the window closes, the process loop continues but does
       no scheduling. ``keep_running`` polls the signal queue, so a
       ``quit`` signal still tears the worker down cleanly.
    """

    DEFAULT_DURATION_SEC = 30.0
    DEFAULT_PAIRS_TARGET = 20

    def __init__(self, configurations: dict, subsystems, log_q,
                 dependencies: list[str] = None, **kwargs: Any) -> None:
        # The worker drives Task invitations into the negotiation queue
        # and pulls peer/capability state from identity-side configs.
        # Both have to be initialized before our `process` runs — express
        # that as an ordering dependency so run_forever starts us last.
        deps = dependencies if dependencies is not None else [
            CfgIds.negotiation, CfgIds.identity,
        ]
        super().__init__(configurations, subsystems, log_q,
                         dependencies=deps, **kwargs)
        self.identity = configurations[CfgIds.identity]
        self.peers = configurations[CfgIds.peers]
        # The node's OWN registered Capabilities live on the orchestrator
        # (Automate.capabilities) and are NOT exposed through the configs
        # dict: configs[CfgIds.capabilities] is the PeerCapabilities map
        # (name -> [peer_ids]) per the Protocol convention (see
        # protocol.py:45 and Automate._configure's `defaultable`). Reading
        # that key here grabbed a PeerCapabilities, which has no to_list()
        # -> _tick raised AttributeError every pass -> the worker never
        # issued a bootstrap pair -> peers were never admitted to the group
        # ("not in group" floods, peers.all stuck low, reputations frozen
        # at 0.5). The worker only ever issues the three bootstrap caps, so
        # own a private Capabilities with exactly those registered, mirroring
        # Automate.__init__'s register_bootstrap_capabilities(self.capabilities).
        # Gate on AT_BOOTSTRAP_DISABLED exactly as Automate does, so the
        # "cap not registered -> skip" branch in _try_issue_pair stays
        # meaningful (process() also exits outright when disabled).
        self.capabilities: Capabilities = Capabilities()
        if not os.environ.get('AT_BOOTSTRAP_DISABLED'):
            register_bootstrap_capabilities(self.capabilities)

        self.duration_sec = self._read_float_env(
            'AT_BOOTSTRAP_DURATION_SEC', self.DEFAULT_DURATION_SEC)
        self.pairs_target = self._read_int_env(
            'AT_BOOTSTRAP_PAIRS', self.DEFAULT_PAIRS_TARGET)

        seed_env = os.environ.get('AT_BOOTSTRAP_SEED')
        if seed_env is not None and seed_env.lstrip('-').isdigit():
            self._rng = random.Random(int(seed_env))
        else:
            self._rng = random.Random()

        self._window_start = None
        self._pairs_issued = 0
        # cap_name -> issuance count. Lets the conformance pin assert
        # that each of the three bootstrap caps fired at least once.
        self._counts_by_cap: dict[str, int] = {
            name: 0 for name in BOOTSTRAP_CAPABILITY_NAMES
        }

    @staticmethod
    def _read_float_env(name: str, default: float) -> float:
        try:
            v = os.environ.get(name)
            return float(v) if v is not None else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _read_int_env(name: str, default: int) -> int:
        try:
            v = os.environ.get(name)
            return int(v) if v is not None else default
        except (TypeError, ValueError):
            return default

    def _build_task_args(self, cap_name: str) -> tuple[tuple, dict]:
        """Return ``(args, kwargs)`` for a bootstrap capability invocation.

        The server-side functions in ``bootstrap_capabilities.py`` accept
        kwargs (so ``at_handshake(nonce=...)`` rather than positional);
        the negotiation pipeline forwards ``TaskParameters.args/kwargs``
        verbatim to ``Capability.execute``. Each call here draws from
        ``self._rng`` so seeded scenarios reproduce identical sequences.
        """
        if cap_name == 'at.handshake':
            return ((), {'nonce': self._rng.randint(1, 1_000_000)})
        if cap_name == 'at.time-attest':
            return ((), {})
        if cap_name == 'at.echo-challenge':
            return ((), {'payload': f'echo:{self._rng.randrange(0, 2**32):08x}'})
        return ((), {})

    def _try_issue_pair(self, queues: dict) -> bool:
        """Schedule one Task invitation against a random bootstrap cap.

        Returns True if a Task was put on the negotiation queue. False
        if no eligible peers / no bootstrap caps are registered locally /
        the queue is full (the latter is logged but otherwise non-fatal —
        the worker will retry on the next tick).
        """
        if not list(self.peers.all):
            return False

        cap_name = self._rng.choice(BOOTSTRAP_CAPABILITY_NAMES)
        if cap_name not in self.capabilities.to_list():
            # AT_BOOTSTRAP_DISABLED was set after registration suppressed
            # one of the caps, or the host is running with a curated
            # subset. Skip this tick rather than crash.
            return False
        cap = self.capabilities[cap_name]
        args, kwargs = self._build_task_args(cap_name)
        task = Task(TaskParameters(cap, args=args, kwargs=kwargs),
                    self.identity)
        msg = Message(CfgIds.negotiation, NegotiationProtocol.start, task)
        try:
            queues[CfgIds.negotiation].put(
                msg, block=True, timeout=self.q_cadence)
        except queue.Full:
            self.logger.warning(
                'BootstrapWorker: negotiation queue full, retrying next tick')
            return False
        self._pairs_issued += 1
        self._counts_by_cap[cap_name] = self._counts_by_cap.get(cap_name, 0) + 1
        self.logger.debug(
            'BootstrapWorker: issued %d/%d (cap=%s)',
            self._pairs_issued, self.pairs_target, cap_name)
        return True

    def _tick(self, queues: dict) -> None:
        """One pass of the worker's main loop: open window when peers
        appear, schedule a pair if the window is open and the target
        hasn't been hit, otherwise idle."""
        if self._window_start is None:
            if list(self.peers.all):
                self._window_start = now()
                self.logger.info(
                    'BootstrapWorker: window open, duration=%.1fs, '
                    'target_pairs=%d, peers=%d',
                    self.duration_sec, self.pairs_target,
                    len(list(self.peers.all)))
            else:
                return
        if self._pairs_issued >= self.pairs_target:
            return
        elapsed = (now() - self._window_start).total_seconds()
        if elapsed > self.duration_sec:
            return
        self._try_issue_pair(queues)

    def process(self, queues: dict, signal) -> None:
        """Process entry point. Honors ``AT_BOOTSTRAP_DISABLED`` and then
        runs the standard ``keep_running`` loop, ticking at the Process
        cadence. The loop survives the window — once scheduling stops
        the worker idles, leaving the quit signal as the only way out."""
        if os.environ.get('AT_BOOTSTRAP_DISABLED') == '1':
            self.logger.info(
                'BootstrapWorker: AT_BOOTSTRAP_DISABLED=1, exiting')
            return
        self.logger.debug('BootstrapWorker: process loop start')
        while self.keep_running(signal):
            try:
                self._tick(queues)
            except Exception as exc:  # noqa: BLE001 — never crash the loop
                self.report_exception(exc, function='BootstrapWorker._tick')
            self.sleep_until(self.cadence)
        self.logger.debug(
            'BootstrapWorker: process loop exit (issued=%d, counts=%s)',
            self._pairs_issued, self._counts_by_cap)
