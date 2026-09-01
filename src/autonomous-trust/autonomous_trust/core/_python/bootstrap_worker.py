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

Continuous probing (R+D.md §12.7)
---------------------------------

The bootstrap window seeds reputation and then stops, which leaves the
honeypot pattern applied only at cold start. A peer therefore has to
misbehave inside its first 30 seconds to be caught by a known-answer
check, and a peer that degrades later — or that behaves well until it is
trusted — is never challenged again. Probing continues past the window
for exactly that reason, and it is what makes the probe channel an
*anchor* rather than a one-off initiation rite: it is the only evidence
that does not degrade as the adversarial fraction rises.

- ``AT_PROBE_INTERVAL_SEC`` (default 60.0) — minimum spacing between
  continuous probes. This is a rate limit, not a schedule: probes cost a
  real task round trip on both peers, so the default is deliberately
  slack compared to the bootstrap window's per-tick pacing.
- ``AT_PROBE_CONTINUOUS_DISABLED`` (default unset) — set to ``1`` to keep
  the historical behavior (bootstrap window only, then idle).
  ``AT_BOOTSTRAP_DISABLED=1`` still disables the worker entirely.

Allocation differs between the two phases, and the split is principled
rather than incidental. Inside the bootstrap window every peer is equally
unknown, so there is no posterior to be widest and uniform-random
selection is the correct allocation (it is also what the seeded
conformance contract pins). Once counts diverge, the doc's rule applies:
spend probes where the posterior over a peer's quality is widest and the
capability weight is highest. See ``_select_target`` and
``_select_capability``.
"""

from __future__ import annotations

import math
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
    #: Minimum seconds between continuous (post-window) probes.
    DEFAULT_PROBE_INTERVAL_SEC = 60.0

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

        self.probe_interval_sec = self._read_float_env(
            'AT_PROBE_INTERVAL_SEC', self.DEFAULT_PROBE_INTERVAL_SEC)
        self.continuous_enabled = (
            os.environ.get('AT_PROBE_CONTINUOUS_DISABLED') != '1')

        self._window_start = None
        self._pairs_issued = 0
        # Continuous-phase state (R+D.md §12.7). Counts are the posterior:
        # with no outcome feedback reaching this process, how *uncertain* we
        # are about a peer is a function of how often we have challenged it,
        # which is exactly what the UCB exploration term measures. See
        # _ucb_bonus for why this is the honest reading of "widest posterior"
        # here rather than a Beta posterior we have no way to update.
        self._probes_by_peer: dict[str, int] = {}
        self._probes_by_cap: dict[str, int] = {
            name: 0 for name in BOOTSTRAP_CAPABILITY_NAMES
        }
        self._probes_issued = 0
        self._last_probe_at = None
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

    @staticmethod
    def _ucb_bonus(count: int, total: int) -> float:
        """UCB1 exploration term for an arm probed ``count`` times out of
        ``total`` draws: ``sqrt(2 * ln(total + 1) / (count + 1))``.

        This is the "widest posterior" of R+D.md §12.7, read honestly for the
        information this process actually has. A Beta posterior over a peer's
        quality would need the probe *outcomes*, and those are scored in
        ``automate.py`` on the requestor's main loop — a different process,
        which does not report back here. What is available is how many times
        each peer and capability has been challenged, and under a
        count-only posterior the width is a function of exactly that. Writing
        it as UCB1 keeps it a standard, citable quantity rather than an
        invented heuristic, and it degrades correctly: an unprobed peer has
        the widest interval and is chosen first.

        ``total + 2`` rather than ``total + 1`` inside the log: at
        ``total == 0`` the latter is ``ln(1) == 0``, which zeroes the bonus for
        every arm and silently degenerates the whole selection to its
        tie-break on the very first draw. ``+ 1`` on the count avoids dividing
        by zero for an arm never drawn.
        """
        return math.sqrt(2.0 * math.log(total + 2) / (count + 1))

    def _select_target(self, peers: list):
        """Pick the peer whose quality we are least sure of.

        Deterministic ``argmax`` of :meth:`_ucb_bonus` over per-peer probe
        counts, tie-broken on the uuid string so the choice is reproducible
        across runs and mirrorable by the C twin (which has no ``random``
        parity with Python — see the conformance scenario's note). With all
        counts equal, the tie-break makes this a round-robin, which is the
        right cold behavior: nothing is known, so spread.
        """
        candidates = []
        for peer in peers:
            uuid_str = str(getattr(peer, 'uuid', ''))
            if not uuid_str:
                continue
            bonus = self._ucb_bonus(
                self._probes_by_peer.get(uuid_str, 0), self._probes_issued)
            # Highest bonus first, then lowest uuid: one total order, so the
            # winner does not depend on iteration order of `peers`.
            candidates.append(((-bonus, uuid_str), peer))
        if not candidates:
            return None
        return min(candidates, key=lambda item: item[0])[1]

    def _capability_weight(self, cap_name: str) -> float:
        """``transaction_weight`` for ``cap_name``, defaulting to 1.

        Read from the locally registered Capability, which
        ``register_bootstrap_capabilities`` populates from the trust ladder —
        so an operator who declares a bootstrap cap heavier in
        ``trust_ladder.json`` also gets it probed more often, with no code
        change here.
        """
        try:
            cap = self.capabilities[cap_name]
        except (KeyError, TypeError):
            return 1.0
        try:
            return float(getattr(cap, 'transaction_weight', 1) or 1)
        except (TypeError, ValueError):
            return 1.0

    def _select_capability(self, registered: list) -> str:
        """Pick the capability to probe with: ``argmax`` of
        ``weight / (per-cap count + 1)``.

        This is the doc's "and the capability weight is highest", and the
        *form* is deliberate. Peers and capabilities are not the same problem:
        for a peer we are trying to identify a bad arm, which is what UCB is
        for; for a capability there is nothing to identify — the question is
        how to divide a fixed probe budget across capabilities of differing
        stakes. This rule settles at ``n_cap`` proportional to ``weight``,
        which is exactly "spend more where it matters" while still covering
        everything.

        Two shapes were tried and rejected. Ranking by weight alone probes the
        heaviest capability forever, which loses coverage and leaves an
        adversary a single capability to answer correctly. Multiplying weight
        by the UCB bonus looks reasonable but allocates ``n_cap`` proportional
        to ``weight**2``, because the bonus falls off as ``1/sqrt(n)`` — with
        a weight of 8 a light capability is not selected until the heavy one
        has been probed 64 times more, so a normally-weighted trust ladder
        would silently stop exercising most of the corpus.
        """
        if not registered:
            return None
        scored = [
            ((-(self._capability_weight(name)
                / (self._probes_by_cap.get(name, 0) + 1.0)), name), name)
            for name in registered
        ]
        return min(scored, key=lambda item: item[0])[1]

    def _registered_bootstrap_caps(self) -> list:
        """The bootstrap caps actually registered locally, in canonical
        order."""
        try:
            local = self.capabilities.to_list()
        except AttributeError:
            return []
        return [n for n in BOOTSTRAP_CAPABILITY_NAMES if n in local]

    def _try_issue_probe(self, queues: dict) -> bool:
        """Issue one *directed* probe: a chosen capability, addressed to a
        chosen peer.

        Distinct from :meth:`_try_issue_pair`, which broadcasts. Addressing
        matters here because a fanned-out probe is answered by whichever peer
        replies first (``start_task`` pre-seeds ``tracker.results`` for every
        participant and ``handle_results`` forwards on the first one), so a
        broadcast cannot express "probe THIS peer" and a slow peer would never
        be probed at all.
        """
        peers = list(self.peers.all)
        if not peers:
            return False
        registered = self._registered_bootstrap_caps()
        if not registered:
            return False
        target = self._select_target(peers)
        if target is None:
            return False
        cap_name = self._select_capability(registered)
        if cap_name is None:
            return False
        cap = self.capabilities[cap_name]
        args, kwargs = self._build_task_args(cap_name)
        task = Task(TaskParameters(cap, args=args, kwargs=kwargs),
                    self.identity)
        msg = Message(CfgIds.negotiation, NegotiationProtocol.start, task,
                      to_whom=target)
        try:
            queues[CfgIds.negotiation].put(
                msg, block=True, timeout=self.q_cadence)
        except queue.Full:
            self.logger.warning(
                'BootstrapWorker: negotiation queue full, probe deferred')
            return False
        uuid_str = str(getattr(target, 'uuid', ''))
        self._probes_by_peer[uuid_str] = self._probes_by_peer.get(uuid_str, 0) + 1
        self._probes_by_cap[cap_name] = self._probes_by_cap.get(cap_name, 0) + 1
        self._probes_issued += 1
        self._counts_by_cap[cap_name] = self._counts_by_cap.get(cap_name, 0) + 1
        self.logger.debug(
            'BootstrapWorker: probe %d (cap=%s, peer=%s, n_peer=%d)',
            self._probes_issued, cap_name, uuid_str[:8],
            self._probes_by_peer[uuid_str])
        return True

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
        elapsed = (now() - self._window_start).total_seconds()
        window_done = (self._pairs_issued >= self.pairs_target
                       or elapsed > self.duration_sec)
        if not window_done:
            self._try_issue_pair(queues)
            return
        # Window closed. Historically the worker idled here forever, which
        # left the honeypot pattern applied only at cold start (R+D.md §12.7).
        if not self.continuous_enabled:
            return
        self._maybe_probe(queues)

    def _maybe_probe(self, queues: dict) -> bool:
        """Issue a directed probe if the rate limit allows it.

        Rate-limited rather than issued every tick: a probe is a real task
        round trip on both peers, and the point of continuing past the window
        is coverage over time, not volume. The first call after the window
        closes probes immediately (there is no reason to wait an interval to
        start), and every later one waits ``probe_interval_sec``.
        """
        current = now()
        if self._last_probe_at is not None:
            since = (current - self._last_probe_at).total_seconds()
            if since < self.probe_interval_sec:
                return False
        # Stamp before issuing, not after: a full negotiation queue returns
        # False from _try_issue_probe, and retrying it on every tick would
        # ignore the rate limit exactly when the node is most loaded.
        self._last_probe_at = current
        return self._try_issue_probe(queues)

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
