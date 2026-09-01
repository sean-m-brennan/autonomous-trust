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

"""Bootstrap-protocol conformance adapter (kind: scenario, protocol: bootstrap).

Pins the BootstrapWorker coverage contract (doc/architecture/trust-tiers.md
§6.5): a freshly-admitted peer, once it has peers, runs a seeded window of
pairwise invitations that exercises each of the three tier-0 ``at.*``
capabilities at least once.

The scenario is not message-driven like the others — the single step is a
trigger; the adapter builds the worker from ``fixtures.bootstrap`` (seed,
ticks, pairs_target, duration_sec), ticks it ``ticks`` times against a peer
set sized from the participant list, and asserts the per-host observable.
The C adapter mirrors this against ``bootstrap_worker_t``; the contract is
the RNG-agnostic coverage set (all three caps fired), so the two impls need
not produce identical selection sequences.

Observables (per host participant, in ``expected_state``):

- ``bootstrap_caps_fired``: number of distinct bootstrap caps that fired at
  least once over the run (3 == full coverage).
- ``pairs_issued``: total invitations issued (optional; equals the seeded
  tick count when the window stays open and the target is not hit first).

Continuous probing (R+D.md §12.7) is driven by two extra fixture keys and
observed by three more. ``continuous: true`` lets the worker keep probing once
the window has closed, and ``probe_interval_sec: 0`` removes the rate limit so
a fixed tick count yields a fixed probe count. It defaults to OFF here so the
window scenario keeps measuring the window alone.

- ``probes_issued``: directed probes issued after the window closed.
- ``distinct_peers_probed``: how many different peers were probed. This is the
  allocation contract: probes must spread rather than pile onto one peer.
- ``probe_caps_fired``: distinct capabilities used across those probes.

Unlike the window's coverage pin, the probe allocation is deterministic in BOTH
twins (argmax over counts, no PRNG), so these are aggregate rather than
sequence assertions only because the two runtimes index peers differently —
Python by uuid ordering, C by position.

Result scoring (R+D.md §12.7 / §12.8) is the other half of a probe and has its
own fixture: ``fixtures.scored_results`` is a list of ``{capability, kwargs,
result}`` rows, each fed through this runtime's requestor-side scorer, with
``result_scores`` and ``result_channels`` asserted per row. The two runtimes
cannot share a call site — Python scores in its main process
(``automate.score_task_result``), C in its negotiation process, because that is
where each keeps the requestor's record of what it asked — so what is pinned is
the rules. ``kwargs`` is the challenge the REQUESTOR retained, never anything
read back off the reply; see ``TaskResult.attach_requested_parameters``.
"""

from __future__ import annotations

import os
import queue
import sys
from pathlib import Path
import hashlib
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock
from uuid import NAMESPACE_URL, uuid5

from autonomous_trust.core.bootstrap_capabilities import (
    BOOTSTRAP_CAPABILITY_NAMES, register_bootstrap_capabilities,
)
from autonomous_trust.core.bootstrap_worker import BootstrapWorker
from autonomous_trust.core.automate import score_task_result
from autonomous_trust.core.capabilities import Capabilities
from autonomous_trust.core.negotiation import TaskResult
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.system import CfgIds

#: Namespace for the adapter's derived participant uuids.
_NS = uuid5(NAMESPACE_URL, 'https://autonomous-trust/conformance/bootstrap')

from ...common.scenario_loader import Case


class BootstrapAdapter:
    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    # -- kinds this adapter does not handle ---------------------------------
    def run_wire_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('bootstrap adapter handles kind:scenario only')

    def run_crypto_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('bootstrap adapter handles kind:scenario only')

    def run_agreement_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('bootstrap adapter handles kind:scenario only')

    def run_negative(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('bootstrap adapter handles kind:scenario only')

    # -- the bootstrap scenario ---------------------------------------------
    def run_scenario(self, case: Case) -> None:
        spec = case.data
        fixtures = spec.get('fixtures') or {}
        # Result scoring is its own trigger: a scenario carrying
        # `scored_results` is about judging replies, not about issuing probes,
        # and the two never appear together.
        if fixtures.get('scored_results'):
            self._score_results(spec, fixtures['scored_results'])
            return
        bs = fixtures.get('bootstrap') or {}
        seed = int(bs.get('seed', 12345))
        ticks = int(bs.get('ticks', 30))
        pairs_target = int(bs.get('pairs_target', ticks))
        duration_sec = float(bs.get('duration_sec', 999.0))
        continuous = bool(bs.get('continuous', False))
        probe_interval_sec = float(bs.get('probe_interval_sec', 0.0))

        participants = spec.get('participants') or []
        host = next((p for p in participants if p.get('role') == 'new_node'),
                    participants[0] if participants else None)
        if host is None:
            raise AssertionError('bootstrap scenario needs at least one participant')
        peer_count = max(0, len(participants) - 1)

        worker = self._build_worker(seed, pairs_target, duration_sec,
                                    peer_count, continuous, probe_interval_sec)
        queues = {CfgIds.negotiation: queue.Queue()}
        for _ in range(ticks):
            worker._tick(queues)

        expected = (spec.get('expected_state') or {}).get(host['id'], {})
        caps_fired = sum(
            1 for name in BOOTSTRAP_CAPABILITY_NAMES
            if worker._counts_by_cap.get(name, 0) >= 1
        )
        if 'bootstrap_caps_fired' in expected:
            want = int(expected['bootstrap_caps_fired'])
            assert caps_fired == want, (
                f"{host['id']}: bootstrap_caps_fired={caps_fired}, expected "
                f"{want} (counts={worker._counts_by_cap})"
            )
        if 'pairs_issued' in expected:
            want = int(expected['pairs_issued'])
            assert worker._pairs_issued == want, (
                f"{host['id']}: pairs_issued={worker._pairs_issued}, "
                f"expected {want}"
            )
        if 'probes_issued' in expected:
            want = int(expected['probes_issued'])
            assert worker._probes_issued == want, (
                f"{host['id']}: probes_issued={worker._probes_issued}, "
                f"expected {want}"
            )
        if 'distinct_peers_probed' in expected:
            want = int(expected['distinct_peers_probed'])
            got = sum(1 for n in worker._probes_by_peer.values() if n >= 1)
            assert got == want, (
                f"{host['id']}: distinct_peers_probed={got}, expected {want} "
                f"(counts={worker._probes_by_peer})"
            )
        if 'probe_caps_fired' in expected:
            want = int(expected['probe_caps_fired'])
            got = sum(1 for name in BOOTSTRAP_CAPABILITY_NAMES
                      if worker._probes_by_cap.get(name, 0) >= 1)
            assert got == want, (
                f"{host['id']}: probe_caps_fired={got}, expected {want} "
                f"(counts={worker._probes_by_cap})"
            )

    # -----------------------------------------------------------------------
    def _score_results(self, spec: dict[str, Any], rows: list) -> None:
        """Score each row through the production scorer and assert the pins.

        A ``TaskResult`` is built per row with the requested capability and
        kwargs stamped on it, which is the shape the requestor's negotiation
        process produces (``attach_requested_parameters``) — deliberately not
        a hand-rolled call into the verifier, so this pins the same
        fall-through to completion scoring that production takes for a
        capability with no known answer.
        """
        participants = spec.get('participants') or []
        host = next((p for p in participants if p.get('role') == 'new_node'),
                    participants[0] if participants else None)
        if host is None:
            raise AssertionError('bootstrap scenario needs at least one participant')

        # Scored with the ZKP extension treated as ABSENT, which is the only
        # arm the C twin can reach: that runtime attaches no proofs at all, so
        # `certificate` is not a verdict it can produce. Left ambient, a
        # non-probe row scores 0.8/task_outcome where the extension is unbuilt
        # and 0.3/certificate where it is built, and the corpus would then pin
        # a property of the machine rather than of the runtime -- passing here
        # and failing (asymmetric) on a host that has the extension. The
        # defining module is patched rather than the import site, because
        # score_task_result reads the flag from its own globals.
        automate_mod = sys.modules[score_task_result.__module__]
        had_zkp = getattr(automate_mod, 'ZKP_AVAILABLE')
        setattr(automate_mod, 'ZKP_AVAILABLE', False)
        scores: list[float] = []
        channels: list[str] = []
        try:
            for row in rows:
                result = TaskResult(
                    None, row.get('result'), requestor=None,
                    requested_capability_name=row.get('capability'),
                    requested_kwargs=row.get('kwargs') or {})
                score, channel = score_task_result(result)
                scores.append(score)
                channels.append(channel)
        finally:
            setattr(automate_mod, 'ZKP_AVAILABLE', had_zkp)

        expected = (spec.get('expected_state') or {}).get(host['id'], {})
        if 'result_scores' in expected:
            want = [float(v) for v in expected['result_scores']]
            assert len(want) == len(scores), (
                f"{host['id']}: {len(scores)} results scored, "
                f"{len(want)} pinned")
            for i, (got, exp) in enumerate(zip(scores, want)):
                assert abs(got - exp) < 1e-9, (
                    f"{host['id']}: row {i} "
                    f"({rows[i].get('capability')} -> {rows[i].get('result')!r}) "
                    f"scored {got}, expected {exp}")
        if 'result_channels' in expected:
            want_ch = list(expected['result_channels'])
            assert len(want_ch) == len(channels), (
                f"{host['id']}: {len(channels)} results scored, "
                f"{len(want_ch)} channels pinned")
            for i, (got, exp) in enumerate(zip(channels, want_ch)):
                assert got == exp, (
                    f"{host['id']}: row {i} "
                    f"({rows[i].get('capability')}) reported channel "
                    f"{got!r}, expected {exp!r}")

    # -----------------------------------------------------------------------
    @staticmethod
    def _identity(label: str, idx: int) -> Identity:
        """A deterministic Identity for `label`. Same shape as the reputation
        adapter's participants: derived keys so a run is reproducible."""
        sig = hashlib.sha256(b'bootstrap:sig:' + label.encode()).hexdigest().encode('ascii')
        enc = hashlib.sha256(b'bootstrap:enc:' + label.encode()).hexdigest().encode('ascii')
        return Identity(
            uuid5(_NS, f'bootstrap:{label}'), f'10.0.70.{idx + 1}',
            f'{label}.bs',
            Signature(sig, public_only=False),
            Encryptor(enc, public_only=False),
            label, False, 0, 'authority',
        )

    def _build_worker(self, seed: int, pairs_target: int, duration_sec: float,
                      peer_count: int, continuous: bool = False,
                      probe_interval_sec: float = 0.0) -> BootstrapWorker:
        """Construct a BootstrapWorker with the minimum-viable configs, seeded
        from the fixture. Mirrors test_bootstrap_worker._make_worker; the
        AT_BOOTSTRAP_* env is set across construction (the worker reads it in
        __init__) and restored afterwards so scenarios don't leak state."""
        env = {
            'AT_BOOTSTRAP_SEED': str(seed),
            'AT_BOOTSTRAP_PAIRS': str(pairs_target),
            'AT_BOOTSTRAP_DURATION_SEC': str(duration_sec),
            'AT_BOOTSTRAP_DISABLED': None,  # ensure not disabled
            # Explicit rather than inherited: the window scenarios must not
            # start counting probes just because continuous probing shipped.
            'AT_PROBE_CONTINUOUS_DISABLED': None if continuous else '1',
            'AT_PROBE_INTERVAL_SEC': str(probe_interval_sec),
        }
        saved = {k: os.environ.get(k) for k in env}
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        try:
            caps = Capabilities()
            register_bootstrap_capabilities(caps)
            # Real Identity objects, not stubs. A directed probe addresses
            # its peer via Message(to_whom=peer), and Message._normalize_to_whom
            # accepts an Identity (or a list of them) and raises on anything
            # else -- a SimpleNamespace fails outright, and a MagicMock only
            # passes by accident, because it answers hasattr('__iter__') and
            # len() == 0 and so slips through as an empty recipient list. Both
            # would make this scenario prove less than it appears to.
            identity = self._identity('self', 0)
            peers = SimpleNamespace(
                all=[self._identity(f'peer-{i}', i + 1)
                     for i in range(peer_count)])
            configurations = {
                CfgIds.identity: identity,
                CfgIds.peers: peers,
                CfgIds.capabilities: caps,
                'processes': [],
            }
            return BootstrapWorker(
                configurations, MagicMock(), queue.Queue(),
                dependencies=[], suppress_log=True)
        finally:
            for k, original in saved.items():
                if original is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = original
