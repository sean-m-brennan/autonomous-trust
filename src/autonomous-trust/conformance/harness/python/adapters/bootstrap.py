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
"""

from __future__ import annotations

import os
import queue
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

from autonomous_trust.core.bootstrap_capabilities import (
    BOOTSTRAP_CAPABILITY_NAMES, register_bootstrap_capabilities,
)
from autonomous_trust.core.bootstrap_worker import BootstrapWorker
from autonomous_trust.core.capabilities import Capabilities
from autonomous_trust.core.system import CfgIds

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
        bs = fixtures.get('bootstrap') or {}
        seed = int(bs.get('seed', 12345))
        ticks = int(bs.get('ticks', 30))
        pairs_target = int(bs.get('pairs_target', ticks))
        duration_sec = float(bs.get('duration_sec', 999.0))

        participants = spec.get('participants') or []
        host = next((p for p in participants if p.get('role') == 'new_node'),
                    participants[0] if participants else None)
        if host is None:
            raise AssertionError('bootstrap scenario needs at least one participant')
        peer_count = max(0, len(participants) - 1)

        worker = self._build_worker(seed, pairs_target, duration_sec, peer_count)
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

    # -----------------------------------------------------------------------
    def _build_worker(self, seed: int, pairs_target: int, duration_sec: float,
                      peer_count: int) -> BootstrapWorker:
        """Construct a BootstrapWorker with the minimum-viable configs, seeded
        from the fixture. Mirrors test_bootstrap_worker._make_worker; the
        AT_BOOTSTRAP_* env is set across construction (the worker reads it in
        __init__) and restored afterwards so scenarios don't leak state."""
        env = {
            'AT_BOOTSTRAP_SEED': str(seed),
            'AT_BOOTSTRAP_PAIRS': str(pairs_target),
            'AT_BOOTSTRAP_DURATION_SEC': str(duration_sec),
            'AT_BOOTSTRAP_DISABLED': None,  # ensure not disabled
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
            identity = SimpleNamespace(uuid=str(uuid4()))
            peers = SimpleNamespace(
                all=[SimpleNamespace(uuid=str(uuid4()),
                                     nickname=f'peer-{i}')
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
