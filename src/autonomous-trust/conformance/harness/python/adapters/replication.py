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
"""Python adapter for the ``replication`` conformance protocol (R+D.md §12.6).

Non-message-driven, like the ``physics``, ``calibration`` and ``prequential``
adapters: the scenario carries a declaration (``fixtures.replication``) and a
list of events, and the adapter loads the declaration into this runtime and
evaluates each event in order.

What is pinned is the RULES, not a shared call site. The sampling decision is
pure -- one SplitMix64 draw against a probability -- so the two runtimes must
decide identically for a given (probability, seed): a task one replicates and
the other skips would let a peer's exposure depend on which implementation was
watching, which is the one thing sampling cannot tolerate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from autonomous_trust.core.replication import (adjudicate, bisect_adjudicate,
                                               commit_root, parse_replication,
                                               should_replicate, verify)

from ...common.scenario_loader import Case

#: Draw comparison tolerance. The draw is exact integer arithmetic scaled by a
#: power of two, so this is tight; it exists only so a pinned literal need not
#: carry all 17 digits.
TOL = 1e-12


class ReplicationAdapter:
    """Replays a replication scenario against this runtime's sampler."""

    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    def run_scenario(self, case: Case) -> None:
        fixtures = case.data.get('fixtures', {}) or {}
        decl = fixtures.get('replication')
        if decl is None:
            raise AssertionError(
                'replication scenario needs fixtures.replication')
        model = parse_replication(decl)

        for index, event in enumerate(fixtures.get('events', []) or [],
                                      start=1):
            self._event(model, index, event)

    # ------------------------------------------------------------------
    def _event(self, model, index: int, event: dict[str, Any]) -> None:
        where = f'event {index}'
        if 'sample' in event:
            self._sample(model, where, event)
        elif 'adjudicate' in event:
            self._adjudicate(model, where, event)
        elif 'bisect' in event:
            self._bisect(model, where, event)
        elif 'prob' in event and 'capability' in event:
            # A bare probability-lookup assertion (no draw), for rows that pin
            # only the declaration's resolution of a capability to its number.
            self._prob(model, where, event)
        else:
            raise AssertionError(f'{where}: unrecognised event {event!r}')

    def _sample(self, model, where: str, event: dict[str, Any]) -> None:
        spec = event['sample']
        cap = spec.get('capability')
        if 'seed' not in spec:
            raise AssertionError(f'{where}: sample needs a seed')
        seed = int(spec['seed'])
        prob = (float(spec['prob']) if 'prob' in spec
                else model.prob_for(cap))
        decision, draw = should_replicate(prob, seed)

        if 'replicate' in event:
            expected = bool(event['replicate'])
            if decision != expected:
                raise AssertionError(
                    f'{where}: replicate={decision}, expected {expected} '
                    f'(prob={prob}, seed={seed}, draw={draw!r})')
        if 'draw' in event:
            want = float(event['draw'])
            if abs(draw - want) > TOL:
                raise AssertionError(
                    f'{where}: draw={draw!r}, expected {want!r}')
        if 'effective_prob' in event:
            want = float(event['effective_prob'])
            if abs(prob - want) > TOL:
                raise AssertionError(
                    f'{where}: effective_prob={prob!r}, expected {want!r}')

    def _adjudicate(self, model, where: str, event: dict[str, Any]) -> None:
        spec = event['adjudicate']
        cap = spec.get('capability')
        tol = (float(spec['tolerance']) if 'tolerance' in spec
               else model.tolerance_for(cap))
        results = [(r['peer'], r['value']) for r in spec.get('results', [])]
        verdicts = adjudicate(results, tolerance=tol)
        self._check_verdicts_scores(where, event, verdicts)

    def _bisect(self, model, where: str, event: dict[str, Any]) -> None:
        spec = event['bisect']
        traces = spec.get('traces', {}) or {}
        peers = list(traces.keys())
        if len(peers) != 2:
            raise AssertionError(
                f'{where}: bisect needs exactly two traces, got {peers}')
        pa, pb = peers[0], peers[1]
        reference = spec.get('reference', []) or []
        k, verdicts = bisect_adjudicate(pa, traces[pa], pb, traces[pb],
                                        reference)

        if 'divergence_index' in event:
            want = event['divergence_index']
            if k != want:
                raise AssertionError(
                    f'{where}: divergence_index={k}, expected {want}')
        if 'roots' in event:
            for peer, want_root in event['roots'].items():
                got = commit_root(traces[peer])
                if got != want_root:
                    raise AssertionError(
                        f'{where}: root[{peer}]={got}, expected {want_root}')
        self._check_verdicts_scores(where, event, verdicts)

    def _check_verdicts_scores(self, where: str, event: dict[str, Any],
                               verdicts: dict[str, str]) -> None:
        if 'verdicts' in event:
            want = event['verdicts']
            if verdicts != want:
                raise AssertionError(
                    f'{where}: verdicts={verdicts}, expected {want}')
        if 'scores' in event:
            # Only the executors the scenario names; a verdict that maps to no
            # score (`dispute`, `single`) is ABSENT from the expected map,
            # which is exactly what verify() returning None pins.
            want = event['scores']
            actual: dict[str, list] = {}
            for peer, verdict in verdicts.items():
                scored = verify(verdict)
                if scored is not None:
                    actual[peer] = [scored[0], scored[1]]
            want_norm = {k: [float(v[0]), v[1]] for k, v in want.items()}
            if actual != want_norm:
                raise AssertionError(
                    f'{where}: scores={actual}, expected {want_norm}')

    def _prob(self, model, where: str, event: dict[str, Any]) -> None:
        cap = event['capability']
        want = float(event['prob'])
        actual = model.prob_for(cap)
        if abs(actual - want) > TOL:
            raise AssertionError(
                f'{where}: prob_for({cap!r})={actual!r}, expected {want!r}')
