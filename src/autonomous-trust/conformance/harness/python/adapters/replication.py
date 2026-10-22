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

from autonomous_trust.oracle.replication import (
    CORROBORATED, DEFAULT_MAX_STATE_BYTES, ChallengeSession,
    ReplicationDeclarationError, adjudicate, bisect_adjudicate, commit_root,
    hash_chain, parse_replication, settle, should_replicate, verify)

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
        elif 'challenge' in event:
            self._challenge(model, where, event)
        elif 'declare' in event:
            self._declare(where, event)
        elif 'live_prob' in event and 'capability' in event:
            self._live_prob(model, where, event)
        elif 'replay' in event and 'capability' in event:
            self._replay(model, where, event)
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

    # --- the live declaration and game (RD_12.6 plan, Phases 1 and 2) -----

    def _declare(self, where: str, event: dict[str, Any]) -> None:
        """A declaration parsed on its own: `refused: true` pins a refusal."""
        try:
            parse_replication(event['declare'])
            refused = False
        except ReplicationDeclarationError:
            refused = True
        if refused != bool(event.get('refused', False)):
            raise AssertionError(f'{where}: refused={refused}, expected '
                                 f'{bool(event.get("refused", False))}')

    def _live_prob(self, model, where: str, event: dict[str, Any]) -> None:
        cap, want = event['capability'], float(event['live_prob'])
        actual = model.live_prob_for(cap)
        if abs(actual - want) > TOL:
            raise AssertionError(
                f'{where}: live_prob_for({cap!r})={actual!r}, expected {want!r}')

    def _replay(self, model, where: str, event: dict[str, Any]) -> None:
        cap, want = event['capability'], event['replay']
        spec = model.replay_for(cap)
        actual = None if spec is None else {'max_steps': spec.max_steps,
                                            'max_state_bytes': spec.max_state_bytes}
        if actual != want:
            raise AssertionError(
                f'{where}: replay_for({cap!r})={actual}, expected {want}')

    def _challenge(self, model, where: str, event: dict[str, Any]) -> None:
        """Play the live game: each executor answers from its own chain,
        except at the indices `lies` names; each reveals its own states at k,
        overridden by `reveal`. The `reference` stands in for re-executing the
        step (None past its end: the computation is over)."""
        spec = event['challenge']
        traces = spec.get('traces', {}) or {}
        peers = list(traces.keys())
        if len(peers) != 2:
            raise AssertionError(f'{where}: challenge needs exactly two traces')
        side = dict(zip(peers, ('a', 'b')))
        chains = {p: hash_chain(traces[p]) for p in peers}
        lies = {p: {int(i): d for i, d in (spec.get('lies', {}) or {}).get(p, {}).items()}
                for p in peers}
        session = ChallengeSession(
            len(traces[peers[0]]), commit_root(traces[peers[0]]),
            len(traces[peers[1]]), commit_root(traces[peers[1]]))
        while (step := session.pending()) is not None:
            index, owe = step
            given = {}
            for p in peers:
                if side[p] in owe:
                    given[side[p]] = lies[p].get(index, chains[p][index])
            session.answer(index, given.get('a'), given.get('b'))
        k = session.divergence
        if 'asked' in event and session.asked != list(event['asked']):
            raise AssertionError(
                f'{where}: asked={session.asked}, expected {event["asked"]}')
        if 'divergence_index' in event and k != event['divergence_index']:
            raise AssertionError(
                f'{where}: divergence_index={k}, expected {event["divergence_index"]}')
        if k is None:
            verdicts = {p: CORROBORATED for p in peers}
        else:
            reveals = {}
            for p in peers:
                st, ch = traces[p], chains[p]
                r = {'prev': ch[k - 2] if k >= 2 else None,
                     'pre': st[k - 1] if 1 <= k <= len(st) else None,
                     'state': st[k] if k < len(st) else None}
                r.update((spec.get('reveal', {}) or {}).get(p, {}))
                reveals[side[p]] = r
            reference = spec.get('reference', []) or []
            out = settle(session, reveals,
                         lambda _pre: reference[k] if k < len(reference) else None,
                         int(spec.get('max_state_bytes', DEFAULT_MAX_STATE_BYTES)))
            verdicts = {p: out[side[p]] for p in peers}
        self._check_verdicts_scores(where, event, verdicts)
