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
"""Conformance adapter for the physical-consistency layer (R+D.md §12.2).

A ``physics`` scenario declares a model in ``fixtures.physics`` -- the same
shape a ``physics.json`` file carries -- and a list of ``fixtures.claims``,
each ``{capability, result, subject, t}``. Every row is fed through this
runtime's checker in order, carrying the observation store forward, and the
verdict, score and evidence channel are asserted per row.

What is pinned is the RULES, not a shared call site. The two runtimes check in
different processes for the same reason they score probes in different ones
(R+D.md §12.7): the judgment needs what the requestor asked for, and each
runtime keeps that record in a different place. Python's checker is reached
through ``automate.score_task_result``; C's through
``negotiation_score_task_result``.

Why the verdict is asserted alongside the score. ``none`` is not "scored zero",
it is "this layer has nothing to say", and the caller then falls through to its
completion and certificate arms. Pinning the score alone would let a runtime
that returned ``implicated`` with a 0.1 score look identical to one that
refuted -- and the difference between those two is the whole of the diagnosis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from autonomous_trust.core.physics import (IMPLICATED_SCORE, REFUTED_SCORE,
                                           PhysicsChecker, parse_physics)
from autonomous_trust.core.reputation import (TX_CHANNEL_PHYSICAL,
                                              TX_CHANNEL_SWARM_DISAGREEMENT)

from ...common.scenario_loader import Case

#: verdict name -> (score, channel) for the two speaking verdicts. The checker
#: returns only the pair, so this is how the adapter recovers the verdict name
#: the scenario spells: the mapping is one-to-one by construction, and
#: asserting through it catches a runtime that returned the right number on the
#: wrong channel.
_VERDICTS = {
    'refuted': (REFUTED_SCORE, TX_CHANNEL_PHYSICAL),
    'implicated': (IMPLICATED_SCORE, TX_CHANNEL_SWARM_DISAGREEMENT),
}


class PhysicsAdapter:
    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    # -- kinds this adapter does not handle ---------------------------------
    def run_wire_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('physics adapter handles kind:scenario only')

    def run_crypto_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('physics adapter handles kind:scenario only')

    def run_agreement_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('physics adapter handles kind:scenario only')

    def run_negative(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('physics adapter handles kind:scenario only')

    # -- the physics scenario -----------------------------------------------
    def run_scenario(self, case: Case) -> None:
        spec = case.data
        fixtures = spec.get('fixtures') or {}
        declaration = fixtures.get('physics')
        if declaration is None:
            raise AssertionError('physics scenario needs fixtures.physics')
        rows = fixtures.get('claims') or []

        participants = spec.get('participants') or []
        host = next((p for p in participants if p.get('role') == 'new_node'),
                    participants[0] if participants else None)
        if host is None:
            raise AssertionError('physics scenario needs a participant')

        checker = PhysicsChecker(parse_physics(declaration))
        verdicts: list[str] = []
        scores: list[Any] = []
        channels: list[Any] = []
        for row in rows:
            subject = row.get('subject')
            verdict = checker.check(
                row.get('capability'), row.get('result'),
                subject=None if subject is None else str(subject),
                now=float(row.get('t', 0.0)))
            if verdict is None:
                verdicts.append('none')
                scores.append(None)
                channels.append(None)
                continue
            score, channel = verdict
            name = next((k for k, v in _VERDICTS.items()
                         if v == (score, channel)), None)
            if name is None:
                raise AssertionError(
                    f'row {len(verdicts)}: checker returned an unmapped '
                    f'(score, channel) pair {(score, channel)!r}; the layer '
                    f'may only speak to refute or to implicate')
            verdicts.append(name)
            scores.append(score)
            channels.append(channel)

        expected = (spec.get('expected_state') or {}).get(host['id'], {})
        self._assert_list(host['id'], rows, 'claim_verdicts', expected,
                          verdicts, lambda a, b: a == b)
        self._assert_list(host['id'], rows, 'claim_scores', expected, scores,
                          lambda a, b: (a is None and b is None) or
                          (a is not None and b is not None
                           and abs(float(a) - float(b)) < 1e-9))
        self._assert_list(host['id'], rows, 'claim_channels', expected,
                          channels, lambda a, b: a == b)

    @staticmethod
    def _assert_list(host_id, rows, key, expected, got, eq) -> None:
        if key not in expected:
            return
        want = list(expected[key])
        assert len(want) == len(got), (
            f'{host_id}: {len(got)} claims checked, {len(want)} {key} pinned')
        for i, (g, w) in enumerate(zip(got, want)):
            assert eq(g, w), (
                f'{host_id}: row {i} '
                f'({rows[i].get("capability")} -> {rows[i].get("result")!r} '
                f'from {rows[i].get("subject")!r}) reported {key[:-1]} {g!r}, '
                f'expected {w!r}')
