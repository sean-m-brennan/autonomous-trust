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
"""Python adapter for the ``calibration`` conformance protocol (R+D.md §12.4).

Non-message-driven, like the ``physics`` and ``bootstrap`` adapters: the
scenario carries a declaration and a list of events, the adapter loads the
declaration into this runtime's auditor and replays the events in order,
carrying the outstanding-prediction and outcome stores forward.

What is pinned is the RULES, not a shared call site. Python audits from its
main process (``automate.score_task_result``) and C from its negotiation
process, for the same reason the physics layer does.

Both resolution paths are exercised, because the design has two: a ``report``
event goes through the physics-declared path (a later result for the quantity's
reporting capability settles the prediction), and a ``resolve`` event through
the explicit one, for a ground truth AT never sees as a task result.

The ``outstanding`` and ``outcomes`` events assert STORE state rather than a
verdict. They earn their place because two of the rules have no observable
effect on any single score: a peer's own report not settling its own
prediction, and an expired prediction being dropped rather than counted as a
miss. Both are invisible from the verdict alone -- silence is also what a
correctly-audited honest peer produces -- so a runtime that got either wrong
would pass a verdict-only scenario.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from autonomous_trust.core.calibration import (ABSENT_SCORE,
                                               OVERCONFIDENT_SCORE,
                                               CalibrationAuditor,
                                               parse_calibration)
from autonomous_trust.core.physics import parse_physics
from autonomous_trust.core.reputation import TX_CHANNEL_CALIBRATION

from ...common.scenario_loader import Case


class CalibrationAdapter:
    """Replays a calibration scenario against this runtime's auditor."""

    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    def run_scenario(self, case: Case) -> None:
        fixtures = case.data.get('fixtures', {}) or {}
        decl = fixtures.get('calibration')
        if decl is None:
            raise AssertionError('calibration scenario needs fixtures.calibration')
        model = parse_calibration(decl)
        physics = parse_physics(fixtures.get('physics') or {'version': 1})
        auditor = CalibrationAuditor(model, physics_model=physics)

        for index, event in enumerate(fixtures.get('events', []) or [], start=1):
            self._event(auditor, physics, index, event)

    # ------------------------------------------------------------------
    def _event(self, auditor, physics, index: int, event: dict[str, Any]) -> None:
        where = f'event {index}'
        if 'predict' in event:
            self._predict(auditor, where, event)
        elif 'report' in event:
            spec = event['report']
            auditor.settle(spec.get('capability'), spec.get('result'),
                           event.get('subject'), float(event['t']))
        elif 'resolve' in event:
            spec = event['resolve']
            auditor.resolve(spec.get('quantity'), spec.get('value'),
                            float(event['t']))
        elif 'outstanding' in event:
            spec = event['outstanding']
            pending = auditor._outstanding.get(spec['quantity'])
            got = len(pending) if pending else 0
            want = int(spec['count'])
            if got != want:
                raise AssertionError(
                    f'{where}: {spec["quantity"]} has {got} outstanding '
                    f'prediction(s), expected {want}')
        elif 'outcomes' in event:
            spec = event['outcomes']
            ring = auditor._outcomes.get(spec['subject'], {}).get(
                spec['capability'])
            got_n = len(ring) if ring else 0
            got_hits = sum(1 for hit in ring if hit) if ring else 0
            if got_n != int(spec['count']) or got_hits != int(spec['hits']):
                raise AssertionError(
                    f'{where}: {spec["subject"]}/{spec["capability"]} has '
                    f'{got_hits}/{got_n} resolutions, expected '
                    f'{spec["hits"]}/{spec["count"]}')
        else:
            raise AssertionError(f'{where}: unrecognised event {sorted(event)}')

    def _predict(self, auditor, where: str, event: dict[str, Any]) -> None:
        spec = dict(event['predict'])
        capability = spec.pop('capability', None)
        # An empty spec means "declared predictive and attached nothing", which
        # is a distinct row from "attached a malformed set" -- and the auditor
        # is entitled to tell them apart, so the fixture has to be able to say
        # which one it means.
        prediction = spec if spec else None
        verdict = auditor.assess(capability, prediction, event.get('subject'),
                                 float(event['t']))

        want_score = event.get('score')
        want_channel = event.get('channel')
        if want_score is None:
            if verdict is not None:
                raise AssertionError(
                    f'{where}: expected no verdict, got {verdict}')
            if want_channel is not None:
                raise AssertionError(
                    f'{where}: a null score cannot carry channel '
                    f'{want_channel!r}')
            return

        if verdict is None:
            raise AssertionError(
                f'{where}: expected {want_score} on {want_channel}, got no '
                'verdict')
        score, channel = verdict
        if abs(score - float(want_score)) > 1e-9:
            raise AssertionError(
                f'{where}: scored {score}, expected {want_score}')
        if channel != want_channel:
            raise AssertionError(
                f'{where}: scored on {channel!r}, expected {want_channel!r}')
        # The score alone does not identify the verdict to a reader, and the
        # two this layer produces mean different things: cross-check that the
        # number is one this layer is entitled to return on this channel.
        if channel != TX_CHANNEL_CALIBRATION:
            raise AssertionError(
                f'{where}: {channel!r} is not the calibration channel')
        if score not in (OVERCONFIDENT_SCORE, ABSENT_SCORE):
            raise AssertionError(
                f'{where}: {score} is not a calibration verdict score')
