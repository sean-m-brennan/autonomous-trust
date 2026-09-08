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
"""Python adapter for the ``prequential`` conformance protocol (R+D.md §12.5).

Non-message-driven, like the ``physics``, ``calibration`` and ``bootstrap``
adapters: the scenario carries a declaration and a list of events, the adapter
loads the declaration into this runtime's estimator and replays the events in
order, carrying the outstanding-forecast and loss stores forward.

What is pinned is the RULES, not a shared call site. Python observes forecasts
from its main process (``automate.score_task_result``) and C from its
negotiation process, for the same reason the two layers before it do.

Unlike every other oracle protocol, no event here asserts a score: this layer
produces no evidence and no channel, only the weight multiplier. So the
``competence`` event asserts the multiplier and the ``weight`` event the
composed integer weight the reputation process would fold a score in at ---
which is where the two runtimes could differ without either looking wrong,
since ``floor(x + 0.5)`` is neither language's native rounding.

Both resolution paths are exercised, because the design has two: a ``report``
event goes through the physics-declared path (a later result for the
quantity's reporting capability settles the forecast) and a ``resolve`` event
through the explicit one, for a ground truth AT never sees as a task result.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from autonomous_trust.core.physics import parse_physics
from autonomous_trust.core.prequential import (NEUTRAL_COMPETENCE,
                                               PrequentialEstimator,
                                               parse_prequential, weight_round)

from ...common.scenario_loader import Case

#: Loss and weight comparisons. Tight enough that a different formula fails
#: and loose enough that the last ulp of an `exp` does not decide a run --- the
#: two runtimes both go to libm, but not necessarily to the same libm.
TOL = 1e-9


class PrequentialAdapter:
    """Replays a prequential scenario against this runtime's estimator."""

    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    def run_scenario(self, case: Case) -> None:
        fixtures = case.data.get('fixtures', {}) or {}
        decl = fixtures.get('prequential')
        if decl is None:
            raise AssertionError(
                'prequential scenario needs fixtures.prequential')
        physics = parse_physics(fixtures.get('physics') or {'version': 1})
        est = PrequentialEstimator(parse_prequential(decl),
                                   physics_model=physics)

        for index, event in enumerate(fixtures.get('events', []) or [],
                                      start=1):
            self._event(est, index, event)

    # ------------------------------------------------------------------
    def _event(self, est, index: int, event: dict[str, Any]) -> None:
        where = f'event {index}'
        if 'forecast' in event:
            self._forecast(est, where, event)
        elif 'report' in event:
            spec = event['report']
            got = est.settle(spec.get('capability'), spec.get('result'),
                             event.get('subject'), float(event['t']))
            self._settled(where, got, event)
        elif 'resolve' in event:
            spec = event['resolve']
            got = est.resolve(spec.get('quantity'), spec.get('value'),
                              float(event['t']),
                              reporter=spec.get('reporter'))
            self._settled(where, got, event)
        elif 'outstanding' in event:
            spec = event['outstanding']
            pending = est._outstanding.get(spec['quantity'])
            self._count(where, spec['quantity'], len(pending) if pending
                        else 0, int(spec['count']), 'outstanding forecast(s)')
        elif 'outcomes' in event:
            spec = event['outcomes']
            ring = est._losses.get(spec['subject'], {}).get(spec['capability'])
            self._count(where, f'{spec["subject"]}/{spec["capability"]}',
                        len(ring) if ring else 0, int(spec['count']),
                        'resolved loss(es)')
        elif 'competence' in event:
            spec = event['competence']
            got = est.competence(spec.get('subject'), spec.get('capability'))
            want = float(event['value'])
            # The neutral case is EXACT, not approximate: "the authored
            # transaction_weight, verbatim" is the documented behaviour, and a
            # multiplier of 1.0 + 1e-12 would silently perturb a weight the
            # operator authored.
            if want == NEUTRAL_COMPETENCE and got != NEUTRAL_COMPETENCE:
                raise AssertionError(
                    f'{where}: expected exactly the neutral multiplier, '
                    f'got {got!r}')
            if abs(got - want) > TOL:
                raise AssertionError(
                    f'{where}: competence {got}, expected {want}')
        elif 'weight' in event:
            spec = event['weight']
            authored = int(spec['transaction_weight'])
            competence = est.competence(spec.get('subject'),
                                        spec.get('capability'))
            got = max(1, weight_round(float(authored) * competence))
            want = int(event['value'])
            if got != want:
                raise AssertionError(
                    f'{where}: authored {authored} x {competence} composed to '
                    f'weight {got}, expected {want}')
        elif 'aggregate' in event:
            self._aggregate(est, where, event)
        elif 'regret' in event:
            self._regret(est, where, event)
        elif 'peer_regret' in event:
            self._peer_regret(est, where, event)
        else:
            raise AssertionError(f'{where}: unrecognised event {sorted(event)}')

    # ------------------------------------------------------------------
    def _forecast(self, est, where: str, event: dict[str, Any]) -> None:
        spec = dict(event['forecast'])
        capability = spec.pop('capability', None)
        # An empty spec means "declared predictive and attached nothing",
        # which is a distinct row from "attached a malformed box" -- and the
        # estimator is entitled to tell them apart, so the fixture has to be
        # able to say which one it means.
        prediction = spec if spec else None
        got = bool(est.observe(capability, prediction, event.get('subject'),
                               float(event['t'])))
        want = bool(event['recorded'])
        if got != want:
            raise AssertionError(
                f'{where}: forecast {"recorded" if got else "rejected"}, '
                f'expected {"recorded" if want else "rejected"}')

    def _settled(self, where: str, got: int, event: dict[str, Any]) -> None:
        want = int(event['settled'])
        if got != want:
            raise AssertionError(
                f'{where}: settled {got} forecast(s), expected {want}')

    def _count(self, where: str, what: str, got: int, want: int,
               noun: str) -> None:
        if got != want:
            raise AssertionError(
                f'{where}: {what} has {got} {noun}, expected {want}')

    def _aggregate(self, est, where: str, event: dict[str, Any]) -> None:
        spec = event['aggregate']
        agg = est.combine(spec['quantity'], float(spec.get('now', 0.0)))
        if event.get('absent'):
            if agg is not None:
                raise AssertionError(
                    f'{where}: expected no aggregate, got {agg}')
            return
        if agg is None:
            raise AssertionError(f'{where}: expected an aggregate, got none')
        for key in ('lo', 'hi'):
            want = [float(v) for v in event[key]]
            got = list(agg[key])
            if len(got) != len(want) or any(
                    abs(g - w) > TOL for g, w in zip(got, want)):
                raise AssertionError(
                    f'{where}: aggregate {key} {got}, expected {want}')
        if 'contributors' in event:
            got_n = len(agg['contributors'])
            if got_n != int(event['contributors']):
                raise AssertionError(
                    f'{where}: aggregate has {got_n} contributor(s), '
                    f'expected {event["contributors"]}')
        if 'weights' in event:
            want_w = [float(v) for v in event['weights']]
            got_w = [float(c['weight']) for c in agg['contributors']]
            if len(got_w) != len(want_w) or any(
                    abs(g - w) > TOL for g, w in zip(got_w, want_w)):
                raise AssertionError(
                    f'{where}: aggregate weights {got_w}, expected {want_w}')

    def _regret(self, est, where: str, event: dict[str, Any]) -> None:
        spec = event['regret']
        report = est.regret(spec['quantity'])
        if event.get('absent'):
            if report is not None:
                raise AssertionError(
                    f'{where}: expected no regret report, got {report}')
            return
        if report is None:
            raise AssertionError(f'{where}: expected a regret report, got none')
        for key in ('rounds', 'experts', 'saturated_rounds'):
            if key in event and int(report[key]) != int(event[key]):
                raise AssertionError(
                    f'{where}: {key} {report[key]}, expected {event[key]}')
        for key in ('mixture_loss', 'aggregate_loss'):
            if key in event and abs(report[key] - float(event[key])) > TOL:
                raise AssertionError(
                    f'{where}: {key} {report[key]!r}, expected {event[key]!r}')
        if event.get('bound_holds'):
            # The guarantee, checked rather than quoted: for every peer, the
            # mixture's realized excess over that peer's own loss on the
            # rounds that peer was awake stays under Hedge's bound. Asserted
            # per peer because the sleeping-experts claim IS per specialist.
            for peer, row in report['peers'].items():
                if not row['realized'] < row['bound']:
                    raise AssertionError(
                        f'{where}: realized regret {row["realized"]!r} '
                        f'against {peer} is not below the bound '
                        f'{row["bound"]!r}')

    def _peer_regret(self, est, where: str, event: dict[str, Any]) -> None:
        spec = event['peer_regret']
        report = est.regret(spec['quantity'])
        if report is None:
            raise AssertionError(f'{where}: no regret report to read')
        row = report['peers'].get(spec['peer'])
        if row is None:
            raise AssertionError(
                f'{where}: {spec["peer"]} is not in the regret report')
        if 'rounds' in event and int(row['rounds']) != int(event['rounds']):
            raise AssertionError(
                f'{where}: {spec["peer"]} was awake {row["rounds"]} round(s), '
                f'expected {event["rounds"]}')
        for key in ('cumulative_loss', 'bound'):
            if key in event and abs(row[key] - float(event[key])) > TOL:
                raise AssertionError(
                    f'{where}: {spec["peer"]} {key} {row[key]!r}, expected '
                    f'{event[key]!r}')
