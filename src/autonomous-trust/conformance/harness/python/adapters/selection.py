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
"""Python adapter for the ``selection`` conformance protocol (R+D.md §12.7;
RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md).

Non-message-driven, like ``replication``: the scenario carries a declaration
(``fixtures.selection``), a chain root (``fixtures.root``, 64 hex) and a list
of events, evaluated in order against one requestor and one auditing peer.
What is pinned is the RULES: the same weights, floor and seed must select the
same peers with the same propensities in both runtimes, the same chain must
give the same links, and the same log must audit and estimate the same.

Events (each names one operation and what it must produce):

* ``declare: {...}`` with ``refused``.
* ``policy: <cap>`` with ``k`` and ``floor``.
* ``propensities: {weights, floor}`` with ``probs`` and ``degraded``.
* ``draw: {weights, k, floor, seed}`` with ``selected``, ``inclusion``,
  ``kind`` and ``fallback``.
* ``link: <index>`` with ``hex``; ``head`` with ``hex``.
* ``verify: {index, link_of | link, known_index}`` with ``ok``.
* ``decide: {task, capability, peers, weights, k, floor, purpose}`` with
  ``selected`` (peer names) and ``index``. The requestor's log grows.
* ``decline: {task, peer}`` with ``recorded``; ``outcome: {task, peer,
  score}`` with ``recorded``.
* ``audit: {index, asker}`` with ``answer`` (a subset to match).
* ``check_draw: {index | draw}`` with ``finding`` and ``gap``: the peer
  checks the requestor's draw ``index`` (or an explicit, tampered one).
* ``check_answer: {index, asker, tamper}`` with ``finding``.
* ``estimate: {}`` (over the log) or ``estimate: {records}`` with ``result``.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from autonomous_trust.oracle.selection import (
    SeedChain, SelectionDeclarationError, draw, estimate, parse_selection,
    propensities, verify_link)
from autonomous_trust.oracle._python.selection import hooks
from autonomous_trust.oracle._python.selection.selector import Requestor

from ...common.scenario_loader import Case

TOL = 1e-12


def _close(a, b) -> bool:
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(_close(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_close(x, y) for x, y in zip(a, b))
    if isinstance(a, bool) or isinstance(b, bool):
        return a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(float(a) - float(b)) <= TOL
    return a == b


def _subset(actual, want) -> bool:
    """Every key ``want`` names matches in ``actual`` (recursively for
    objects)."""
    if isinstance(want, dict):
        return isinstance(actual, dict) and all(
            k in actual and _subset(actual[k], v) for k, v in want.items())
    return _close(actual, want)


class SelectionAdapter:
    """Replays a selection scenario against this runtime's layer."""

    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    def run_scenario(self, case: Case) -> None:
        fixtures = case.data.get('fixtures', {}) or {}
        model = parse_selection(fixtures.get('selection', {'version': 1}))
        root = bytes.fromhex(fixtures.get('root', '00' * 32))
        with tempfile.TemporaryDirectory() as cfg_dir:
            req = Requestor('negotiation', model, cfg_dir=cfg_dir, root=root)
            peer = {'chains': {}, 'findings': {}}
            for index, event in enumerate(fixtures.get('events', []) or [], start=1):
                self._event(model, req, peer, root, f'event {index}', event)

    # ------------------------------------------------------------------
    def _event(self, model, req, peer, root, where: str, ev: dict[str, Any]) -> None:
        def expect(name, actual):
            if name in ev and not _close(actual, ev[name]):
                raise AssertionError(f'{where}: {name}={actual!r}, expected {ev[name]!r}')

        if 'declare' in ev:
            try:
                parse_selection(ev['declare'])
                refused = False
            except SelectionDeclarationError:
                refused = True
            expect('refused', refused)
        elif 'policy' in ev:
            pol = model.policy_for(ev['policy'])
            expect('k', pol.k)
            expect('floor', pol.floor)
            expect('selects', model.selects(ev['policy']))
        elif 'propensities' in ev:
            spec = ev['propensities']
            probs, degraded = propensities(spec['weights'], float(spec['floor']))
            expect('probs', probs)
            expect('degraded', degraded)
        elif 'draw' in ev:
            spec = ev['draw']
            d = draw(spec['weights'], spec.get('k'), float(spec['floor']), int(spec['seed']))
            expect('selected', list(d.selected))
            expect('inclusion', list(d.inclusion))
            expect('kind', d.kind)
            expect('fallback', d.fallback)
            expect('degraded', d.degraded)
        elif 'link' in ev:
            expect('hex', SeedChain(root).link(int(ev['link'])).hex())
        elif 'head' in ev:
            expect('hex', SeedChain(root).head.hex())
        elif 'verify' in ev:
            spec = ev['verify']
            chain = SeedChain(root)
            link = (chain.link(int(spec['link_of'])) if 'link_of' in spec
                    else bytes.fromhex(spec['link']))
            known = None
            if spec.get('known_index'):
                known = (int(spec['known_index']), chain.link(int(spec['known_index'])))
            expect('ok', verify_link(chain.head, int(spec['index']), link, known))
        elif 'decide' in ev:
            spec = ev['decide']
            peers = list(spec['peers'])
            selected, field = req.decide(spec['task'], spec['capability'], peers,
                                         spec['weights'], spec.get('k'),
                                         float(spec['floor']),
                                         spec.get('purpose', 'task'))
            expect('selected', [peers[i] for i in selected])
            expect('index', field['index'])
        elif 'decline' in ev:
            spec = ev['decline']
            expect('recorded', req.record_decline(spec['task'], spec['peer']) is not None)
        elif 'outcome' in ev:
            spec = ev['outcome']
            expect('recorded', req.record_outcome(spec['task'], spec['peer'],
                                                  float(spec['score'])))
        elif 'audit' in ev:
            spec = ev['audit']
            answer = req.audit_answer(int(spec['index']), spec['asker'])
            if 'answer' in ev and not _subset(answer, ev['answer']):
                raise AssertionError(f'{where}: answer={answer!r}, expected {ev["answer"]!r}')
        elif 'check_draw' in ev:
            spec = ev['check_draw']
            if 'draw' in spec:
                field = dict(spec['draw'])
            else:
                rec = req.records[int(spec['index'])]
                field = {'head': rec['head'], 'index': rec['index'], 'link': rec['link']}
                field.update(spec.get('tamper', {}) or {})
            finding, gap = hooks.check_draw(peer, spec.get('requestor', 'R'), field)
            expect('finding', finding)
            expect('gap', gap)
        elif 'check_answer' in ev:
            spec = ev['check_answer']
            answer = req.audit_answer(int(spec['index']), spec['asker'])
            for key, value in (spec.get('tamper', {}) or {}).items():
                if key == 'row' and isinstance(value, dict) and isinstance(answer.get('row'), dict):
                    answer['row'].update(value)
                else:
                    answer[key] = value
            expect('finding', hooks.check_answer(peer, spec.get('requestor', 'R'), answer))
        elif 'estimate' in ev:
            spec = ev['estimate'] or {}
            records = spec.get('records')
            result = estimate(records if records is not None else list(req.records.values()))
            expect('result', result)
        else:
            raise AssertionError(f'{where}: unrecognised event {ev!r}')
