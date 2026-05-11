# ******************
#  Copyright 2026 Sean M. Brennan and contributors
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

"""Universal scenario engine.

Owns the protocol-agnostic walk over scenario steps. Per-protocol adapters
plug in by providing a `Participant` factory and a `dispatch()` callback.

The engine treats every step as one of:

  - Source step (no `in_response_to`): the named `from` participant is the
    originator. The engine builds the message and delivers it to `to`.
  - Assertion step (with `in_response_to: N`): the engine looks up the outbox
    captured when step N was delivered, finds a message that matches this
    step's (from, to, function), asserts it exists, and then delivers that
    captured message to `to` so any cascade continues.

`to: broadcast` expands to every participant other than `from`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..common.scenario_loader import Case


@dataclass
class CapturedMessage:
    """An outbound message observed on a participant's network queue."""
    from_id: str
    to_id: str  # participant id, or 'broadcast'
    function: str
    payload: Any  # the original message.obj (kept loose for v1)
    raw: Any = None  # adapter-specific underlying object (e.g. a Message)


@dataclass
class StepOutbox:
    step_id: int
    captured: list[CapturedMessage] = field(default_factory=list)


@dataclass
class ParticipantHandle:
    """Per-participant state carried by the engine.

    `dispatch` is the adapter-supplied callback that delivers one inbound
    message to this participant and returns the messages it emitted.
    """
    id: str
    role: str
    impl: Any  # whatever the adapter wants (an IdentityProcess, a mock, ...)
    dispatch: Callable[[Any], list[CapturedMessage]]


@dataclass
class ScenarioContext:
    case: Case
    participants: dict[str, ParticipantHandle]
    outboxes: dict[int, StepOutbox] = field(default_factory=dict)
    # adapter-supplied: builds a Message-like inbound from (from_id, to_id,
    # function, payload) for a source step
    build_inbound: Callable[..., Any] = None
    # adapter-supplied: extracts (from_id, to_id, function, payload) from a
    # CapturedMessage's `raw` so the engine can match assertion steps
    describe: Callable[[CapturedMessage], tuple[str, str, str, Any]] = None


def run_scenario(ctx: ScenarioContext) -> None:
    """Walk the scenario's steps, applying the source/assertion model above.

    Raises AssertionError on the first failure, with a step-id-tagged message.
    """
    steps = ctx.case.data['steps']
    for step in steps:
        sid = step['id']
        in_resp = step.get('in_response_to')
        ctx.outboxes.setdefault(sid, StepOutbox(step_id=sid))

        if in_resp is None:
            _drive_source(ctx, step)
        else:
            _drive_assertion(ctx, step, in_resp)

    _check_expected_state(ctx)


def _drive_source(ctx: ScenarioContext, step: dict) -> None:
    sid = step['id']
    sender = ctx.participants.get(step['from'])
    if sender is None:
        raise AssertionError(f'step {sid}: unknown sender {step["from"]!r}')
    inbound = ctx.build_inbound(
        from_id=step['from'],
        to_id=step['to'],
        function=step['function'],
        payload=step.get('payload', {}),
    )
    targets = _resolve_targets(ctx, step, exclude={step['from']})
    # repeat: N delivers the same inbound message N times to the same
    # targets. Used by replay-handling probes; a correctly-deduping
    # handler produces the same observable state after N deliveries as
    # after 1. Built once, dispatched N times — matches what a real
    # network replay attack would look like (same wire bytes redelivered).
    repeat = int(step.get('repeat', 1))
    for _ in range(repeat):
        for target in targets:
            emitted = target.dispatch(inbound)
            ctx.outboxes[sid].captured.extend(_tag_emitter(emitted, target.id))


def _drive_assertion(ctx: ScenarioContext, step: dict, in_resp: int) -> None:
    sid = step['id']
    parent = ctx.outboxes.get(in_resp)
    if parent is None:
        raise AssertionError(
            f'step {sid}: in_response_to references step {in_resp} that has not run yet'
        )
    expected_from = step['from']
    expected_to = step['to']
    expected_fn = step['function']

    matches = [
        cm for cm in parent.captured
        if cm.from_id == expected_from
        and cm.function == expected_fn
        and (expected_to == 'broadcast' or cm.to_id in (expected_to, 'broadcast'))
    ]
    if not matches:
        captured_summary = ', '.join(
            f'{cm.from_id}->{cm.to_id}:{cm.function}' for cm in parent.captured
        ) or '(empty)'
        raise AssertionError(
            f'step {sid}: expected {expected_from}->{expected_to}:{expected_fn} '
            f'in response to step {in_resp}; outbox of step {in_resp} held [{captured_summary}]'
        )

    if step.get('no_propagate'):
        return  # assertion-only step; emission verified, delivery skipped

    cm = matches[0]
    targets = _resolve_targets(ctx, step, exclude={expected_from})
    for target in targets:
        emitted = target.dispatch(cm.raw)
        ctx.outboxes[sid].captured.extend(_tag_emitter(emitted, target.id))


def _resolve_targets(ctx: ScenarioContext, step: dict, exclude: set[str]) -> list[ParticipantHandle]:
    to = step['to']
    if to == 'broadcast':
        return [p for pid, p in ctx.participants.items() if pid not in exclude]
    target = ctx.participants.get(to)
    if target is None:
        raise AssertionError(f'step {step["id"]}: unknown target {to!r}')
    return [target]


def _tag_emitter(captured: Iterable[CapturedMessage], emitter_id: str) -> list[CapturedMessage]:
    out = []
    for cm in captured:
        if not cm.from_id:
            cm = CapturedMessage(
                from_id=emitter_id, to_id=cm.to_id, function=cm.function,
                payload=cm.payload, raw=cm.raw,
            )
        out.append(cm)
    return out


def _check_expected_state(ctx: ScenarioContext) -> None:
    expected = ctx.case.data.get('expected_state')
    if not expected:
        return
    for participant_id, asserts in expected.items():
        if participant_id == 'group':
            # group state is checked by the adapter via a sentinel; v1 logs
            # but does not enforce. Adapter can post-validate.
            continue
        p = ctx.participants.get(participant_id)
        if p is None:
            raise AssertionError(f'expected_state references unknown participant {participant_id!r}')
        if hasattr(p.impl, '_check_expected_state'):
            p.impl._check_expected_state(asserts)
