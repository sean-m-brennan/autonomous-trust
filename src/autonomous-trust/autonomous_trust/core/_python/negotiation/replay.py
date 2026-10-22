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
"""Replayable capabilities: the executor's half of live replication
(RD_12.6_LIVE_REPLICATION_PLAN.md §3.2, the user's D2).

A capability written for replay supplies a step contract instead of one call:
``init(*args, **kwargs)`` gives the first state, ``step(state, i)`` the next
(or None once the computation is done), ``encode(state)`` a state's canonical
text. The executor runs the steps, commits to the hash chain of the encoded
states (``trace_root`` and ``trace_len`` on its TaskResult) and keeps the
states, so that if a replica disagrees it can answer a verifier's questions
about any step. The chain is the replication layer's
(``autonomous_trust.oracle.replication.hash_chain``), repeated here because an
executor needs it whether or not this node loads that layer; a test pins the
two equal. The Python half of ``negotiation/neg_replay.h``.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..structures.merkle import MerkleTree

#: The most steps a trace may hold: the bisection game's bound (C
#: ``AT_REPL_MAX_STEPS``, ``NEG_REPLAY_MAX_STEPS``).
MAX_TRACE_STEPS = 256


def _as_text(text: str) -> str:
    return text


class Replayable:
    """A capability's step contract. ``result(final_state)`` is what the task
    answers with; by default the final state's encoding. ``decode(text)``
    rebuilds a state from its encoding, which a requestor needs to re-execute
    one step from a revealed state; by default the text itself."""

    def __init__(self, init: Callable[..., Any],
                 step: Callable[[Any, int], Any],
                 encode: Callable[[Any], str] = str,
                 result: Optional[Callable[[Any], Any]] = None,
                 decode: Callable[[str], Any] = None) -> None:
        self.init = init
        self.step = step
        self.encode = encode
        self.result = result
        # A module function, not a lambda: a Capability pickles across the
        # fork into the worker processes, and its contract with it.
        self.decode = decode if decode is not None else _as_text


class Traced:
    """What a replayable capability's execution returns: the answer and the
    encoded states it passed through."""

    def __init__(self, value: Any, states: list[str]) -> None:
        self.value = value
        self.states = list(states)


def run_trace(replay: Replayable, args=(), kwargs=None) -> Traced:
    """Run ``replay`` from its first state to its last. Raises RuntimeError
    when the computation takes more than :data:`MAX_TRACE_STEPS` states."""
    state = replay.init(*args, **(kwargs or {}))
    states = [replay.encode(state)]
    i = 1
    while True:
        nxt = replay.step(state, i)
        if nxt is None:
            break
        if len(states) >= MAX_TRACE_STEPS:
            raise RuntimeError('a replayable computation ran past %d steps'
                               % MAX_TRACE_STEPS)
        state = nxt
        states.append(replay.encode(state))
        i += 1
    value = replay.result(state) if replay.result is not None else states[-1]
    return Traced(value, states)


def replay_step(replay: Replayable, pre: Optional[str], k: int, args=(),
                kwargs=None) -> Optional[str]:
    """Re-execute step ``k``: the encoded state after the encoded ``pre``, or
    the first state at k = 0 (``pre`` None), or None when the computation is
    done. What a requestor holding the step contract computes to settle a
    dispute."""
    if k == 0:
        return replay.encode(replay.init(*args, **(kwargs or {})))
    nxt = replay.step(replay.decode(pre), k)
    return None if nxt is None else replay.encode(nxt)


def trace_chain(states: list[str]) -> list[str]:
    """``h_0 = H(s_0)``, ``h_i = H(h_{i-1} || s_i)``, 64-char hex each."""
    chain: list[str] = []
    prev = b''
    for state in states:
        prev = MerkleTree.get_hash(prev + str(state).encode('utf-8'))
        chain.append(prev.decode('ascii'))
    return chain


def split_traced(result):
    """``(value, states)`` for a possibly-traced result, states None if not."""
    if isinstance(result, Traced):
        return result.value, result.states
    return result, None
