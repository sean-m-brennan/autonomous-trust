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
"""The executor's half of live replication (RD_12.6_LIVE_REPLICATION_PLAN.md
§3.2): a replayable capability runs step by step, its result commits to the
hash chain of its states, and the states stay local. The chain is pinned
against the digest src/c/test/neg_replay_test.c pins, and against the
replication layer's own when that layer is on the path."""
import queue

import pytest

from autonomous_trust.core.capabilities import Capability
from autonomous_trust.core.config import from_json_string, to_json_string
from autonomous_trust.core._python.negotiation.negotiation import (
    Task, TaskParameters, TaskResult)
from autonomous_trust.core._python.negotiation.replay import (
    MAX_TRACE_STEPS, Replayable, Traced, run_trace, split_traced, trace_chain)

#: h_2 of the chain over s0, s1, s2 (as negotiation-task-result.yaml pins).
H2 = '7a795ece0f922bf5090999cded4068f473e8bebe46265e829edf9b7024479d85'


def _counter(limit):
    """s0 .. s<limit>: one state per step, done after `limit`."""
    return Replayable(init=lambda: 0,
                      step=lambda s, i: s + 1 if s < limit else None,
                      encode=lambda s: 's%d' % s)


def test_the_chain_is_pinned():
    assert trace_chain(['s0', 's1', 's2'])[-1] == H2


def test_the_chain_is_the_replication_layers():
    replication = pytest.importorskip('autonomous_trust.oracle.replication')
    states = ['s0', 's1', 'x' * 600]
    assert trace_chain(states) == replication.hash_chain(states)


def test_a_trace_runs_to_its_end():
    traced = run_trace(_counter(2))
    assert traced.states == ['s0', 's1', 's2'] and traced.value == 's2'
    assert split_traced(traced) == ('s2', ['s0', 's1', 's2'])
    assert split_traced(7) == (7, None)
    with_result = Replayable(init=lambda n: n, step=lambda s, i: None,
                             result=lambda s: s * 10)
    assert run_trace(with_result, (4,)).value == 40


def test_a_trace_past_the_bound_fails():
    with pytest.raises(RuntimeError):
        run_trace(_counter(MAX_TRACE_STEPS))
    assert len(run_trace(_counter(MAX_TRACE_STEPS - 1)).states) == MAX_TRACE_STEPS


def test_a_replayable_capability_executes_its_trace():
    from types import SimpleNamespace
    cap = Capability('demo.count', replay=_counter(2))
    task = SimpleNamespace(uuid='t', parameters=SimpleNamespace(args=(), kwargs={}))
    out = cap.execute(task, queue.Queue())
    assert isinstance(out, Traced) and out.states[-1] == 's2'
    cap.sync_from_message()
    assert cap.replay is None                   # never off the wire


def test_the_commitment_travels_and_the_states_do_not():
    task = Task(TaskParameters('demo.count'), 'req')
    tr = TaskResult(task, 's2', trace_root=H2, trace_len=3)
    tr.trace_states = ['s0', 's1', 's2']
    wire = to_json_string(tr)
    assert 'trace_states' not in wire and H2 in wire
    back = from_json_string(wire)
    assert back.trace_root == H2 and back.trace_len == 3
    assert back.trace_states is None
    plain = from_json_string(to_json_string(TaskResult(task, 1)))
    assert plain.trace_root is None and plain.trace_len is None
