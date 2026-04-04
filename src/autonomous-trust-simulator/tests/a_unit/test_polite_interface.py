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
"""Tests for polite event dataclasses and evaluator protocol."""

from datetime import datetime

import pytest

try:
    from polite.interface import (
        PeerAdmitted, ReputationUpdate, NegotiationStarted,
        NegotiationOutcome, EvaluatorResult, PoliteEvaluatorProtocol,
    )
except ImportError:
    pytest.skip("polite package not on PYTHONPATH", allow_module_level=True)


class TestEventDataclasses:

    def test_peer_admitted_is_frozen(self):
        e = PeerAdmitted(peer_id='p1', timestamp=datetime(2026, 1, 1))
        with pytest.raises(AttributeError):
            e.peer_id = 'p2'

    def test_reputation_update_fields(self):
        e = ReputationUpdate(peer_id='p1', score=0.85, timestamp=datetime(2026, 1, 1))
        assert e.peer_id == 'p1'
        assert e.score == 0.85

    def test_negotiation_started_fields(self):
        e = NegotiationStarted(task_id='t1', initiator_id='p1',
                               timestamp=datetime(2026, 1, 1))
        assert e.task_id == 't1'
        assert e.initiator_id == 'p1'

    def test_negotiation_outcome_fields(self):
        e = NegotiationOutcome(task_id='t1', success=True,
                               timestamp=datetime(2026, 1, 1))
        assert e.success is True


class TestEvaluatorResult:

    def test_evaluator_result_is_frozen(self):
        r = EvaluatorResult(
            policy=None, observer_report={},
            metrics_report={}, fitness_score=0.5)
        with pytest.raises(AttributeError):
            r.fitness_score = 1.0
