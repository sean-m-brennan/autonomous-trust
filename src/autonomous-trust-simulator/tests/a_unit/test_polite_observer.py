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
"""Tests for PoliteObserver event parsing and policy evaluation."""

from datetime import datetime, timedelta

import pytest

try:
    from polite.policy import null_policy, strict_policy
except ImportError:
    pytest.skip("polite package not on PYTHONPATH", allow_module_level=True)

from autonomous_trust.simulator.polite.observer import PoliteObserver


class TestEventParsing:
    """Observer correctly parses AT message functions into events."""

    @pytest.fixture
    def observer(self):
        obs = PoliteObserver.__new__(PoliteObserver)
        obs.policy = null_policy()
        obs.output_path = None
        obs._init_state()
        return obs

    def test_handles_access_granted(self, observer):
        observer._handle_message('access_granted', peer_id='peer-a',
                                 timestamp=datetime(2026, 1, 1))
        assert observer._peer_count == 1

    def test_handles_reputation_response(self, observer):
        observer._handle_message('reputation_update', peer_id='peer-a',
                                 score=0.75, timestamp=datetime(2026, 1, 1))
        assert observer._peer_reputations['peer-a'] == 0.75

    def test_handles_invitation(self, observer):
        observer._handle_message('negotiation_started', task_id='t1',
                                 initiator_id='peer-a',
                                 timestamp=datetime(2026, 1, 1))
        assert 't1' in observer._pending_negotiations

    def test_handles_ack(self, observer):
        observer._handle_message('negotiation_started', task_id='t1',
                                 initiator_id='peer-a',
                                 timestamp=datetime(2026, 1, 1))
        observer._handle_message('negotiation_outcome', task_id='t1',
                                 success=True, timestamp=datetime(2026, 1, 1))
        assert observer._negotiation_outcomes == [True]

    def test_ignores_unknown_event(self, observer):
        observer._handle_message('unknown_function',
                                 timestamp=datetime(2026, 1, 1))
        assert observer._policy_violations == 0
        assert observer._policy_compliant == 0


class TestPolicyEvaluation:

    @pytest.fixture
    def observer(self):
        obs = PoliteObserver.__new__(PoliteObserver)
        obs.policy = strict_policy()  # min_reputation=0.5
        obs.output_path = None
        obs._init_state()
        return obs

    def test_negotiation_below_threshold_is_violation(self, observer):
        now = datetime(2026, 1, 1)
        observer._peer_reputations['peer-a'] = 0.3
        observer._handle_message('negotiation_started', task_id='t1',
                                 initiator_id='peer-a', timestamp=now)
        assert observer._policy_violations == 1

    def test_negotiation_above_threshold_is_compliant(self, observer):
        now = datetime(2026, 1, 1)
        observer._peer_reputations['peer-a'] = 0.8
        observer._handle_message('negotiation_started', task_id='t1',
                                 initiator_id='peer-a', timestamp=now)
        assert observer._policy_compliant == 1

    def test_negotiation_unknown_peer_is_violation(self, observer):
        now = datetime(2026, 1, 1)
        observer._handle_message('negotiation_started', task_id='t1',
                                 initiator_id='peer-unknown', timestamp=now)
        assert observer._policy_violations == 1

    def test_cooldown_blocks_negotiation(self, observer):
        now = datetime(2026, 1, 1)
        observer._peer_reputations['peer-a'] = 0.8
        observer._cooldown_until['peer-a'] = now + timedelta(seconds=120)
        observer._handle_message('negotiation_started', task_id='t1',
                                 initiator_id='peer-a', timestamp=now)
        assert observer._policy_violations == 1

    def test_group_size_violation(self, observer):
        now = datetime(2026, 1, 1)
        observer._peer_count = 10  # strict: max_group_size=10
        observer._handle_message('access_granted', peer_id='peer-11',
                                 timestamp=now)
        assert observer._policy_violations == 1


class TestReport:

    def test_report_structure(self):
        obs = PoliteObserver.__new__(PoliteObserver)
        obs.policy = null_policy()
        obs.output_path = None
        obs._init_state()
        obs._start_time = datetime(2026, 1, 1)
        obs._negotiation_outcomes = [True, True, False]
        obs._policy_compliant = 5
        obs._policy_violations = 2
        obs._peer_count = 3
        obs._group_size_max = 3

        report = obs.report()
        assert report['cooperation_rate'] == pytest.approx(2 / 3)
        assert report['policy_compliance_rate'] == pytest.approx(5 / 7)
        assert report['violation_count'] == 2
        assert report['group_size_peak'] == 3
        assert report['peer_count'] == 3
        assert 'policy' in report
        assert 'task_throughput' in report
