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

import math
from datetime import datetime

import pytest

try:
    from autonomous_trust.core.network.message import Message
    from autonomous_trust.core.processes import ProcessTracker
except ImportError:
    pytest.skip("AT core not installed", allow_module_level=True)

from autonomous_trust.evaluation.metrics.collector import MetricsCollector


class TestIdentityConvergence:
    """Test that MetricsCollector tracks identity admission timing."""

    def test_records_admission_timestamps(self):
        """Collector records when each peer is admitted."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        t1 = datetime(2026, 1, 1, 12, 0, 0)
        t2 = datetime(2026, 1, 1, 12, 0, 30)

        collector._handle_identity_event('access_granted', 'peer-a', t1)
        collector._handle_identity_event('access_granted', 'peer-b', t2)

        assert 'peer-a' in collector._identity_admitted
        assert 'peer-b' in collector._identity_admitted
        assert collector._identity_admitted['peer-a'] == t1
        assert collector._identity_admitted['peer-b'] == t2

    def test_convergence_time_calculation(self):
        """Convergence = time from first to last admission."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        t1 = datetime(2026, 1, 1, 12, 0, 0)
        t2 = datetime(2026, 1, 1, 12, 0, 15)
        t3 = datetime(2026, 1, 1, 12, 0, 45)

        collector._handle_identity_event('access_granted', 'peer-a', t1)
        collector._handle_identity_event('access_granted', 'peer-b', t2)
        collector._handle_identity_event('access_granted', 'peer-c', t3)

        report = collector.report()
        assert report['identity_convergence_s'] == 45.0

    def test_convergence_none_when_no_admissions(self):
        """No admissions -> convergence is None."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        report = collector.report()
        assert report['identity_convergence_s'] is None


class TestReputationStability:
    """Test reputation score tracking and stability computation."""

    def test_records_reputation_scores(self):
        """Collector accumulates scores per peer."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        collector._handle_reputation_event('peer-a', 0.8)
        collector._handle_reputation_event('peer-a', 0.85)
        collector._handle_reputation_event('peer-b', 0.7)

        assert len(collector._reputation_scores['peer-a']) == 2
        assert len(collector._reputation_scores['peer-b']) == 1

    def test_stability_calculation(self):
        """Stability = mean std dev across peers (last N scores)."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        # Stable peer: scores barely change
        for score in [0.80, 0.81, 0.79, 0.80, 0.80]:
            collector._handle_reputation_event('peer-a', score)

        # Less stable peer
        for score in [0.70, 0.75, 0.65, 0.72, 0.68]:
            collector._handle_reputation_event('peer-b', score)

        report = collector.report()
        assert report['reputation_stability_stddev'] is not None
        # peer-a stddev ~ 0.006, peer-b stddev ~ 0.035, mean ~ 0.021
        assert report['reputation_stability_stddev'] < 0.05

    def test_stability_none_when_insufficient_data(self):
        """Need at least 2 scores per peer for stddev."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        collector._handle_reputation_event('peer-a', 0.8)

        report = collector.report()
        assert report['reputation_stability_stddev'] is None


class TestNegotiationRTT:
    """Test negotiation round-trip time tracking."""

    def test_records_rtt_from_invite_to_haggle(self):
        """RTT = time between invitation and first haggle for same task."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        t1 = datetime(2026, 1, 1, 12, 0, 0)
        t2 = datetime(2026, 1, 1, 12, 0, 2)  # 2 seconds later

        collector._handle_negotiation_event('invitation', 'task-1', t1)
        collector._handle_negotiation_event('haggle', 'task-1', t2)

        report = collector.report()
        assert report['negotiation_rtt_mean_s'] == 2.0
        assert report['negotiation_rtt_count'] == 1

    def test_multiple_rtts_averaged(self):
        """Mean RTT across multiple completed exchanges."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        # Exchange 1: 2s RTT
        collector._handle_negotiation_event('invitation', 'task-1',
                                            datetime(2026, 1, 1, 12, 0, 0))
        collector._handle_negotiation_event('haggle', 'task-1',
                                            datetime(2026, 1, 1, 12, 0, 2))

        # Exchange 2: 4s RTT
        collector._handle_negotiation_event('invitation', 'task-2',
                                            datetime(2026, 1, 1, 12, 1, 0))
        collector._handle_negotiation_event('haggle', 'task-2',
                                            datetime(2026, 1, 1, 12, 1, 4))

        report = collector.report()
        assert report['negotiation_rtt_mean_s'] == 3.0
        assert report['negotiation_rtt_count'] == 2

    def test_rtt_none_when_no_completed_exchanges(self):
        """Invitation without response -> no RTT."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        collector._handle_negotiation_event('invitation', 'task-1',
                                            datetime(2026, 1, 1, 12, 0, 0))

        report = collector.report()
        assert report['negotiation_rtt_mean_s'] is None
        assert report['negotiation_rtt_count'] == 0


class TestBandwidthOverhead:
    """Test bandwidth overhead estimation."""

    def test_tracks_protocol_bytes(self):
        """Each processed message increments byte counter."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()

        collector._record_message_bytes(150)
        collector._record_message_bytes(200)

        assert collector._protocol_bytes == 350

    def test_overhead_calculation(self):
        """Overhead = protocol_bytes / (bandwidth_bps * duration_s / 8)."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()
        collector._start_time = datetime(2026, 1, 1, 12, 0, 0)

        # 1000 bytes of protocol traffic (timestamp sets first_message_time)
        msg_time = datetime(2026, 1, 1, 12, 0, 0)
        collector._record_message_bytes(1000, timestamp=msg_time)
        # Available bandwidth: 10 Kbps = 1250 bytes/sec
        collector._total_bandwidth_bps = 10_000.0
        collector._bandwidth_samples = 1

        end_time = datetime(2026, 1, 1, 12, 0, 10)  # 10 seconds
        report = collector._compute_bandwidth_report(end_time)
        # Capacity = 1250 B/s * 10s = 12500 bytes
        # Overhead = 1000 / 12500 = 0.08
        assert abs(report['bandwidth_overhead_fraction'] - 0.08) < 0.001

    def test_overhead_none_when_no_data(self):
        """No bandwidth data -> None."""
        collector = MetricsCollector.__new__(MetricsCollector)
        collector._init_metrics()
        collector._start_time = datetime(2026, 1, 1, 12, 0, 0)

        report = collector._compute_bandwidth_report(datetime(2026, 1, 1, 12, 0, 10))
        assert report['bandwidth_overhead_fraction'] is None
