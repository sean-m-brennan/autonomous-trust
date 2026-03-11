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

"""MetricsCollector: an AT Process that observes protocol messages
and computes performance metrics for simulation evaluation.

Tracked metrics:
  - Identity convergence: time from first to last peer admission
  - Reputation stability: std dev of reputation scores post-convergence
  - Negotiation RTT: round-trip time for negotiation exchanges
  - Bandwidth overhead: AT protocol bytes as fraction of available bandwidth
"""

import json
import queue
import statistics
from datetime import datetime
from typing import Any, Optional

from autonomous_trust.core import ProcMeta
from autonomous_trust.core._python.processes import Process, ProcessTracker
from autonomous_trust.core._python.network.message import Message
from autonomous_trust.core.system import QueueType


class MetricsCollector(Process, metaclass=ProcMeta,
                       proc_name='metrics-collector',
                       description='Protocol metrics collection'):

    def __init__(self, configurations: dict[str, Any], subsystems: ProcessTracker,
                 log_queue: QueueType, dependencies: list[str] = None,
                 output_path: Optional[str] = None):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        self.output_path = output_path
        self._init_metrics()

    def _init_metrics(self):
        """Initialize metric tracking state."""
        # Identity convergence
        self._identity_admitted: dict[str, datetime] = {}

        # Reputation stability
        self._reputation_scores: dict[str, list[float]] = {}

        # Negotiation RTT
        self._negotiation_starts: dict[str, datetime] = {}  # task_id -> start
        self._negotiation_rtts: list[float] = []

        # Bandwidth overhead
        self._protocol_bytes: int = 0
        self._total_bandwidth_bps: float = 0.0
        self._bandwidth_samples: int = 0
        self._start_time: Optional[datetime] = None

    def _handle_identity_event(self, function: str, peer_id: str,
                               timestamp: datetime):
        """Record identity admission events."""
        if function == 'access_granted' and peer_id not in self._identity_admitted:
            self._identity_admitted[peer_id] = timestamp

    def _handle_reputation_event(self, peer_id: str, score: float):
        """Record a reputation score update for a peer."""
        if peer_id not in self._reputation_scores:
            self._reputation_scores[peer_id] = []
        self._reputation_scores[peer_id].append(score)

    def _handle_negotiation_event(self, function: str, task_id: str,
                                  timestamp: datetime):
        """Track negotiation request/response timing."""
        if function == 'invitation':
            if task_id not in self._negotiation_starts:
                self._negotiation_starts[task_id] = timestamp
        elif function == 'haggle':
            if task_id in self._negotiation_starts:
                start = self._negotiation_starts.pop(task_id)
                rtt = (timestamp - start).total_seconds()
                self._negotiation_rtts.append(rtt)

    def _record_message_bytes(self, nbytes: int):
        """Accumulate protocol traffic byte count."""
        self._protocol_bytes += nbytes

    def _compute_bandwidth_report(self, end_time: datetime) -> dict:
        """Compute bandwidth overhead fraction."""
        result: dict[str, Any] = {}
        if (self._start_time and self._bandwidth_samples > 0
                and self._total_bandwidth_bps > 0):
            duration_s = (end_time - self._start_time).total_seconds()
            if duration_s > 0:
                mean_bw_bps = self._total_bandwidth_bps / self._bandwidth_samples
                capacity_bytes = (mean_bw_bps / 8.0) * duration_s
                result['bandwidth_overhead_fraction'] = (
                    self._protocol_bytes / capacity_bytes
                    if capacity_bytes > 0 else None)
            else:
                result['bandwidth_overhead_fraction'] = None
        else:
            result['bandwidth_overhead_fraction'] = None
        result['protocol_bytes_total'] = self._protocol_bytes
        return result

    def report(self) -> dict:
        """Compute and return all metrics as a dict."""
        result: dict[str, Any] = {}

        # Identity convergence
        if self._identity_admitted:
            times = list(self._identity_admitted.values())
            delta = (max(times) - min(times)).total_seconds()
            result['identity_convergence_s'] = delta
        else:
            result['identity_convergence_s'] = None
        result['identity_peers_admitted'] = len(self._identity_admitted)

        # Reputation stability (mean std dev across peers)
        stddevs = []
        for peer_id, scores in self._reputation_scores.items():
            if len(scores) >= 2:
                stddevs.append(statistics.stdev(scores))
        if stddevs:
            result['reputation_stability_stddev'] = statistics.mean(stddevs)
        else:
            result['reputation_stability_stddev'] = None
        result['reputation_peers_tracked'] = len(self._reputation_scores)

        # Negotiation RTT
        if self._negotiation_rtts:
            result['negotiation_rtt_mean_s'] = statistics.mean(
                self._negotiation_rtts)
        else:
            result['negotiation_rtt_mean_s'] = None
        result['negotiation_rtt_count'] = len(self._negotiation_rtts)

        # Bandwidth overhead
        bandwidth = self._compute_bandwidth_report(datetime.now())
        result.update(bandwidth)

        return result

    def _write_report(self):
        """Write metrics report to JSON file if output_path is set."""
        report = self.report()
        if self.output_path:
            with open(self.output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        return report

    def process(self, queues: dict[str, QueueType], signal: QueueType):
        """Main loop: receive messages, track metrics, write report on shutdown."""
        self._start_time = datetime.now()
        while self.keep_running(signal):
            try:
                msg = queues[self.name].get(block=True, timeout=self.q_cadence)
            except queue.Empty:
                continue

            if isinstance(msg, Message):
                now = datetime.now()

                # Estimate message size for bandwidth tracking
                msg_size = (len(str(msg.process)) + len(str(msg.function))
                            + len(str(msg.obj)))
                self._record_message_bytes(msg_size)

                # Identity events
                if msg.function in ('access_granted', 'request_access',
                                    'peer_accepted'):
                    peer_id = str(msg.from_whom) if msg.from_whom else 'unknown'
                    self._handle_identity_event(msg.function, peer_id, now)

                # Reputation events
                elif msg.function == 'reputation response':
                    if isinstance(msg.obj, (tuple, list)) and len(msg.obj) >= 2:
                        self._handle_reputation_event(
                            str(msg.obj[0]), float(msg.obj[1]))

                # Negotiation events
                elif msg.function in ('invitation', 'haggle', 'ack', 'nack'):
                    task_id = str(msg.obj) if msg.obj else 'unknown'
                    self._handle_negotiation_event(msg.function, task_id, now)

        self._write_report()
