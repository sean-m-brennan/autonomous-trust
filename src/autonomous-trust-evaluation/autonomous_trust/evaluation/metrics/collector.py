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
from autonomous_trust.core._python.negotiation.negotiation import TaskInfo
from autonomous_trust.core._python.reputation.reputation import Reputation
from autonomous_trust.core.system import CfgIds, QueueType


class MetricsCollector(Process, metaclass=ProcMeta,
                       proc_name='metrics-collector',
                       description='Protocol metrics collection'):

    is_tee_observer = True

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
        self._first_message_time: Optional[datetime] = None

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
        elif function in ('haggle', 'ack'):
            # Complete RTT on first response: either a counter-offer
            # (haggle) or a direct acceptance (ack).
            if task_id in self._negotiation_starts:
                start = self._negotiation_starts.pop(task_id)
                rtt = (timestamp - start).total_seconds()
                self._negotiation_rtts.append(rtt)

    def _record_message_bytes(self, nbytes: int, timestamp: Optional[datetime] = None):
        """Accumulate protocol traffic byte count."""
        if self._first_message_time is None:
            self._first_message_time = timestamp or datetime.now()
        self._protocol_bytes += nbytes

    # Default assumed link capacity in bits per second for bandwidth fraction
    # calculation.  Containers use tc-based shaping; this is a conservative
    # estimate for a simulated radio mesh link (1 Mbps).
    _assumed_link_bps: float = 1_000_000.0

    def _compute_bandwidth_report(self, end_time: datetime) -> dict:
        """Compute bandwidth overhead fraction.

        Uses externally-reported bandwidth samples when available, falling
        back to a fixed assumed link capacity so the metric is never null
        when protocol bytes have been observed.

        Duration is measured from the first observed network message to
        avoid inflating the denominator with idle startup time.
        """
        result: dict[str, Any] = {}
        bw_start = self._first_message_time or self._start_time
        if bw_start and self._protocol_bytes > 0:
            duration_s = (end_time - bw_start).total_seconds()
            if duration_s > 0:
                if self._bandwidth_samples > 0 and self._total_bandwidth_bps > 0:
                    link_bps = self._total_bandwidth_bps / self._bandwidth_samples
                else:
                    link_bps = self._assumed_link_bps
                capacity_bytes = (link_bps / 8.0) * duration_s
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
        # Distinct identities that were granted access, so downstream
        # consumers (e.g. the Sybil red-team scenario) can perform a
        # bound check against the expected legitimate roster.
        result['identity_admitted_ids'] = sorted(self._identity_admitted.keys())

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

    # Write metrics snapshot every 30 seconds so that results survive
    # ungraceful termination (e.g. SIGKILL from ``docker stop``).
    _SNAPSHOT_INTERVAL_S = 30.0

    def process(self, queues: dict[str, QueueType], signal: QueueType):
        """Main loop: receive messages, track metrics, write report periodically."""
        self._start_time = datetime.now()
        last_snapshot = self._start_time
        while self.keep_running(signal):
            try:
                msg = queues[self.name].get(block=True, timeout=self.q_cadence)
            except queue.Empty:
                # Periodically flush metrics even when idle
                if (datetime.now() - last_snapshot).total_seconds() >= self._SNAPSHOT_INTERVAL_S:
                    self._write_report()
                    last_snapshot = datetime.now()
                continue

            if isinstance(msg, Message):
                now = datetime.now()

                # Only count messages that actually traverse the wire:
                # outbound (destined for network process) or inbound
                # (from_whom set by Message.parse on network receipt).
                is_network_msg = (msg.process == CfgIds.network
                                  or msg.from_whom is not None)
                if is_network_msg:
                    try:
                        msg_size = len(bytes(msg))
                    except Exception:
                        msg_size = (len(str(msg.process))
                                    + len(str(msg.function))
                                    + len(str(msg.obj)))
                    self._record_message_bytes(msg_size, timestamp=now)

                # Identity events
                if msg.function in ('access_granted', 'request_access',
                                    'peer_accepted'):
                    # Outgoing messages (from this node) have from_whom=None;
                    # the admitted peer is in to_whom.  Incoming messages
                    # (from the network) have from_whom set by Message.parse.
                    peer_id = None
                    if msg.from_whom:
                        peer_id = str(msg.from_whom)
                    elif msg.to_whom and isinstance(msg.to_whom, list) and len(msg.to_whom) > 0:
                        peer_id = str(msg.to_whom[0])
                    if peer_id:
                        self._handle_identity_event(msg.function, peer_id, now)

                # Reputation events
                elif msg.function == 'reputation response':
                    if isinstance(msg.obj, Reputation):
                        self._handle_reputation_event(
                            str(msg.obj.peer_id), float(msg.obj.score))
                    elif isinstance(msg.obj, (tuple, list)) and len(msg.obj) >= 2:
                        self._handle_reputation_event(
                            str(msg.obj[0]), float(msg.obj[1]))

                # Negotiation events
                elif msg.function in ('invitation', 'haggle', 'ack', 'nack'):
                    # Extract stable task UUID rather than full object string,
                    # so invitation/haggle for the same task match up.
                    if isinstance(msg.obj, TaskInfo):
                        task_id = str(msg.obj.uuid)
                    else:
                        task_id = str(msg.obj) if msg.obj else 'unknown'
                    self._handle_negotiation_event(msg.function, task_id, now)

                # Periodic snapshot after processing messages
                if (now - last_snapshot).total_seconds() >= self._SNAPSHOT_INTERVAL_S:
                    self._write_report()
                    last_snapshot = now

        self._write_report()
