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

"""PoliteObserver: an AT Process plugin that receives protocol messages,
creates typed event dataclass instances, evaluates them against a
PolitePolicy, and tracks compliance metrics.

Tracked metrics:
  - Peer admission count and group size peak
  - Reputation scores per peer and cooldown tracking
  - Negotiation outcomes (success/failure)
  - Policy violations and compliant events
"""

import json
import queue
from datetime import datetime
from typing import Any, Optional

from autonomous_trust.core import ProcMeta
from autonomous_trust.core._python.processes import Process, ProcessTracker
from autonomous_trust.core._python.network.message import Message
from autonomous_trust.core._python.negotiation.negotiation import TaskInfo
from autonomous_trust.core._python.reputation.reputation import Reputation
from autonomous_trust.core.system import CfgIds, QueueType

from polite.interface import (
    PeerAdmitted, ReputationUpdate, NegotiationStarted, NegotiationOutcome,
)
from polite.policy import PolitePolicy


class PoliteObserver(Process, metaclass=ProcMeta,
                     proc_name='polite-observer',
                     description='Polite policy compliance observation'):

    is_tee_observer = True

    def __init__(self, configurations: dict[str, Any], subsystems: ProcessTracker,
                 log_queue: QueueType, dependencies: list[str] = None,
                 policy: Optional[PolitePolicy] = None,
                 output_path: Optional[str] = None):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        self.policy = policy if policy is not None else PolitePolicy()
        self.output_path = output_path
        self._init_state()

    def _init_state(self):
        """Initialize all tracking state."""
        self._peer_reputations: dict[str, float] = {}
        self._cooldown_until: dict[str, datetime] = {}
        self._pending_negotiations: dict[str, datetime] = {}  # task_id -> start time
        self._policy_violations: int = 0
        self._policy_compliant: int = 0
        self._negotiation_outcomes: list[bool] = []
        self._peer_count: int = 0
        self._group_size_max: int = 0
        self._start_time: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_peer_admitted(self, event: PeerAdmitted):
        """Handle PeerAdmitted: increment peer count and check max_group_size."""
        self._peer_count += 1
        if self._peer_count > self._group_size_max:
            self._group_size_max = self._peer_count

        if (self.policy.max_group_size is not None
                and self._peer_count > self.policy.max_group_size):
            self._policy_violations += 1

    def _on_reputation_update(self, event: ReputationUpdate):
        """Handle ReputationUpdate: store score and apply cooldown if below threshold."""
        self._peer_reputations[event.peer_id] = event.score

        if (self.policy.min_reputation_to_negotiate is not None
                and event.score < self.policy.min_reputation_to_negotiate
                and self.policy.defection_cooldown_s is not None):
            from datetime import timedelta
            self._cooldown_until[event.peer_id] = (
                event.timestamp
                + timedelta(seconds=self.policy.defection_cooldown_s)
            )

    def _on_negotiation_started(self, event: NegotiationStarted):
        """Handle NegotiationStarted: check policy and record pending negotiation."""
        self._pending_negotiations[event.task_id] = event.timestamp

        initiator = event.initiator_id
        now = event.timestamp

        # Check cooldown first
        if initiator in self._cooldown_until:
            if now < self._cooldown_until[initiator]:
                self._policy_violations += 1
                return

        # Check min reputation
        if self.policy.min_reputation_to_negotiate is not None:
            score = self._peer_reputations.get(initiator)
            if score is None or score < self.policy.min_reputation_to_negotiate:
                self._policy_violations += 1
                return

        self._policy_compliant += 1

    def _on_negotiation_outcome(self, event: NegotiationOutcome):
        """Handle NegotiationOutcome: record result and remove from pending."""
        self._negotiation_outcomes.append(event.success)
        self._pending_negotiations.pop(event.task_id, None)

    def _handle_event(self, event):
        """Dispatch a typed event to the appropriate handler."""
        if isinstance(event, PeerAdmitted):
            self._on_peer_admitted(event)
        elif isinstance(event, ReputationUpdate):
            self._on_reputation_update(event)
        elif isinstance(event, NegotiationStarted):
            self._on_negotiation_started(event)
        elif isinstance(event, NegotiationOutcome):
            self._on_negotiation_outcome(event)

    def _handle_message(self, event_type: str, **kwargs):
        """Convenience method: create a typed event from kwargs and dispatch it.

        Primarily used by tests. Maps event_type strings to event dataclasses.
        """
        timestamp = kwargs.get('timestamp', datetime.now())

        if event_type == 'access_granted':
            event = PeerAdmitted(
                peer_id=kwargs['peer_id'],
                timestamp=timestamp,
            )
        elif event_type == 'reputation_update':
            event = ReputationUpdate(
                peer_id=kwargs['peer_id'],
                score=kwargs['score'],
                timestamp=timestamp,
            )
        elif event_type == 'negotiation_started':
            event = NegotiationStarted(
                task_id=kwargs['task_id'],
                initiator_id=kwargs['initiator_id'],
                timestamp=timestamp,
            )
        elif event_type == 'negotiation_outcome':
            event = NegotiationOutcome(
                task_id=kwargs['task_id'],
                success=kwargs['success'],
                timestamp=timestamp,
            )
        else:
            # Unknown event type — ignore
            return

        self._handle_event(event)

    def _dispatch_message(self, msg: Message, now: datetime):
        """Parse an AT Message into a typed event and dispatch it."""
        function = msg.function

        if function == 'access_granted':
            peer_id = None
            if msg.from_whom:
                peer_id = str(msg.from_whom)
            elif (msg.to_whom and isinstance(msg.to_whom, list)
                  and len(msg.to_whom) > 0):
                peer_id = str(msg.to_whom[0])
            if peer_id:
                self._handle_event(PeerAdmitted(peer_id=peer_id, timestamp=now))

        elif function == 'reputation response':
            if isinstance(msg.obj, Reputation):
                peer_id = str(msg.obj.peer_id)
                score = float(msg.obj.score)
            elif (isinstance(msg.obj, (tuple, list)) and len(msg.obj) >= 2):
                peer_id = str(msg.obj[0])
                score = float(msg.obj[1])
            else:
                return
            self._handle_event(
                ReputationUpdate(peer_id=peer_id, score=score, timestamp=now))

        elif function == 'invitation':
            if isinstance(msg.obj, TaskInfo):
                task_id = str(msg.obj.uuid)
            else:
                task_id = str(msg.obj) if msg.obj else 'unknown'
            # Inbound invitation: initiator is from_whom
            initiator_id = str(msg.from_whom) if msg.from_whom else 'unknown'
            self._handle_event(
                NegotiationStarted(task_id=task_id, initiator_id=initiator_id,
                                   timestamp=now))

        elif function in ('ack', 'nack'):
            if isinstance(msg.obj, TaskInfo):
                task_id = str(msg.obj.uuid)
            else:
                task_id = str(msg.obj) if msg.obj else 'unknown'
            self._handle_event(
                NegotiationOutcome(task_id=task_id,
                                   success=(function == 'ack'),
                                   timestamp=now))

        # Ignored: 'request_access', 'peer_accepted', 'haggle'

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def report(self) -> dict:
        """Compute and return policy compliance metrics as a dict."""
        result: dict[str, Any] = {}

        result['policy'] = self.policy.to_dict()

        # Cooperation rate: fraction of successful negotiations
        total_outcomes = len(self._negotiation_outcomes)
        if total_outcomes > 0:
            result['cooperation_rate'] = (
                sum(1 for s in self._negotiation_outcomes if s) / total_outcomes
            )
        else:
            result['cooperation_rate'] = None

        # Task throughput: successful negotiations per second
        now = datetime.now()
        start = self._start_time or now
        elapsed_s = (now - start).total_seconds()
        successful = sum(1 for s in self._negotiation_outcomes if s)
        if elapsed_s > 0:
            result['task_throughput'] = successful / elapsed_s
        else:
            result['task_throughput'] = None

        # Policy compliance rate
        total_evaluated = self._policy_compliant + self._policy_violations
        if total_evaluated > 0:
            result['policy_compliance_rate'] = (
                self._policy_compliant / total_evaluated
            )
        else:
            result['policy_compliance_rate'] = None

        result['violation_count'] = self._policy_violations
        result['group_size_peak'] = self._group_size_max
        result['peer_count'] = self._peer_count

        return result

    def _write_report(self):
        """Write metrics report to JSON file if output_path is set."""
        report = self.report()
        if self.output_path:
            with open(self.output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        return report

    # ------------------------------------------------------------------
    # Main process loop
    # ------------------------------------------------------------------

    # Write metrics snapshot every 30 seconds so that results survive
    # ungraceful termination (e.g. SIGKILL from ``docker stop``).
    _SNAPSHOT_INTERVAL_S = 30.0

    def process(self, queues: dict[str, QueueType], signal: QueueType):
        """Main loop: receive messages, evaluate policy, write report periodically."""
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
                self._dispatch_message(msg, now)

                # Periodic snapshot after processing messages
                if (now - last_snapshot).total_seconds() >= self._SNAPSHOT_INTERVAL_S:
                    self._write_report()
                    last_snapshot = now

        self._write_report()
