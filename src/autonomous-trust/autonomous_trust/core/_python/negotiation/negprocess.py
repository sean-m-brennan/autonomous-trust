# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import traceback
from queue import Empty, Full
from datetime import timedelta
from uuid import UUID

from ..capabilities import Capability
from ..config import from_json_string
from ..freshness import Freshness
from ..identity.protocol import IdentityProtocol
from ..network import Message
from ..processes import Process, ProcMeta
from .protocol import NegotiationProtocol
from .negotiation import Job, JobQueue, Task, TaskStatus, TaskTracker, TaskCounter, TaskResult, Status
from ..system import CfgIds, max_concurrency, now, proc_idle_floor
from .. import _probes


class NegotiationProcess(Process, metaclass=ProcMeta,
                         proc_name=CfgIds.negotiation, description='Negotiate transactions'):
    """
    Handle transaction agreement negotiations
    """
    max_task_duplicates = 5

    def __init__(self, configurations, subsystems, log_q, max_cores=max_concurrency, **kwargs):
        super().__init__(configurations, subsystems, log_q,
                         dependencies=[CfgIds.network, CfgIds.identity], **kwargs)
        self.task_stack = JobQueue()
        self.proposed_tasks = {}  # TaskCounters for local tasks remotely requested
        # Persistent per-task flood counter. Kept separate from
        # `proposed_tasks` because `_add_task` clears the latter on every
        # successful admission, which would make the flood threshold
        # unreachable in normal operation. Mirrors C's structurally
        # separate "flood:<uuid>" key on `proposed_tasks` in
        # negotiation/neg_proc.c — see BUGS.md §P7.
        self.flood_counts = {}
        self.my_tasks = {}  # TaskTrackers for remote tasks I've requested
        self.confirmed = {}
        self.status_pending = []
        # Per-verb replay state: our own monotonic send counter and the
        # per-(sender, verb) high-water marks, both persisted. Used by the
        # `announce` verb only -- the invitation was the one negotiation verb
        # whose payload carried no freshness token of its own, and it is the
        # verb that asks a peer to RUN something. The other verbs are bounded
        # by state that already exists: an acceptance is deduped per
        # participant, a status response spends an outstanding request. See
        # core/freshness.py and doc/architecture/security-hardening.md,
        # "Replay resistance, per verb".
        self.freshness = Freshness(self.name, self.logger)
        self.max_concurrency = max_cores
        self.protocol = NegotiationProtocol(self.name, self.logger, configurations)
        self.protocol.register_handler(NegotiationProtocol.start, self.start_task)
        self.protocol.register_handler(NegotiationProtocol.announce, self.handle_invite)
        self.protocol.register_handler(NegotiationProtocol.response, self.handle_haggle)
        self.protocol.register_handler(NegotiationProtocol.acceptance, self.handle_accept)
        self.protocol.register_handler(NegotiationProtocol.status_req, self.handle_stat_req)
        self.protocol.register_handler(NegotiationProtocol.status_resp, self.handle_stat_resp)
        self.protocol.register_handler(NegotiationProtocol.result, self.handle_results)
        # Trust-tier demotion → cancel in-flight tasks the peer is no
        # longer authorised for. Local IPC from ReputationProcess; see
        # doc/architecture/trust-tiers.md §7.2.
        self.protocol.register_handler(IdentityProtocol.tier_lost, self.handle_tier_lost)

    @property
    def peers(self):
        return self.protocol.peers

    @property
    def group(self):
        return self.protocol.group

    @property
    def capabilities(self):
        return self.protocol.capabilities

    @property
    def peer_capabilities(self):
        return self.protocol.peer_capabilities

    def _add_task(self, task):
        job = Job(task)
        if task.uuid not in self.task_stack or self.task_stack.count(job) <= self.max_concurrency:
            self.task_stack.push(job)
            if task.uuid in self.proposed_tasks:
                del self.proposed_tasks[task.uuid]
            return True
        return False

    def _get_jobs(self):
        jobs = []
        while len(self.task_stack) > 0 and now() >= self.task_stack.min():
            jobs.append(self.task_stack.pop())
        return jobs

    def start_task(self, queues, message):
        if message.function == NegotiationProtocol.start:
            if not isinstance(message.obj, Task):
                return False
            task = message.obj
            tracker = TaskTracker(task)
            self.my_tasks[task.uuid] = tracker
            self.status_pending.append(task)
            participants = []
            for cap_name, uuid_list in self.peer_capabilities.items():
                if cap_name == task.capability.name:
                    for peer_id in uuid_list:
                        peer = self.peers.find_by_uuid(peer_id)
                        if peer is not None:
                            participants.append(peer)
            # Optional single-peer addressing (R+D.md §12.7). `to_whom` unset
            # keeps the historical fan-out to every capable peer; set, it
            # narrows the announcement to that one peer.
            #
            # A honeypot probe needs this. Fanned out, a probe is announced to
            # N peers, `tracker.results` is pre-seeded for all of them below,
            # and `handle_results` forwards on the FIRST reply and drops the
            # tracker -- so one probe yields exactly one score, from whichever
            # peer answered first, and there is no way to say WHICH peer is
            # being probed. Allocation ("spend probes where the posterior is
            # widest") is meaningless without that, and a peer that never
            # answers first is never probed at all.
            target = getattr(message, 'to_whom', None)
            target_uuid = getattr(target, 'uuid', None)
            if target_uuid is not None:
                addressed = [p for p in participants
                             if getattr(p, 'uuid', None) == target_uuid]
                if not addressed:
                    # Asked for a peer that is not capable (or not known). Do
                    # not silently widen to everyone -- that would turn a
                    # targeted probe into a broadcast and score the wrong peer.
                    self.logger.warning(
                        'Task %s addressed to %s, which is not a capable peer',
                        task.capability.name, str(target_uuid)[:8])
                    queues[CfgIds.main].put(
                        TaskResult(task, Status.no_peers, None),
                        block=True, timeout=self.q_cadence)
                    return True
                participants = addressed
            if len(participants) < 1:
                self.logger.warning('No capable peers for task %s', task.capability.name)
                queues[CfgIds.main].put(
                    TaskResult(task, Status.no_peers, None),
                    block=True, timeout=self.q_cadence)
                return True
            # One stamp for the whole announcement, not one per peer. The
            # invitation is a single act fanned out to every capable peer, and
            # each receiver keeps its OWN high-water mark -- so it is
            # per-receiver monotonicity that does the work, and numbering the
            # copies separately would only make one act look like N. A later
            # re-announce (the haggle resolution below) draws a new, higher
            # number, which is what makes it distinguishable from a replay of
            # this one.
            task.seq = self.freshness.stamp()
            try:
                for peer in participants:
                    tracker.results[peer.uuid] = None
                    msg = Message(self.name, NegotiationProtocol.announce, task.to_json_string(), peer)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                    self.logger.debug('Sent task to %s', peer.nickname)
            except Full:
                self.logger.error('start_task: Network queue full')
            return True
        return False

    def handle_invite(self, queues, message):
        if message.function == NegotiationProtocol.announce:
            task = message.obj
            # Freshness FIRST, ahead of the flood counter, and silently.
            #
            # Ahead, because the counter is the thing a replay would otherwise
            # drive: six copies of one captured invitation would push
            # `flood_counts` past `max_task_duplicates` and make us refuse --
            # and a refusal is what the requestor reads as "this worker is out"
            # (`_cancel_participant`). That turns a replay into a way of
            # evicting a worker from a task it had already accepted. Past the
            # gate, the counter counts what it was built to count: distinct,
            # freshly stamped invitations for one task, which is a requestor
            # misbehaving rather than an attacker echoing.
            #
            # Silently, because a replay deserves no reply. Answering would
            # both spend a message on a sender we cannot vouch for and tell an
            # attacker exactly where our mark sits.
            #
            # Unstamped (seq 0, the proto3 default and what a peer that has not
            # been rebuilt emits) is refused, not admitted as legacy: a
            # receiver that accepts unstamped invitations is one an attacker
            # selects by not stamping. See doc/architecture/reputation.md,
            # "Quorum attestation", for the standing rule.
            sender = str(getattr(message.from_whom, 'uuid', '') or '')
            if not self.freshness.accept(sender, NegotiationProtocol.announce,
                                         getattr(task, 'seq', 0)):
                self.logger.debug(
                    'Invitation for %s from %s refused: sequence %s not above '
                    'mark %d (replay or unstamped)',
                    getattr(task, 'uuid', None), sender[:8],
                    getattr(task, 'seq', 0),
                    self.freshness.mark(sender, NegotiationProtocol.announce))
                return True
            if task.uuid not in self.proposed_tasks:
                self.proposed_tasks[task.uuid] = TaskCounter(task)
            self.proposed_tasks[task.uuid].count += 1
            self.flood_counts[task.uuid] = self.flood_counts.get(task.uuid, 0) + 1
            # Flood threshold: refuse the invite and short-circuit further
            # processing. Mirrors C's neg_proc.c handle_invite — see BUGS.md
            # §P7 for counter persistence and the past-threshold action
            # alignment rationale.
            if self.flood_counts[task.uuid] > self.max_task_duplicates:
                self.logger.warning(
                    'Negotiation: flood detected for task %s (count=%d), refusing', task.uuid, self.flood_counts[task.uuid])
                try:
                    msg = Message(self.name, NegotiationProtocol.refusal,
                                  task.to_json_string(), message.from_whom)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                except Full:
                    self.logger.error('handle_invite: Network queue full (flood-refuse)')
                return True
            try:
                if task.capability not in self.capabilities:
                    msg = Message(self.name, NegotiationProtocol.refusal, task.to_json_string(), message.from_whom)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                    self.logger.debug('Remote task refused: not capable')
                else:
                    # Trust-tier gate. Refuse if the sender's reputation-
                    # derived tier is below the capability's required_tier
                    # (capabilities.py:Capability). Generalises the prior
                    # hierarchy-bucket check; see
                    # doc/architecture/trust-tiers.md §7.1.
                    sender = None
                    if message.from_whom is not None:
                        sender = self.peers.find_by_uuid(
                            getattr(message.from_whom, 'uuid', None))
                    sender_tier = getattr(sender, '_tier', 0) if sender is not None else 0
                    # Capabilities is keyed by name; the task carries a
                    # serialized Capability whose required_tier may have
                    # been built with defaults (e.g. by a remote peer or
                    # the conformance harness). The local registered
                    # Capability — set via TrustLadder at startup —
                    # is the authoritative source of required_tier for
                    # gating *my* acceptance. See trust-tiers.md §7.1.
                    local_cap = self.capabilities[task.capability.name]
                    required_tier = getattr(local_cap, 'required_tier', 0)
                    if sender_tier < required_tier:
                        msg = Message(self.name, NegotiationProtocol.refusal,
                                      task.to_json_string(), message.from_whom)
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                        self.logger.debug(
                            'Remote task refused: sender tier %d < required %d',
                            sender_tier, required_tier)
                    elif task.parameters.acceptable():
                        if self._add_task(task):
                            msg = Message(self.name, NegotiationProtocol.acceptance,
                                          task.to_json_string(), message.from_whom)
                            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                            self.logger.debug('Remote task accepted')
                        else:
                            task.parameters.when = self.task_stack.find_nearest_slot(task)
                            msg = Message(self.name, NegotiationProtocol.response,
                                          task.to_json_string(), message.from_whom)
                            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                            self.logger.debug('Haggle over remote task timing')
                    else:
                        task.adjust()
                        msg = Message(self.name, NegotiationProtocol.response,
                                      task.to_json_string(), message.from_whom)
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                        self.logger.debug('Haggle over remote task content')
            except Full:
                self.logger.error('handle_invite: Network queue full')
            return True
        return False

    def _cancel_participant(self, queues, message):
        task = message.obj
        result = self.my_tasks[task.uuid].results
        if result[message.from_whom.uuid] is None:
            del result[message.from_whom.uuid]
        # Drop the confirmation too, mirroring the C twin's removal of its
        # per-(task, peer) marker: a peer we have cancelled out of a task must
        # not still read as confirmed in handle_stat_resp, or it can go on
        # spending the extension token for work it is no longer doing.
        confirmed = self.confirmed.get(task.uuid)
        if confirmed is not None and message.from_whom in confirmed:
            confirmed.remove(message.from_whom)
        if len(result) < task.size:
            queues[CfgIds.main].put(result, block=True, timeout=self.q_cadence)

    def handle_haggle(self, queues, message):
        if message.function == NegotiationProtocol.response:
            task = message.obj
            if task.parameters.flexible:
                try:
                    # Accept the peer's counter-proposal if our parameters allow it
                    if task.uuid in self.my_tasks:
                        # The tracker IS the task (TaskTracker subclasses
                        # Task); it has no `.task` attribute, so the old
                        # `.task` raised AttributeError out of this handler and
                        # no re-announce was ever sent. Likewise `adjust` is
                        # defined on TaskParameters, not on Task.
                        original = self.my_tasks[task.uuid]
                        if task.parameters.when != original.parameters.when:
                            original.parameters.when = task.parameters.when
                        original.parameters.adjust()
                        task = original
                    # A fresh stamp: this is a NEW invitation, carrying the
                    # schedule we just conceded, and the peer's mark has
                    # already consumed the sequence of the first one. Reusing
                    # that sequence would have the peer refuse the resolution
                    # as a replay -- correctly, since it cannot tell the two
                    # apart otherwise.
                    task.seq = self.freshness.stamp()
                    msg = Message(self.name, NegotiationProtocol.announce, task.to_json_string(), message.from_whom)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                    self.logger.debug('Attempt to resolve haggling')
                except Full:
                    self.logger.error('handle_haggle: Network queue full')
            else:
                try:
                    self._cancel_participant(queues, message)
                except Full:
                    self.logger.error('handle_haggle: Main queue full')
            return True
        return False

    def handle_accept(self, _, message):
        if message.function == NegotiationProtocol.acceptance:
            task = message.obj
            if task.uuid not in self.confirmed:
                self.confirmed[task.uuid] = []
            # One participant, one promise. An `ack` carries nothing that
            # separates a second delivery from a second promise, so a replayed
            # one used to lengthen this list — inflating the count of peers
            # believed to have committed to the task. Same dedup-by-sender
            # shape as ReputationProcess.handle_accepted, and it keeps this
            # list consistent with the `in` test handle_stat_resp already
            # runs against it (Identity.__eq__ compares uuid/address/keys).
            if message.from_whom not in self.confirmed[task.uuid]:
                self.confirmed[task.uuid].append(message.from_whom)
            self.logger.debug('Execution of my task promised')
            return True
        return False

    def handle_refuse(self, queues, message):
        if message.function == NegotiationProtocol.refusal:
            try:
                self._cancel_participant(queues, message)
                self.logger.debug('My task refused')
            except Full:
                self.logger.error('handle_refuse: Main queue full')
            return True
        return False

    def handle_stat_req(self, queues, message):
        if message.function == NegotiationProtocol.status_req:
            task_status = TaskStatus(message.obj, message.from_whom)
            if task_status.uuid in self.task_stack:
                task_status.status = Status.pending
                self.forward_status(queues, task_status)
            else:
                try:
                    queues[CfgIds.main].put(task_status, block=True, timeout=self.q_cadence)
                    self.logger.debug('Remote status requested')
                except Full:
                    self.logger.error('handle_stat_req: Main queue full')
            return True
        return False

    def forward_status(self, queues, message):
        if isinstance(message, TaskStatus):
            if message.status is not None:
                try:
                    msg = Message(self.name, NegotiationProtocol.status_resp,
                                  message.to_json_string(), message.requestor)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                    self.logger.debug('Local status for forwarding')
                except Full:
                    self.logger.error('forward_status: Network queue full')
            return True
        return False

    def handle_stat_resp(self, queues, message):
        if message.function == NegotiationProtocol.status_resp:
            task = message.obj
            if isinstance(task, TaskStatus):
                self.logger.debug('Remote status received')
                if task.status in [Status.running, Status.sleeping, Status.pending]:
                    if task.status == Status.pending:
                        self.logger.error('Clock synchronization error with %s', message.from_whom.nickname)
                    if task.uuid in self.confirmed and message.from_whom in self.confirmed[task.uuid]:
                        # The outstanding status request is the token that
                        # authorises one extension, and it is consumed here, so
                        # a replayed (or unsolicited) status response finds
                        # nothing to consume and cannot extend the deadline a
                        # second time.
                        #
                        # Matched by uuid throughout, for two reasons. The wire
                        # object is a fresh TaskStatus while the entries are the
                        # original Task / TaskTracker, and Configuration defines
                        # no __eq__ — so the old identity-based `remove` matched
                        # nothing and raised ValueError out of this handler
                        # instead of extending anything. And `status_pending`
                        # can legitimately hold two entries for one task (the
                        # Task from start_task, the TaskTracker from the
                        # re-request in process()), so ALL of them are drained:
                        # leaving one behind would leave a second token for a
                        # replay to spend.
                        tracker = self.my_tasks.get(task.uuid)
                        pending = [t for t in self.status_pending
                                   if t.uuid == task.uuid]
                        if tracker is not None and pending:
                            # OUR parameters, not the peer's. The deadline being
                            # extended is the one process() checks against
                            # `tracker.parameters`, so extending a copy of the
                            # peer's parameters moved nothing; and the size of
                            # our own patience is not the remote end's call to
                            # make.
                            params = tracker.parameters
                            extend = params.timeout_extension
                            if params.timeout.total_seconds() > 0:
                                extend = params.timeout.total_seconds()
                            elif params.duration.total_seconds() > 0:
                                extend = int(params.duration.total_seconds() * params.duration_fraction / 100) + 1
                            params.timeout += timedelta(seconds=extend)
                            for entry in pending:
                                self.status_pending.remove(entry)
                elif task.status in [Status.dead, Status.zombie, Status.stopped, Status.unknown]:
                    try:
                        self._cancel_participant(queues, message)
                    except Full:
                        self.logger.error('handle_stat_resp: Main queue full')
            return True
        return False

    def forward_result(self, queues, message):
        if isinstance(message, TaskResult):
            try:
                msg = Message(self.name, NegotiationProtocol.result, message.to_json_string(), message.requestor)
                queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                self.logger.debug('Local result for forwarding')
            except Full:
                self.logger.error('forward_result: Network queue full')
            return True
        return False

    def handle_results(self, queues, message):
        if message.function == NegotiationProtocol.result:
            task = message.obj
            if task.uuid in self.my_tasks:
                try:
                    tracker = self.my_tasks[task.uuid]
                    results = tracker.results
                    results[message.from_whom.uuid] = task.result
                    if len(results) >= task.size:
                        # Stamp the result with what WE asked for, before the
                        # `del` below drops our only copy (R+D.md §12.7).
                        # TaskInfo carries no `parameters`, so without this the
                        # requestor-side scorer in automate.py cannot tell which
                        # capability produced the result, let alone what
                        # challenge was sent -- which is why the bootstrap
                        # corpus's known-answer verifiers had nothing to
                        # compare against and every probe scored as a plain
                        # completion. Taken from `tracker` (our retained Task),
                        # never from the responder's reply: see
                        # TaskResult.attach_requested_parameters for why reading
                        # the challenge off the reply would verify nothing.
                        # The `result` verb carries a TaskResult in
                        # production, but this handler is reachable with a bare
                        # Task (the status/error paths build one, and the unit
                        # tests exercise that shape), so stamp only what can be
                        # stamped rather than raising out of the handler.
                        # WHO answered, for the same reason and from the same
                        # side of the wire (R+D.md §12.8): the requestor-side
                        # scorer produces the evidence channel, and a
                        # refutation that cannot name the peer it refutes is
                        # scored but not actionable. Only for a single-
                        # participant task -- see attach_executor.
                        attach_who = getattr(task, 'attach_executor', None)
                        if attach_who is not None:
                            attach_who(next(iter(results))
                                       if len(results) == 1 else None)
                        attach = getattr(task, 'attach_requested_parameters',
                                         None)
                        if attach is None:
                            self.logger.debug(
                                'handle_results: %s carries no requested-'
                                'parameter fields; forwarded unstamped',
                                type(task).__name__)
                        elif not attach(tracker):
                            self.logger.debug(
                                'handle_results: no parameters retained for '
                                'task %s; result forwarded unstamped',
                                task.uuid)
                        queues[CfgIds.main].put(task, block=True, timeout=self.q_cadence)
                        self.logger.debug('Task results forwarded')
                    del self.my_tasks[task.uuid]  # no more results accepted
                except Full:
                    self.logger.error('handle_results: Main queue full')
            return True
        return False

    def handle_tier_lost(self, queues, message):
        """Cancel in-flight tasks the affected peer is no longer
        authorised to participate in. Triggered by a tier_lost IPC
        from ReputationProcess on demotion. See
        doc/architecture/trust-tiers.md §7.2.

        Walks two surfaces:
        - ``self.task_stack`` (worker side): jobs scheduled for me to
          execute on behalf of the affected peer. Cancelled if the
          task's capability.required_tier > new_tier.
        - ``self.my_tasks`` (requestor side): trackers for tasks I've
          requested from peers. If the affected peer is a participant
          AND the capability now requires a higher tier than they
          hold, drop them from the tracker.
        """
        if message.function != IdentityProtocol.tier_lost:
            return False
        try:
            payload = (from_json_string(message.obj)
                       if isinstance(message.obj, (str, bytes))
                       else message.obj)
            if not (isinstance(payload, (list, tuple)) and len(payload) >= 2):
                self.logger.warning('handle_tier_lost: bad payload %r', payload)
                return True
            peer_uuid_str, new_tier = str(payload[0]), int(payload[1])
        except Exception as err:
            self.report_exception(err, 'handle_tier_lost')
            return True

        try:
            # Normalize: target keeps a UUID for set-key lookups in
            # tracker.results (which use UUID keys), and a string for
            # comparing against task.requestor.uuid — that attribute
            # round-trips through JSON as a string in production IPC.
            target_uuid = UUID(peer_uuid_str)
            target_str = str(target_uuid)
        except (ValueError, AttributeError):
            self.logger.warning(
                'handle_tier_lost: bad peer uuid %r', peer_uuid_str)
            return True

        cancelled_jobs = 0
        # Worker-side: cancel scheduled jobs originated by the
        # demoted peer when their tier no longer satisfies the
        # capability's required_tier. JobQueue stores tuples on a
        # heap; iterate ._heap directly (no public __iter__). The
        # required_tier comes from the locally-registered capability,
        # not the wire-form Capability on the task — same policy
        # source as handle_invite's tier gate.
        try:
            kept: list = []
            for entry in list(self.task_stack._heap):
                job = entry[2]
                task = job.task
                try:
                    local_cap = self.capabilities[task.capability.name]
                except KeyError:
                    local_cap = task.capability
                req = getattr(local_cap, 'required_tier', 0)
                requestor = getattr(task, 'requestor', None)
                req_uuid = getattr(requestor, 'uuid', None) if requestor is not None else None
                if req_uuid is not None and str(req_uuid) == target_str and req > new_tier:
                    cancelled_jobs += 1
                    self.logger.info(
                        'Cancelling scheduled task %s: requestor %s tier %d < required %d',
                        task.uuid, peer_uuid_str, new_tier, req)
                else:
                    kept.append(job)
            if cancelled_jobs:
                self.task_stack.clear()
                for j in kept:
                    self.task_stack.push(j)
        except Exception as err:
            self.report_exception(err, 'handle_tier_lost.task_stack')

        # Requestor-side: drop the demoted peer from any tracker
        # whose capability now exceeds their tier. TaskTracker IS a
        # Task subclass (carries .capability and .results directly);
        # there is no nested `.task` attribute. Tracker.results may
        # be keyed by either UUID or str depending on whether the
        # tracker was populated locally (UUID) or via the JSON IPC
        # path (str) — match either. If dropping empties the tracker,
        # emit TaskResult(Status.cancelled) to main and remove the
        # entry so further `result` messages are rejected. The
        # required_tier comes from the locally-registered capability
        # when known; falls back to the wire-form Capability on the
        # tracker (defaulting to 0).
        try:
            for task_uuid, tracker in list(self.my_tasks.items()):
                try:
                    local_cap = self.capabilities[tracker.capability.name]
                except KeyError:
                    local_cap = tracker.capability
                req = getattr(local_cap, 'required_tier', 0)
                if req <= new_tier:
                    continue
                # Try both UUID and str forms — tracker.results may
                # carry either depending on construction path.
                drop_key = None
                if target_uuid in tracker.results:
                    drop_key = target_uuid
                elif target_str in tracker.results:
                    drop_key = target_str
                if drop_key is not None:
                    del tracker.results[drop_key]
                    cancelled_jobs += 1
                    self.logger.info(
                        'Dropped %s from task %s: tier %d < required %d',
                        peer_uuid_str, task_uuid, new_tier, req)
                if len(tracker.results) == 0:
                    try:
                        result = TaskResult(
                            tracker, Status.cancelled, None)
                        queues[CfgIds.main].put(
                            result, block=True, timeout=self.q_cadence)
                    except Full:
                        self.logger.error(
                            'handle_tier_lost: main queue full')
                    del self.my_tasks[task_uuid]
        except Exception as err:
            self.report_exception(err, 'handle_tier_lost.my_tasks')

        if cancelled_jobs:
            self.logger.info(
                'tier_lost on %s -> %d: %d task(s) cancelled',
                peer_uuid_str, new_tier, cancelled_jobs)
        return True

    def process(self, queues, signal):
        # Drain budget per iter — same shape as repprocess.py. The
        # periodic local-jobs / status-pending sweeps below run after
        # the drain, so they fire roughly every q_cadence-ish (when
        # the queue is idle) or as fast as the drain budget allows
        # (when there's a backlog). The old sleep_until(self.cadence)
        # capped throughput at ~2 msgs/s; pacing now comes from the
        # blocking get's q_cadence timeout when there's no work.
        DRAIN_BUDGET = 64
        while self.keep_running(signal):
            try:
                drained = 0
                first = True
                while drained < DRAIN_BUDGET:
                    try:
                        if first:
                            message = queues[self.name].get(
                                block=True, timeout=self.q_cadence)
                            first = False
                        else:
                            message = queues[self.name].get_nowait()
                    except Empty:
                        break
                    drained += 1
                    if not self.protocol.run_message_handlers(queues, message):
                        if not self.forward_status(queues, message):
                            if not self.forward_result(queues, message):
                                if isinstance(message, tuple) and len(message) > 1 and \
                                        isinstance(message[1], Capability):
                                    self.peer_capabilities[message[0]] = message[1]
                                else:
                                    if isinstance(message, Message):
                                        _probes.counter('proc.negotiation', 'unhandled', message.function)
                                        _probes.trace_msg(message, 'unhandled', proc='negotiation')
                                        self.logger.error('Unhandled message %s', message.function)
                                    else:
                                        _probes.counter('proc.negotiation', 'unhandled', 'type:' + message.__class__.__name__)
                                        self.logger.error('Unhandled message of type %s', message.__class__.__name__)  # noqa
                _probes.counter('proc.negotiation', 'iter_drained', str(drained))

                for job in self._get_jobs():  # local jobs
                    try:
                        queues[CfgIds.main].put(job.task, block=True, timeout=self.q_cadence)
                        self.logger.debug('Send for execution')
                    except Full:
                        self.logger.error('process: Main queue full')

                present = now()
                for task_id in self.my_tasks:  # remote jobs
                    task = self.my_tasks[task_id]
                    params = task.parameters
                    try:
                        # Outstanding-request test by uuid, matching the way
                        # handle_stat_resp consumes the entry. Identity
                        # comparison here saw start_task's Task and this
                        # tracker as different objects, so a task could carry
                        # two pending entries at once — and two entries are two
                        # extension tokens.
                        if not any(t.uuid == task.uuid for t in self.status_pending) and \
                                present > params.when + params.duration + params.timeout:
                            tx_task = Task(**task.to_dict())
                            msg = Message(self.name, NegotiationProtocol.status_req,
                                          tx_task.to_json_string(), task.requestor)
                            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                            self.logger.debug('Request remote execution status from %s', task.requestor.nickname)
                            self.status_pending.append(task)
                    except Full:
                        self.logger.error('process: Network queue full')
            except Exception as err:
                self.logger.error(err)
                self.logger.error(traceback.format_exc())
            # CPU-yield floor (see repprocess): queue.get's q_cadence timeout
            # only sleeps on a fully idle window, so under continuous traffic
            # this loop would spin at 100%. sleep_until yields the rest of a
            # ~10ms window when unsaturated. AT_PROC_IDLE_FLOOR_SEC=0 disables.
            self.sleep_until(proc_idle_floor)
