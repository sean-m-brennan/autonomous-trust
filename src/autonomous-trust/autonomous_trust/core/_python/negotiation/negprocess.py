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

import traceback
from queue import Empty, Full
from datetime import timedelta

from ..capabilities import Capability
from ..network import Message
from ..processes import Process, ProcMeta
from .protocol import NegotiationProtocol
from .negotiation import Job, JobQueue, Task, TaskStatus, TaskTracker, TaskCounter, TaskResult, Status
from ..system import CfgIds, max_concurrency, now
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
        self.max_concurrency = max_cores
        self.protocol = NegotiationProtocol(self.name, self.logger, configurations)
        self.protocol.register_handler(NegotiationProtocol.start, self.start_task)
        self.protocol.register_handler(NegotiationProtocol.announce, self.handle_invite)
        self.protocol.register_handler(NegotiationProtocol.response, self.handle_haggle)
        self.protocol.register_handler(NegotiationProtocol.acceptance, self.handle_accept)
        self.protocol.register_handler(NegotiationProtocol.status_req, self.handle_stat_req)
        self.protocol.register_handler(NegotiationProtocol.status_resp, self.handle_stat_resp)
        self.protocol.register_handler(NegotiationProtocol.result, self.handle_results)

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
            if len(participants) < 1:
                self.logger.warning('No capable peers for task %s' % task.capability.name)
                queues[CfgIds.main].put(
                    TaskResult(task, Status.no_peers, None),
                    block=True, timeout=self.q_cadence)
                return True
            try:
                for peer in participants:
                    tracker.results[peer.uuid] = None
                    msg = Message(self.name, NegotiationProtocol.announce, task.to_json_string(), peer)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                    self.logger.debug('Sent task to %s' % peer.nickname)
            except Full:
                self.logger.error('start_task: Network queue full')
            return True
        return False

    def handle_invite(self, queues, message):
        if message.function == NegotiationProtocol.announce:
            task = message.obj
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
                    'Negotiation: flood detected for task %s (count=%d), refusing'
                    % (task.uuid, self.flood_counts[task.uuid]))
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
                    sender_level = self.peers._find(self.peers._index_by(message.from_whom))
                    if sender_level is not None and sender_level == 0:
                        msg = Message(self.name, NegotiationProtocol.refusal,
                                      task.to_json_string(), message.from_whom)
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                        self.logger.debug('Remote task refused: peer reputation too low')
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
        if len(result) < task.size:
            queues[CfgIds.main].put(result, block=True, timeout=self.q_cadence)

    def handle_haggle(self, queues, message):
        if message.function == NegotiationProtocol.response:
            task = message.obj
            if task.parameters.flexible:
                try:
                    # Accept the peer's counter-proposal if our parameters allow it
                    if task.uuid in self.my_tasks:
                        original = self.my_tasks[task.uuid].task
                        if task.parameters.when != original.parameters.when:
                            original.parameters.when = task.parameters.when
                        original.adjust()
                        task = original
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
                        self.logger.error('Clock synchronization error with %s' % message.from_whom.nickname)
                    if task.uuid in self.confirmed and message.from_whom in self.confirmed[task.uuid]:
                        params = task.parameters
                        extend = params.timeout_extension
                        if params.timeout.total_seconds() > 0:
                            extend = params.timeout.total_seconds()
                        elif params.duration.total_seconds() > 0:
                            extend = int(params.duration.total_seconds() * params.duration_fraction / 100) + 1
                        params.timeout += timedelta(seconds=extend)
                        self.status_pending.remove(task)
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
                    results = self.my_tasks[task.uuid].results
                    results[message.from_whom.uuid] = task.result
                    if len(results) >= task.size:
                        queues[CfgIds.main].put(task, block=True, timeout=self.q_cadence)
                        self.logger.debug('Task results forwarded')
                    del self.my_tasks[task.uuid]  # no more results accepted
                except Full:
                    self.logger.error('handle_results: Main queue full')
            return True
        return False

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
                                        self.logger.error('Unhandled message %s' % message.function)
                                    else:
                                        _probes.counter('proc.negotiation', 'unhandled', 'type:' + message.__class__.__name__)
                                        self.logger.error('Unhandled message of type %s' % message.__class__.__name__)  # noqa
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
                        if task not in self.status_pending and \
                                present > params.when + params.duration + params.timeout:
                            tx_task = Task(**task.to_dict())
                            msg = Message(self.name, NegotiationProtocol.status_req,
                                          tx_task.to_json_string(), task.requestor)
                            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                            self.logger.debug('Request remote execution status from %s' % task.requestor.nickname)
                            self.status_pending.append(task)
                    except Full:
                        self.logger.error('process: Network queue full')
            except Exception as err:
                self.logger.error(err)
                self.logger.error(traceback.format_exc())
