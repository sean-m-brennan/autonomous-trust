from queue import Empty
from datetime import datetime, timedelta

from ..capabilities import Capability
from ..network import Message
from ..processes import Process, ProcMeta
from ..config import CfgIds
from .protocol import NegotiationProtocol
from .negotiation import Job, JobQueue, TaskStatus, TaskTracker, TaskCounter, TaskResult, Status
from ..system import max_concurrency


class NegotiationProcess(Process, metaclass=ProcMeta,
                         proc_name=CfgIds.negotiation, description='Negotiate transactions'):
    """
    Handle transaction agreement negotiations
    """
    max_task_duplicates = 5

    def __init__(self, configurations, subsystems, log_q, max_cores=max_concurrency):
        super().__init__(configurations, subsystems, log_q,
                         dependencies=[CfgIds.network, CfgIds.identity])
        self.task_stack = JobQueue()
        self.proposed_tasks = {}  # TaskCounters for local tasks remotely requested
        self.my_tasks = {}  # TaskTrackers for remote tasks I've requested
        self.confirmed = {}
        self.status_pending = []
        self.max_concurrency = max_cores
        self.peer_capabilities = {}
        self.protocol = NegotiationProtocol(self.name, self.logger, configurations[CfgIds.peers])
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
        while datetime.utcnow() >= self.task_stack.min():
            jobs.append(self.task_stack.pop())
        return jobs

    def start_task(self, queues, message):
        if message.function == NegotiationProtocol.start:
            task = message.obj
            tracker = TaskTracker(task)
            self.my_tasks[task.uuid] = tracker
            participants = []
            for uuid, cap in self.peer_capabilities.items():
                if cap == task.capability:
                    participants.append(self.peers.find_by_uuid(uuid))
            for peer in participants:
                tracker.results[peer.uuid] = None
                msg = Message(self.name, NegotiationProtocol.acceptance, task, peer)
                queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
            return True
        return False

    def handle_invite(self, queues, message):
        if message.function == NegotiationProtocol.announce:
            task = message.obj
            if task.uuid not in self.proposed_tasks:
                self.proposed_tasks[task.uuid] = TaskCounter(task)
            self.proposed_tasks[task.uuid].count += 1
            if self.proposed_tasks[task.uuid].count > self.max_task_duplicates:
                self.peers.demote(message.from_whom)

            if task.capability not in self.capabilities:
                msg = Message(self.name, NegotiationProtocol.refusal, task, message.from_whom)
                queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
            else:
                # TODO reputation too low, etc.
                if task.parameters.acceptable():
                    if self._add_task(task):
                        msg = Message(self.name, NegotiationProtocol.acceptance, task, message.from_whom)
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                    else:
                        task.parameters.when = self.task_stack.find_nearest_slot(task)
                        msg = Message(self.name, NegotiationProtocol.response, task, message.from_whom)
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                else:
                    task.adjust()
                    msg = Message(self.name, NegotiationProtocol.response, task, message.from_whom)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
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
        if message.function == NegotiationProtocol.announce:
            task = message.obj
            if task.parameters.flexible:
                alt_task = task  # FIXME address any conflicts in parameters
                msg = Message(self.name, NegotiationProtocol.response, alt_task, message.from_whom)
                queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
            else:
                self._cancel_participant(queues, message)
            return True
        return False

    def handle_accept(self, _, message):
        if message.function == NegotiationProtocol.acceptance:
            task = message.obj
            if task.uuid not in self.confirmed:
                self.confirmed[task.uuid] = []
            self.confirmed[task.uuid].append(message.from_whom)
            return True
        return False

    def handle_refuse(self, queues, message):
        if message.function == NegotiationProtocol.refusal:
            self._cancel_participant(queues, message)
            return True
        return False

    def handle_stat_req(self, queues, message):
        if message.function == NegotiationProtocol.status_req:
            task_status = TaskStatus(message.obj, message.from_whom)
            if task_status.uuid in self.task_stack:
                task_status.status = Status.pending
                self.handle_status(queues, task_status)
            else:
                queues[CfgIds.main].put(task_status, block=True, timeout=self.q_cadence)
            return True
        return False

    def handle_status(self, queues, message):
        if isinstance(message, TaskStatus):
            if message.status is not None:
                msg = Message(self.name, NegotiationProtocol.status_resp, message, message.requestor)
                queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
            return True
        return False

    def handle_stat_resp(self, queues, message):
        if message.function == NegotiationProtocol.status_resp:
            task = message.obj
            if isinstance(task, TaskStatus):
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
                    self._cancel_participant(queues, message)
            return True
        return False

    def handle_results(self, queues, message):
        if message.function == NegotiationProtocol.result:
            if isinstance(message.obj, TaskResult):
                task = message.obj
                if task.uuid in self.my_tasks:
                    results = self.my_tasks[task.uuid].results
                    results[message.from_whom.uuid] = task.result
                    if len(results) >= task.size:
                        queues[CfgIds.main].put(task, block=True, timeout=self.q_cadence)
                    del self.my_tasks[task.uuid]  # no more results accepted
            return True
        return False

    def process(self, queues, signal):
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                if not self.protocol.run_message_handlers(queues, message):
                    if not self.handle_status(queues, message):
                        if isinstance(message, tuple) and len(message) > 1 and \
                                isinstance(message[1], Capability):
                            self.peer_capabilities[message[0]] = message[1]

            for task in self._get_jobs():  # local jobs
                queues[CfgIds.main].put(task, block=True, timeout=self.q_cadence)

            now = datetime.utcnow()
            for task_id in self.my_tasks:  # remote jobs
                task = self.my_tasks[task_id]
                params = task.parameters
                if task not in self.status_pending and \
                        now > params.when + params.duration + params.timeout:
                    msg = Message(self.name, NegotiationProtocol.status_req, task, task.requestor)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                    self.status_pending.append(task)

            self.sleep_until(self.cadence)
