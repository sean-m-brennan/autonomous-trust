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

from datetime import UTC, datetime, timedelta
import heapq
from enum import Enum
from queue import Empty
from typing import Union, Optional
from uuid import UUID, uuid4

import psutil

from ..system import max_concurrency, now
from ..config import Configuration


# TODO tie clock quality to reputation. AT no longer implements NTP: a stock
# daemon disciplines the host clock and network/clock.py reads what it achieved
# (NtpTimeSource.trustworthy). A peer whose clock nothing is steering is the
# reputation-relevant signal, not a sync AT performs itself.

class Status(Enum):
    running = 'running'
    sleeping = 'sleeping'
    zombie = 'zombie'
    stopped = 'stopped'
    dead = 'dead'
    pending = 'pending'  # has not started yet
    unknown = 'unknown'  # not tracking this task
    no_peers = 'no_peers'  # no capable peers found
    rejected = 'rejected'  # task rejected (reputation too low, etc.)
    cancelled = 'cancelled'  # task cancelled mid-flight (e.g. tier_lost; see trust-tiers.md §7.2)

    @classmethod
    def from_ps(cls, status):
        if status == psutil.STATUS_RUNNING:
            return cls.running
        if status in [psutil.STATUS_SLEEPING, psutil.STATUS_DISK_SLEEP, psutil.STATUS_WAKING]:
            return cls.sleeping
        if status in [psutil.STATUS_STOPPED, psutil.STATUS_TRACING_STOP]:
            return cls.stopped
        if status == psutil.STATUS_ZOMBIE:
            return cls.zombie
        if status == psutil.STATUS_DEAD:
            return cls.dead
        return None


class TaskParameters(Configuration):
    default_duration = 1
    default_timeout = 30
    timeout_extension = 120  # seconds
    duration_fraction = 10  # percent

    def __init__(self, _capability, _flexible=True, when: datetime = None, duration: timedelta = None,
                 timeout: timedelta = None, args=None, kwargs=None):
        self._capability = _capability
        self._flexible = _flexible
        self.when = when
        if when is None:
            self.when = now()
        self.duration = duration
        if duration is None:
            self.duration = timedelta(seconds=self.default_duration)
        self.timeout = timeout
        if timeout is None:
            self.timeout = timedelta(seconds=self.default_timeout)
        self.args = args
        if args is None:
            self.args = ()
        self.kwargs = kwargs
        if kwargs is None:
            self.kwargs = {}

    def acceptable(self):
        return True

    def adjust(self):  # tailor to acceptable parameters
        pass

    @property
    def capability(self):
        return self._capability

    @property
    def flexible(self):
        # `_flexible` is the constructor-time storage (private to mirror
        # `_capability`); production handlers read `parameters.flexible`,
        # so expose it as a property — without this, `handle_haggle` (and
        # any other reader) raises AttributeError. Surfaced by the
        # negotiation `invite-haggle-counterprop` conformance scenario
        # (the prior corpus never delivered a haggle, so this code path
        # was unreachable in tests).
        return self._flexible


class TaskInfo(Configuration):
    def __init__(self, requestor, uuid: UUID = None, size=1, seq=0, **kwargs):
        self.uuid = uuid
        if uuid is None:
            self.uuid = uuid4()
        self.requestor = requestor
        self.size = size
        # Freshness sequence of the INVITATION that carried this task; 0 means
        # unstamped, which `handle_invite` refuses. The requestor's monotonic
        # per-process counter (``core/freshness.py``), stamped by `start_task`
        # and by the re-announce in `handle_haggle`, and checked against the
        # receiver's per-(sender, verb) high-water mark.
        #
        # Why the task and not a separate envelope: an invitation's payload IS
        # a serialized task, in both runtimes and in the protobuf schema
        # (`negotiation/task.proto`, field 12), so there is nowhere else to put
        # it without inventing a second wrapper for one verb. It lives on
        # TaskInfo rather than Task so the field survives the
        # `Task(**task.to_dict())` round-trips that TaskStatus, TaskResult,
        # TaskCounter and TaskTracker are built from.
        #
        # Only the `announce` verb stamps it and only `handle_invite` reads it.
        # The other verbs that reuse this serialization (acceptance, refusal,
        # status, results) carry whatever value came in and nothing looks at
        # it -- deliberately inert rather than zeroed, so a task object stays a
        # faithful copy of the invitation it came from.
        self.seq = int(seq or 0)
        # ignore kwargs


class Task(TaskInfo):
    def __init__(self, parameters: TaskParameters, requestor, **kwargs):
        super().__init__(requestor, **kwargs)
        self.parameters = parameters
        # ignore kwargs

    @property
    def capability(self):
        return self.parameters.capability


class TaskStatus(Task):
    def __init__(self, task=None, status=None, **kwargs):
        if task is None:
            task_args = {}
        else:
            task_args = task.to_dict()
        super().__init__(**task_args, **kwargs)
        self.status = status


class TaskResult(TaskInfo):
    """A returned result. Note ``TaskInfo`` carries no ``parameters``, so a
    TaskResult does NOT know which capability produced it or what it was
    asked — see ``attach_requested_parameters`` for how the requestor
    supplies that from its own record.
    """

    def __init__(self, task=None, result=None, proof=None,
                 requested_capability_name: str = None,
                 requested_args=None, requested_kwargs=None, **kwargs):
        if task is None:
            task_args = {}
        else:
            task_args = task.to_dict()
        super().__init__(**task_args, **kwargs)
        self.result = result
        self.proof = proof
        # What the REQUESTOR asked for, filled in on the requestor side by
        # `attach_requested_parameters` (R+D.md §12.7). Default None/empty:
        # an executor building a TaskResult has no business asserting these,
        # and a peer that sends them populated is simply ignored, because the
        # requestor overwrites them from its own record before anything reads
        # them. See the integrity note on that method.
        self.requested_capability_name = requested_capability_name
        self.requested_args = tuple(requested_args or ())
        self.requested_kwargs = dict(requested_kwargs or {})
        # WHO produced this result, stamped on the requestor side by
        # `attach_executor` from the authenticated sender of the reply
        # (R+D.md §12.8). Local-only: `to_dict` drops it, so it is never
        # serialized and an executor cannot assert its own identity here --
        # the same integrity argument as `requested_*` above, and what lets a
        # refutation name the peer it accuses.
        self.executor_uuid = None

    def to_dict(self):
        # `executor_uuid` is the requestor's own attribution, not part of the
        # result: it is derived from the transport-verified sender of the
        # reply, so serializing it would let a forwarded copy carry an
        # assertion nobody re-checked. Same discipline as
        # TransactionScore.subject_uuid.
        d = super().to_dict()
        d.pop('executor_uuid', None)
        return d

    def attach_executor(self, executor_uuid) -> bool:
        """Stamp this result with the peer that produced it.

        ``executor_uuid`` comes from ``message.from_whom`` on the reply --
        transport-authenticated and verified -- never from the payload. Pass
        None to record explicitly that the result is NOT attributable to one
        peer, which is the honest answer for a multi-participant task: the
        results of a fan-out arrive from several peers and only the last one
        to answer carries the object that gets scored, so naming it would
        attribute the whole task's outcome to whoever happened to reply last.

        Clears first, like ``attach_requested_parameters`` and for the same
        reason. Returns True if an executor was attached.
        """
        self.executor_uuid = None
        if executor_uuid is None:
            return False
        self.executor_uuid = str(executor_uuid)
        return True

    def attach_requested_parameters(self, original) -> bool:
        """Stamp this result with what *we* asked for, from ``original``.

        ``original`` is the requestor's own retained Task (the
        ``TaskTracker`` in ``NegotiationProcess.my_tasks``), NOT anything
        the responder sent. That distinction is the whole point, and it is
        what makes a honeypot probe verifiable at all: a known-answer check
        that reads the challenge out of the *responder's* reply verifies
        nothing, because a peer that computed the wrong answer can simply
        report the challenge its answer would have been right for
        (``result=99, nonce=98`` scores as a correct increment). The
        expected value therefore has to come from this side of the wire.

        Nothing secret is being moved: the challenge was sent TO the
        responder in the invitation, so it already knows it. The property
        this protects is integrity, not confidentiality — which is also why
        these fields are safe to serialize if a TaskResult is ever forwarded
        onward.

        Returns True if parameters were found and attached.
        """
        # Clear FIRST, unconditionally. These fields arrive from the wire on
        # the responder's reply, where a peer is free to populate them with
        # whatever makes its answer look right. Overwriting them only on the
        # success path would leave those attacker-chosen values standing
        # whenever we have no record of our own -- exactly the case where a
        # caller most needs "unknown" rather than "the peer says". The
        # downstream scorer treats an absent capability name as "not a probe"
        # and falls back to ordinary task scoring, which is the safe default.
        self.requested_capability_name = None
        self.requested_args = ()
        self.requested_kwargs = {}
        params = getattr(original, 'parameters', None)
        if params is None:
            return False
        capability = getattr(params, 'capability', None)
        self.requested_capability_name = getattr(capability, 'name', None)
        self.requested_args = tuple(getattr(params, 'args', ()) or ())
        self.requested_kwargs = dict(getattr(params, 'kwargs', {}) or {})
        return self.requested_capability_name is not None

    def generate_proof(self):
        """Generate a ZK-STARK proof of data integrity for this result.

        The proof covers the serialized task UUID + result data, allowing
        a verifier to confirm the result hasn't been tampered with.
        Returns True if proof was generated, False if ZKP is unavailable.
        """
        from autonomous_trust.core._zkp import ZKP_AVAILABLE, prove
        if not ZKP_AVAILABLE:
            return False
        self.proof = prove(self._proof_data())
        return True

    def verify_proof(self) -> Optional[bool]:
        """Verify the ZK-STARK proof attached to this result.

        Returns True if valid, False if invalid, None if no proof is present
        or ZKP is unavailable.
        """
        if self.proof is None:
            return None
        from autonomous_trust.core._zkp import ZKP_AVAILABLE, verify
        if not ZKP_AVAILABLE:
            return None
        return verify(self.proof)

    def _proof_data(self) -> bytes:
        """Serialize the fields covered by the proof."""
        import json
        payload = json.dumps({
            'uuid': str(self.uuid),
            'result': self.result,
        }, sort_keys=True, default=str)
        return payload.encode('utf-8')


class TaskCounter(Task):
    def __init__(self, task):
        super().__init__(**task.to_dict())
        self.count = 0


class TaskTracker(Task):
    def __init__(self, task):
        super().__init__(**task.to_dict())
        self.results = {}  # keyed by peer.uuid


class Job(object):
    def __init__(self, task: Task):
        self.task = task
        self.id = task.uuid
        self.start = int(task.parameters.when.timestamp())
        self.length = task.parameters.duration.seconds

    @property
    def endpoints(self):
        return self.start, self.start + self.length

    def __lt__(self, other):
        if self.start < other.start:
            return True
        return False

    def __eq__(self, other):  # when do jobs overlap
        if other.start + other.length >= self.start >= other.start or \
                self.start + self.length >= other.start >= self.start:
            return True
        return False


class JobQueue(object):
    def __init__(self):
        self._heap = []

    def __len__(self):
        return len(self._heap)

    def push(self, item: Job) -> None:
        """Push a Job into sorted position on the queue"""
        heapq.heappush(self._heap, (item.start, item.id, item))

    def pop(self) -> Job:
        """Pop the next Job from the queue"""
        if len(self._heap) < 1:
            raise Empty
        return heapq.heappop(self._heap)[2]

    def min(self) -> Optional[datetime]:
        """What is the datetime of the next Job"""
        if len(self) > 0:
            return datetime.fromtimestamp(self._heap[0][0], tz=UTC)
        return None

    def clear(self) -> None:
        """Reset the queue"""
        self._heap = []

    def __contains__(self, item_id: UUID) -> bool:
        return item_id in (x[1] for x in self._heap)

    def count(self, item: Job) -> int:
        """How many Jobs occupy the slot this Job would"""
        return len([x for x in self._heap if x[2] == item])

    def find(self, item_id: UUID) -> Optional[Job]:
        """Get the Job with this UUID"""
        for x in self._heap:
            if x[1] == item_id:
                return x[2]
        return None

    def find_all(self, item: Job) -> list[Job]:
        """Get all the Jobs that occupy the slot this Job would"""
        others = []
        for x in self._heap:
            if x[2] == item:
                others.append(x)
        return others

    def find_nearest_slot(self, job: Union[Job, Task]) -> datetime:
        """Get the closest open slot for this Job"""
        if isinstance(job, Task):
            job = Job(job)
        while self.count(job) >= max_concurrency:
            possible = []
            last = None
            for occupied in self.find_all(job):
                begin, end = occupied.endpoints
                possible.append(begin + job.length)
                possible.append(end)
                if last is None or last < end:
                    last = end
            job.start = None
            possible.sort()
            for instant in possible:
                job.start = instant
                if self.count(job) < max_concurrency:
                    break
            if job.start is None:
                job.start = last
        return datetime.fromtimestamp(job.start, tz=UTC)
