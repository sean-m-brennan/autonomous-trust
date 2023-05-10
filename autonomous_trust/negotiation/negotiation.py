from datetime import datetime, timedelta
import heapq
from enum import Enum
from queue import Empty
from typing import Union
from uuid import UUID, uuid4

import psutil

from ..system import max_concurrency
from ..config import Configuration


# TODO NTP synchronization using ntplib and tied to reputation

class Status(Enum):
    running = 'running'
    sleeping = 'sleeping'
    zombie = 'zombie'
    stopped = 'stopped'
    dead = 'dead'
    pending = 'pending'  # has not started yet
    unknown = 'unknown'  # not tracking this task

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
    timeout_extension = 120  # seconds
    duration_fraction = 10  # percent

    def __init__(self, _capability, _flexible=True, when: datetime = None, duration: timedelta = None,
                 timeout: timedelta = None, args=None, kwargs=None):
        self._capability = _capability
        self._flexible = _flexible
        self.when = when
        if when is None:
            self.when = datetime.utcnow()
        self.duration = duration
        if duration is None:
            self.duration = timedelta(seconds=0)
        self.timeout = timeout
        if timeout is None:
            self.timeout = timedelta(seconds=0)
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


class Task(Configuration):
    def __init__(self, parameters: TaskParameters, requestor, uuid: UUID = None, size=1):
        self.parameters = parameters
        self.requestor = requestor
        self.uuid = uuid
        if uuid is None:
            self.uuid = uuid4()
        self.size = size

    @property
    def capability(self):
        return self.parameters.capability


class TaskStatus(Task):
    def __init__(self, task, status=None):
        super().__init__(**task.to_dict())
        self.status = status


class TaskResult(Task):
    def __init__(self, task, result):
        super().__init__(**task.to_dict())
        self.result = result


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

    def push(self, item: Job) -> None:
        """Push a Job into sorted position on the queue"""
        heapq.heappush(self._heap, (item.start, item.id, item))

    def pop(self) -> Task:
        """Pop the next Job from the queue"""
        if len(self._heap) < 1:
            raise Empty
        return heapq.heappop(self._heap)[2]

    def min(self) -> datetime:
        """What is the datetime of the next Job"""
        return datetime.fromtimestamp(self._heap[0][0])

    def clear(self) -> None:
        """Reset the queue"""
        self._heap = []

    def __contains__(self, item_id: UUID) -> bool:
        return item_id in (x[1] for x in self._heap)

    def count(self, item: Job) -> int:
        """How many Jobs occupy the slot this Job would"""
        return len([x for x in self._heap if x[2] == item])

    def find(self, item_id: UUID) -> Union[Job, None]:
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
        return datetime.fromtimestamp(job.start)
