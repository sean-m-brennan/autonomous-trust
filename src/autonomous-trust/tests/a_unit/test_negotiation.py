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
import pytest
from datetime import UTC, datetime, timedelta
from queue import Empty
from uuid import uuid4
from unittest.mock import patch, MagicMock

import psutil

from autonomous_trust.core.negotiation.negotiation import (
    Status, TaskParameters, TaskInfo, Task, TaskStatus, TaskResult,
    TaskCounter, TaskTracker, Job, JobQueue,
)


class TestStatus:
    def test_running(self):
        assert Status.from_ps(psutil.STATUS_RUNNING) == Status.running

    def test_sleeping(self):
        assert Status.from_ps(psutil.STATUS_SLEEPING) == Status.sleeping

    def test_disk_sleep(self):
        assert Status.from_ps(psutil.STATUS_DISK_SLEEP) == Status.sleeping

    def test_stopped(self):
        assert Status.from_ps(psutil.STATUS_STOPPED) == Status.stopped

    def test_zombie(self):
        assert Status.from_ps(psutil.STATUS_ZOMBIE) == Status.zombie

    def test_dead(self):
        assert Status.from_ps(psutil.STATUS_DEAD) == Status.dead

    def test_unknown(self):
        assert Status.from_ps('some_unknown_status') is None


class TestTaskParameters:
    def test_defaults(self):
        tp = TaskParameters('cap1')
        assert tp.capability == 'cap1'
        assert tp._flexible is True
        assert tp.when is not None
        assert tp.duration == timedelta(seconds=1)
        assert tp.timeout == timedelta(seconds=30)
        assert tp.args == ()
        assert tp.kwargs == {}

    def test_explicit(self):
        when = datetime(2025, 1, 1)
        dur = timedelta(seconds=10)
        tout = timedelta(seconds=60)
        tp = TaskParameters('cap2', False, when, dur, tout, (1, 2), {'k': 'v'})
        assert tp.capability == 'cap2'
        assert tp._flexible is False
        assert tp.when == when
        assert tp.duration == dur
        assert tp.timeout == tout
        assert tp.args == (1, 2)
        assert tp.kwargs == {'k': 'v'}

    def test_acceptable(self):
        tp = TaskParameters('cap1')
        assert tp.acceptable() is True

    def test_adjust(self):
        tp = TaskParameters('cap1')
        tp.adjust()  # should not raise


class TestTaskInfo:
    def test_auto_uuid(self):
        ti = TaskInfo('requestor1')
        assert ti.uuid is not None
        assert ti.requestor == 'requestor1'
        assert ti.size == 1

    def test_explicit_uuid(self):
        uid = uuid4()
        ti = TaskInfo('req', uuid=uid, size=3)
        assert ti.uuid == uid
        assert ti.size == 3


class TestTask:
    def _make_task(self, **kwargs):
        when = kwargs.pop('when', datetime(2025, 1, 1, 12, 0, 0))
        tp = TaskParameters('cap1', when=when, **kwargs)
        return Task(tp, 'requestor1')

    def test_capability(self):
        t = self._make_task()
        assert t.capability == 'cap1'

    def test_has_uuid(self):
        t = self._make_task()
        assert t.uuid is not None


class TestTaskStatus:
    def test_from_task(self):
        when = datetime(2025, 1, 1, 12, 0, 0)
        tp = TaskParameters('cap1', when=when)
        task = Task(tp, 'req')
        ts = TaskStatus(task=task, status=Status.running)
        assert ts.status == Status.running
        assert ts.capability == 'cap1'

    def test_none_task(self):
        ts = TaskStatus(task=None, status=Status.pending,
                        parameters=TaskParameters('x', when=datetime(2025, 1, 1)),
                        requestor='r')
        assert ts.status == Status.pending


class TestTaskResult:
    def test_from_task(self):
        tp = TaskParameters('cap1', when=datetime(2025, 1, 1))
        task = Task(tp, 'req')
        tr = TaskResult(task=task, result=42)
        assert tr.result == 42
        assert tr.requestor == 'req'


class TestTaskCounter:
    def test_count_init(self):
        tp = TaskParameters('cap1', when=datetime(2025, 1, 1))
        task = Task(tp, 'req')
        tc = TaskCounter(task)
        assert tc.count == 0


class TestTaskTracker:
    def test_results_init(self):
        tp = TaskParameters('cap1', when=datetime(2025, 1, 1))
        task = Task(tp, 'req')
        tt = TaskTracker(task)
        assert tt.results == {}


class TestJob:
    def _make_job(self, start_ts=1000000, duration_secs=10):
        when = datetime.fromtimestamp(start_ts, tz=UTC)
        tp = TaskParameters('cap1', when=when, duration=timedelta(seconds=duration_secs))
        task = Task(tp, 'req')
        return Job(task)

    def test_endpoints(self):
        j = self._make_job(1000000, 10)
        s, e = j.endpoints
        assert e == s + 10

    def test_lt(self):
        j1 = self._make_job(1000000, 10)
        j2 = self._make_job(1000100, 10)
        assert j1 < j2
        assert not j2 < j1

    def test_eq_overlap(self):
        j1 = self._make_job(1000000, 100)
        j2 = self._make_job(1000050, 100)
        assert j1 == j2

    def test_eq_no_overlap(self):
        j1 = self._make_job(1000000, 10)
        j2 = self._make_job(1001000, 10)
        assert not (j1 == j2)


class TestJobQueue:
    def _make_job(self, start_ts=1000000, duration_secs=10):
        when = datetime.fromtimestamp(start_ts, tz=UTC)
        tp = TaskParameters('cap1', when=when, duration=timedelta(seconds=duration_secs))
        task = Task(tp, 'req')
        return Job(task)

    def test_push_pop(self):
        jq = JobQueue()
        j = self._make_job()
        jq.push(j)
        assert len(jq) == 1
        popped = jq.pop()
        assert popped.id == j.id
        assert len(jq) == 0

    def test_pop_empty(self):
        jq = JobQueue()
        with pytest.raises(Empty):
            jq.pop()

    def test_min(self):
        jq = JobQueue()
        assert jq.min() is None
        j = self._make_job(1000000)
        jq.push(j)
        assert jq.min() == datetime.fromtimestamp(1000000, tz=UTC)

    def test_clear(self):
        jq = JobQueue()
        jq.push(self._make_job(1000000))
        jq.push(self._make_job(1000100))
        jq.clear()
        assert len(jq) == 0

    def test_contains(self):
        jq = JobQueue()
        j = self._make_job()
        jq.push(j)
        assert j.id in jq
        assert uuid4() not in jq

    def test_count(self):
        jq = JobQueue()
        j1 = self._make_job(1000000, 100)
        j2 = self._make_job(1000050, 100)
        jq.push(j1)
        jq.push(j2)
        assert jq.count(j1) >= 1

    def test_find(self):
        jq = JobQueue()
        j = self._make_job()
        jq.push(j)
        found = jq.find(j.id)
        assert found is not None
        assert found.id == j.id
        assert jq.find(uuid4()) is None

    def test_find_all(self):
        jq = JobQueue()
        j1 = self._make_job(1000000, 100)
        j2 = self._make_job(1000050, 100)
        jq.push(j1)
        jq.push(j2)
        found = jq.find_all(j1)
        assert len(found) >= 1

    def test_ordering(self):
        jq = JobQueue()
        j1 = self._make_job(1000200)
        j2 = self._make_job(1000100)
        j3 = self._make_job(1000300)
        jq.push(j1)
        jq.push(j2)
        jq.push(j3)
        popped = jq.pop()
        assert popped.start == 1000100


class TestJobNotLt:
    def test_same_start(self):
        when1 = datetime.fromtimestamp(1000000, tz=UTC)
        tp1 = TaskParameters('cap1', when=when1, duration=timedelta(seconds=10))
        j1 = Job(Task(tp1, 'req'))
        when2 = datetime.fromtimestamp(1000000, tz=UTC)
        tp2 = TaskParameters('cap1', when=when2, duration=timedelta(seconds=10))
        j2 = Job(Task(tp2, 'req'))
        assert not (j1 < j2)


class TestFindNearestSlot:
    def _make_job(self, start_ts=1000000, duration_secs=10):
        when = datetime.fromtimestamp(start_ts, tz=UTC)
        tp = TaskParameters('cap1', when=when, duration=timedelta(seconds=duration_secs))
        task = Task(tp, 'req')
        return Job(task)

    def test_empty_queue(self):
        jq = JobQueue()
        j = self._make_job(1000000, 10)
        slot = jq.find_nearest_slot(j)
        assert slot == datetime.fromtimestamp(1000000, tz=UTC)

    def test_from_task(self):
        jq = JobQueue()
        when = datetime.fromtimestamp(1000000, tz=UTC)
        tp = TaskParameters('cap1', when=when, duration=timedelta(seconds=10))
        task = Task(tp, 'req')
        slot = jq.find_nearest_slot(task)
        assert isinstance(slot, datetime)


class TestStatusFromPsWaking:
    def test_waking(self):
        if hasattr(psutil, 'STATUS_WAKING'):
            assert Status.from_ps(psutil.STATUS_WAKING) == Status.sleeping

    def test_tracing_stop(self):
        if hasattr(psutil, 'STATUS_TRACING_STOP'):
            assert Status.from_ps(psutil.STATUS_TRACING_STOP) == Status.stopped


class TestTaskParametersClassVars:
    def test_timeout_extension_value(self):
        """TaskParameters.timeout_extension class variable is 120 seconds (line 127 coverage)."""
        assert TaskParameters.timeout_extension == 120

    def test_timeout_extension_accessible_on_instance(self):
        """timeout_extension is accessible on a TaskParameters instance."""
        tp = TaskParameters('cap1')
        assert tp.timeout_extension == 120

    def test_duration_fraction_value(self):
        """TaskParameters.duration_fraction class variable is 10 percent."""
        assert TaskParameters.duration_fraction == 10

    def test_default_duration_value(self):
        """TaskParameters.default_duration class variable is 1 second."""
        assert TaskParameters.default_duration == 1

    def test_default_timeout_value(self):
        """TaskParameters.default_timeout class variable is 30 seconds."""
        assert TaskParameters.default_timeout == 30


class TestTaskResultNoneTask:
    def test_none_task_uses_kwargs(self):
        """TaskResult with task=None uses provided kwargs directly (line 127: task_args = {})."""
        tr = TaskResult(
            task=None,
            result='output',
            requestor='peer1',
            parameters=TaskParameters('cap1', when=datetime(2025, 1, 1)),
        )
        assert tr.result == 'output'
        assert tr.requestor == 'peer1'

    def test_none_task_result_value(self):
        """TaskResult with task=None stores the result correctly."""
        tr = TaskResult(
            task=None,
            result=99,
            requestor='req',
            parameters=TaskParameters('cap1', when=datetime(2025, 1, 1)),
        )
        assert tr.result == 99

    def test_none_task_result_none_value(self):
        """TaskResult with task=None and result=None stores None."""
        tr = TaskResult(
            task=None,
            result=None,
            requestor='req',
            parameters=TaskParameters('cap1', when=datetime(2025, 1, 1)),
        )
        assert tr.result is None


class TestFindNearestSlotOccupied:
    """Tests for the find_nearest_slot while-loop logic (lines 223-238).

    The while loop fires when count(job) >= max_concurrency.  With the default
    max_concurrency (os.cpu_count() * 2, typically >= 4) it is easiest to mock
    max_concurrency to 1 so a single occupied slot is enough to enter the loop.

    Note: find_all() currently returns heap tuples (start, id, Job) rather than
    Job objects, so occupied.endpoints inside the loop raises AttributeError.
    That is a pre-existing bug documented here.
    """

    def _make_job(self, start_ts=1000000, duration_secs=10):
        when = datetime.fromtimestamp(start_ts, tz=UTC)
        tp = TaskParameters('cap1', when=when, duration=timedelta(seconds=duration_secs))
        task = Task(tp, 'req')
        return Job(task)

    def test_empty_queue_returns_requested_time(self):
        """With an empty queue the slot is always the job's own start time."""
        jq = JobQueue()
        j = self._make_job(1000000, 10)
        slot = jq.find_nearest_slot(j)
        assert slot == datetime.fromtimestamp(1000000, tz=UTC)

    def test_non_overlapping_jobs_return_requested_time(self):
        """A job that does not overlap any queue entry gets its own slot."""
        jq = JobQueue()
        jq.push(self._make_job(1000000, 10))   # occupies [1000000, 1000010)
        new_job = self._make_job(1001000, 10)  # starts well after queue ends
        slot = jq.find_nearest_slot(new_job)
        assert slot == datetime.fromtimestamp(1001000, tz=UTC)

    def test_while_loop_enters_on_full_slot_known_bug(self):
        """When the slot is fully occupied the while loop enters and raises AttributeError.

        find_all() returns heap tuples but the loop calls occupied.endpoints,
        which does not exist on a tuple.  This test documents the pre-existing bug
        so that the line is exercised by coverage and the bug is visible.
        """
        import autonomous_trust.core.negotiation.negotiation as neg_mod

        jq = JobQueue()
        # One overlapping job fills the slot when max_concurrency is mocked to 1.
        jq.push(self._make_job(1000000, 100))
        new_job = self._make_job(1000050, 10)  # overlaps with the existing job

        with patch.object(neg_mod, 'max_concurrency', 1):
            # count(new_job) == 1 >= max_concurrency(1), so the while loop is entered.
            # The loop body hits the pre-existing AttributeError on find_all tuples.
            with pytest.raises(AttributeError, match="'tuple' object has no attribute 'endpoints'"):
                jq.find_nearest_slot(new_job)

    def test_from_task_object_empty_queue(self):
        """find_nearest_slot accepts a Task (not just a Job) and converts it."""
        jq = JobQueue()
        when = datetime.fromtimestamp(1000000, tz=UTC)
        tp = TaskParameters('cap1', when=when, duration=timedelta(seconds=10))
        task = Task(tp, 'req')
        slot = jq.find_nearest_slot(task)
        assert isinstance(slot, datetime)
        assert slot == datetime.fromtimestamp(1000000, tz=UTC)
