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
import pytest
import queue
from uuid import uuid4
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from autonomous_trust.core.negotiation.negprocess import NegotiationProcess
from autonomous_trust.core.negotiation.negotiation import (
    Task, TaskParameters, TaskStatus, TaskResult, TaskCounter, TaskTracker,
    Job, JobQueue, Status,
)
from autonomous_trust.core.negotiation.protocol import NegotiationProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.capabilities import Capability, Capabilities
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity


def _make_mock_peer(uid=None, nickname='peer1', address='10.0.0.1'):
    peer = MagicMock()
    peer.uuid = uid or uuid4()
    peer.nickname = nickname
    peer.address = address
    return peer


def _make_neg_process():
    log_q = queue.Queue()
    mock_net_proc = MagicMock()
    mock_net_proc.name = CfgIds.network
    mock_id_proc = MagicMock()
    mock_id_proc.name = CfgIds.identity
    mock_neg_proc = MagicMock()
    mock_neg_proc.name = CfgIds.negotiation

    configs = {
        'processes': [mock_net_proc, mock_id_proc, mock_neg_proc],
        CfgIds.identity: MagicMock(),
        CfgIds.peers: MagicMock(),
        CfgIds.group: MagicMock(),
    }
    subsystems = ProcessTracker()
    np = NegotiationProcess(configs, subsystems, log_q, suppress_log=True)
    # handle_invite's tier gate looks up the sender via
    # self.peers.find_by_uuid(...). By default the mock returns a
    # MagicMock for everything, which breaks the `sender_tier <
    # required_tier` comparison. Default to None so the test peers
    # are treated as unknown (tier 0) unless a test explicitly sets
    # a sender record.
    np.protocol.peers.find_by_uuid = MagicMock(return_value=None)
    return np


class TestNegotiationProcessInit:
    def test_init(self):
        np = _make_neg_process()
        assert isinstance(np.task_stack, JobQueue)
        assert np.proposed_tasks == {}
        assert np.my_tasks == {}
        assert np.confirmed == {}
        assert np.status_pending == []

    def test_properties(self):
        np = _make_neg_process()
        assert np.peers is np.protocol.peers
        assert np.group is np.protocol.group
        assert np.capabilities is np.protocol.capabilities
        assert np.peer_capabilities is np.protocol.peer_capabilities


class TestAddTask:
    def test_add_task(self):
        np = _make_neg_process()
        tp = TaskParameters('cap1', when=datetime(2025, 1, 1, tzinfo=UTC))
        task = Task(tp, 'req')
        result = np._add_task(task)
        assert result is True
        assert len(np.task_stack) == 1


class TestGetJobs:
    def test_no_ready_jobs(self):
        np = _make_neg_process()
        jobs = np._get_jobs()
        assert jobs == []

    def test_ready_jobs(self):
        np = _make_neg_process()
        # Add a job in the past
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, 'req')
        np._add_task(task)
        jobs = np._get_jobs()
        assert len(jobs) == 1


class TestStartTask:
    def test_wrong_function(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'wrong', 'data')
        result = np.start_task({}, msg)
        assert result is False

    def test_not_task_obj(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, NegotiationProtocol.start, 'not_a_task')
        result = np.start_task({}, msg)
        assert result is False


class TestHandleInvite:
    def test_wrong_function(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'wrong', 'data')
        result = np.handle_invite({}, msg)
        assert result is False


class TestHandleHaggle:
    def test_wrong_function(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'wrong', 'data')
        result = np.handle_haggle({}, msg)
        assert result is False


class TestHandleAccept:
    def test_wrong_function(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'wrong', 'data')
        result = np.handle_accept(None, msg)
        assert result is False

    def test_accept(self):
        np = _make_neg_process()
        tp = TaskParameters('cap1', when=datetime(2025, 1, 1, tzinfo=UTC))
        task = Task(tp, 'req')
        peer = _make_mock_peer()
        msg = Message(CfgIds.negotiation, NegotiationProtocol.acceptance,
                      task, from_whom=peer)
        result = np.handle_accept(None, msg)
        assert result is True
        assert task.uuid in np.confirmed


class TestHandleRefuse:
    def test_wrong_function(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'wrong', 'data')
        result = np.handle_refuse({}, msg)
        assert result is False


class TestHandleStatReq:
    def test_wrong_function(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'wrong', 'data')
        result = np.handle_stat_req({}, msg)
        assert result is False


class TestHandleStatResp:
    def test_wrong_function(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'wrong', 'data')
        result = np.handle_stat_resp({}, msg)
        assert result is False


class TestHandleResults:
    def test_wrong_function(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'wrong', 'data')
        result = np.handle_results({}, msg)
        assert result is False


class TestForwardStatus:
    def test_not_task_status(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'func', 'data')
        result = np.forward_status({}, msg)
        assert result is False

    def test_task_status_with_status(self):
        np = _make_neg_process()
        tp = TaskParameters('cap1', when=datetime(2025, 1, 1, tzinfo=UTC))
        mock_requestor = MagicMock(spec=Identity)
        task = Task(tp, mock_requestor)
        ts = TaskStatus(task=task, status=Status.running)
        ts.to_json_string = MagicMock(return_value='mock_yaml')
        ts.requestor = mock_requestor
        net_q = queue.Queue()
        result = np.forward_status({CfgIds.network: net_q}, ts)
        assert result is True

    def test_task_status_none_status(self):
        np = _make_neg_process()
        tp = TaskParameters('cap1', when=datetime(2025, 1, 1, tzinfo=UTC))
        mock_requestor = MagicMock(spec=Identity)
        task = Task(tp, mock_requestor)
        ts = TaskStatus(task=task, status=None)
        result = np.forward_status({CfgIds.network: queue.Queue()}, ts)
        assert result is True


class TestForwardResult:
    def test_not_task_result(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'func', 'data')
        result = np.forward_result({}, msg)
        assert result is False

    def test_task_result(self):
        np = _make_neg_process()
        tp = TaskParameters('cap1', when=datetime(2025, 1, 1, tzinfo=UTC))
        mock_requestor = MagicMock(spec=Identity)
        task = Task(tp, mock_requestor)
        tr = TaskResult(task=task, result=42)
        tr.to_json_string = MagicMock(return_value='mock_yaml')
        tr.requestor = mock_requestor
        net_q = queue.Queue()
        result = np.forward_result({CfgIds.network: net_q}, tr)
        assert result is True


class TestStartTaskDeeper:
    def test_start_with_capable_peers(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')

        # Set up peer capabilities so peer has 'video'
        np.protocol.peer_capabilities.items = MagicMock(return_value=[('video', [peer.uuid])])
        np.protocol.peers.find_by_uuid = MagicMock(return_value=peer)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        task.to_json_string = MagicMock(return_value='mock_yaml')
        msg = Message(CfgIds.negotiation, NegotiationProtocol.start, task)
        net_q = queue.Queue()
        result = np.start_task({CfgIds.network: net_q}, msg)
        assert result is True
        assert task.uuid in np.my_tasks
        assert not net_q.empty()

    def test_start_no_capable_peers(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        np.protocol.peer_capabilities.items = MagicMock(return_value=[])

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        msg = Message(CfgIds.negotiation, NegotiationProtocol.start, task)
        main_q = queue.Queue()
        result = np.start_task({CfgIds.network: queue.Queue(), CfgIds.main: main_q}, msg)
        assert result is True
        # Error should be reported to main queue
        assert not main_q.empty()
        error_result = main_q.get_nowait()
        assert error_result.result == Status.no_peers


class TestHandleInviteDeeper:
    def test_invite_not_capable(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('nonexistent')
        np.protocol.capabilities.__contains__ = MagicMock(return_value=False)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        net_q = queue.Queue()
        result = np.handle_invite({CfgIds.network: net_q}, msg)
        assert result is True

    def test_invite_capable_acceptable(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        np.protocol.capabilities.__contains__ = MagicMock(return_value=True)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        task.parameters.acceptable = MagicMock(return_value=True)
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        net_q = queue.Queue()
        result = np.handle_invite({CfgIds.network: net_q}, msg)
        assert result is True
        assert not net_q.empty()

    def test_invite_duplicate_refuses_past_threshold(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        np.protocol.capabilities.__contains__ = MagicMock(return_value=True)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        task.to_json_string = MagicMock(return_value='yaml')
        task.parameters.acceptable = MagicMock(return_value=True)
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        # Send more than max_task_duplicates times. The past-threshold
        # iterations short-circuit to refuse-and-return (mirrors C's
        # handle_invite). Peer is NOT demoted — the canonical action.
        #
        # Each delivery carries a FRESH sequence, because that is what a
        # flood is: a requestor emitting distinct invitations for one task.
        # Re-delivering one stamped invitation is a replay, refused by the
        # freshness gate before the counter ever sees it — pinned separately
        # in TestHandleInviteFreshness.
        for n in range(np.max_task_duplicates + 2):
            task.seq = n + 1
            np.handle_invite({CfgIds.network: queue.Queue()}, msg)
        np.protocol.peers.demote.assert_not_called()


class TestHandleHaggleDeeper:
    def test_flexible_task(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        # ``flexible`` is a read-only property; set it via the
        # constructor's ``_flexible`` kwarg (negotiation.py:65-68).
        tp = TaskParameters('cap1', _flexible=True,
                            when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        task.to_json_string = MagicMock(return_value='yaml')
        msg = Message(CfgIds.negotiation, NegotiationProtocol.response,
                      task, from_whom=peer)
        net_q = queue.Queue()
        result = np.handle_haggle({CfgIds.network: net_q}, msg)
        assert result is True
        assert not net_q.empty()

    def test_inflexible_task(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', _flexible=False,
                            when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # Need the task in my_tasks for _cancel_participant
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None
        msg = Message(CfgIds.negotiation, NegotiationProtocol.response,
                      task, from_whom=peer)
        main_q = queue.Queue()
        result = np.handle_haggle({CfgIds.network: queue.Queue(), CfgIds.main: main_q}, msg)
        assert result is True


class TestHandleResultsDeeper:
    def test_results_collected(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=1)
        task.result = 'done'
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None
        msg = Message(CfgIds.negotiation, NegotiationProtocol.result,
                      task, from_whom=peer)
        main_q = queue.Queue()
        result = np.handle_results({CfgIds.main: main_q}, msg)
        assert result is True

    def test_results_unknown_task(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        msg = Message(CfgIds.negotiation, NegotiationProtocol.result,
                      task, from_whom=peer)
        result = np.handle_results({CfgIds.main: queue.Queue()}, msg)
        assert result is True  # returns True even for unknown tasks


class TestHandleRefuseDeeper:
    def test_refuse_cancels_participant(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=2)
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None
        msg = Message(CfgIds.negotiation, NegotiationProtocol.refusal,
                      task, from_whom=peer)
        main_q = queue.Queue()
        result = np.handle_refuse({CfgIds.main: main_q}, msg)
        assert result is True
        assert peer.uuid not in np.my_tasks[task.uuid].results


class TestHandleStatReqDeeper:
    def test_stat_req_pending_in_stack(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2025, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # Add task to the stack so it's found as pending
        np._add_task(task)
        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_req,
                      task, from_whom=peer)
        # Patch forward_status to avoid YAML serialization of mocks
        np.forward_status = MagicMock(return_value=True)
        net_q = queue.Queue()
        result = np.handle_stat_req({CfgIds.network: net_q}, msg)
        assert result is True
        np.forward_status.assert_called_once()

    def test_stat_req_not_in_stack(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_req,
                      task, from_whom=peer)
        main_q = queue.Queue()
        result = np.handle_stat_req({CfgIds.main: main_q}, msg)
        assert result is True
        assert not main_q.empty()


class TestHandleInviteNotAcceptable:
    def test_invite_capable_not_acceptable(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        np.protocol.capabilities.__contains__ = MagicMock(return_value=True)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        task.parameters.acceptable = MagicMock(return_value=False)
        task.adjust = MagicMock()
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        net_q = queue.Queue()
        result = np.handle_invite({CfgIds.network: net_q}, msg)
        assert result is True
        assert not net_q.empty()  # haggle response sent


class TestHandleStatRespDeeper:
    def test_running_status_extends_timeout(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        ts = TaskStatus(task=task, status=Status.running)

        # Must be in confirmed for timeout extension
        np.confirmed[task.uuid] = [peer]
        # Must be in status_pending for removal
        np.status_pending.append(ts)

        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_resp,
                      ts, from_whom=peer)
        result = np.handle_stat_resp({CfgIds.network: queue.Queue()}, msg)
        assert result is True

    def test_pending_status_clock_sync_error(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        ts = TaskStatus(task=task, status=Status.pending)

        np.confirmed[task.uuid] = [peer]
        np.status_pending.append(ts)

        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_resp,
                      ts, from_whom=peer)
        result = np.handle_stat_resp({CfgIds.network: queue.Queue()}, msg)
        assert result is True

    def test_dead_status_cancels(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=2)
        ts = TaskStatus(task=task, status=Status.dead)

        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None

        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_resp,
                      ts, from_whom=peer)
        main_q = queue.Queue()
        result = np.handle_stat_resp({CfgIds.main: main_q}, msg)
        assert result is True

    def test_not_task_status(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_resp,
                      'not_task_status', from_whom=peer)
        result = np.handle_stat_resp({}, msg)
        assert result is True

    def test_sleeping_status_with_duration_timeout(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC),
                          timeout=timedelta(seconds=0),
                          duration=timedelta(seconds=100))
        task = Task(tp, peer)
        ts = TaskStatus(task=task, status=Status.sleeping)

        np.confirmed[task.uuid] = [peer]
        np.status_pending.append(ts)

        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_resp,
                      ts, from_whom=peer)
        result = np.handle_stat_resp({CfgIds.network: queue.Queue()}, msg)
        assert result is True

    def test_running_not_confirmed(self):
        """Running status but task not in confirmed - should not extend."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        ts = TaskStatus(task=task, status=Status.running)

        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_resp,
                      ts, from_whom=peer)
        result = np.handle_stat_resp({CfgIds.network: queue.Queue()}, msg)
        assert result is True


class TestHandleRefuseDeeper2:
    def test_refuse_with_registered_task(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=1)
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None
        msg = Message(CfgIds.negotiation, NegotiationProtocol.refusal,
                      task, from_whom=peer)
        main_q = queue.Queue()
        result = np.handle_refuse({CfgIds.main: main_q}, msg)
        assert result is True


# ---------------------------------------------------------------------------
# Additional tests targeting previously-uncovered lines
# ---------------------------------------------------------------------------

class TestHandleInviteFullException:
    """Cover Full exception paths in handle_invite (lines 145-146)."""

    def test_invite_not_capable_full(self):
        """Queue full when sending refusal for not-capable task."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        # 'nonexistent' capability is not registered → refusal path
        cap = Capability('nonexistent')

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        # Should log error but still return True (Full is caught)
        result = np.handle_invite({CfgIds.network: full_q}, msg)
        assert result is True

    def test_invite_capable_acceptable_add_task_success_full_queue(self):
        """Queue full when sending acceptance after _add_task succeeds."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        # Register so __contains__ check passes
        np.protocol.capabilities.register_ability('video', lambda: None)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        # acceptable() returns True by default; _add_task will succeed on empty stack
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.handle_invite({CfgIds.network: full_q}, msg)
        assert result is True

    def test_invite_capable_acceptable_add_task_fail_full_queue(self):
        """Queue full when sending haggle response after _add_task fails."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        np.protocol.capabilities.register_ability('video', lambda: None)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        # Force _add_task to return False
        np._add_task = MagicMock(return_value=False)
        np.task_stack.find_nearest_slot = MagicMock(return_value=datetime(2020, 6, 1))
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.handle_invite({CfgIds.network: full_q}, msg)
        assert result is True

    def test_invite_capable_not_acceptable_full_queue(self):
        """Queue full when sending haggle response after acceptable() returns False."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        np.protocol.capabilities.register_ability('video', lambda: None)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        task.parameters.acceptable = MagicMock(return_value=False)
        # task.adjust() is called in negprocess but Task has no adjust; mock it
        task.adjust = MagicMock()
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.handle_invite({CfgIds.network: full_q}, msg)
        assert result is True
        # adjust() was called before the Full exception on put()
        task.adjust.assert_called_once()


class TestHandleInviteAddTaskFail:
    """Cover _add_task fails path (lines 134-138) and not-acceptable path (lines 139-144)."""

    def test_add_task_fail_sends_haggle(self):
        """When _add_task returns False, send response with find_nearest_slot."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        # Register so the capability check passes
        np.protocol.capabilities.register_ability('video', lambda: None)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        # acceptable() returns True by default; force _add_task to fail
        np._add_task = MagicMock(return_value=False)
        np.task_stack.find_nearest_slot = MagicMock(return_value=datetime(2021, 1, 1))

        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        net_q = queue.Queue()
        result = np.handle_invite({CfgIds.network: net_q}, msg)
        assert result is True
        assert not net_q.empty()
        sent = net_q.get_nowait()
        assert sent.function == NegotiationProtocol.response

    def test_not_acceptable_sends_haggle(self):
        """When acceptable() is False, call adjust() and send response."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        np.protocol.capabilities.register_ability('video', lambda: None)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        task.parameters.acceptable = MagicMock(return_value=False)
        # task.adjust() is called in negprocess on the Task (which lacks adjust); mock it
        task.adjust = MagicMock()

        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        net_q = queue.Queue()
        result = np.handle_invite({CfgIds.network: net_q}, msg)
        assert result is True
        task.adjust.assert_called_once()
        assert not net_q.empty()
        sent = net_q.get_nowait()
        assert sent.function == NegotiationProtocol.response


class TestHandleInviteNewTask:
    """Cover lines 115-116: task.uuid not in proposed_tasks creates new TaskCounter."""

    def test_first_invite_creates_counter(self):
        """First invite for a task creates a new TaskCounter entry."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        # 'nonexistent' not registered → goes to refusal path; still creates counter
        cap = Capability('nonexistent')

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        # handle_invite refuses an unstamped invitation (TaskInfo.seq 0),
        # so every invite test has to carry a freshness sequence to reach
        # the behaviour it is actually about. See core/freshness.py.
        task.seq = 1
        task.to_json_string = MagicMock(return_value='yaml')
        assert task.uuid not in np.proposed_tasks
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        np.handle_invite({CfgIds.network: queue.Queue()}, msg)
        assert task.uuid in np.proposed_tasks
        assert np.proposed_tasks[task.uuid].count == 1


class TestHandleInviteFloodCounter:
    """Regression for BUGS.md §P7: per-task flood counter must persist
    across `_add_task` admissions so the `max_task_duplicates` threshold
    is reachable. Mirrors C's structurally-separate
    "flood:<uuid>" map entry in negotiation/neg_proc.c."""

    def test_flood_counter_persists_past_threshold(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        cap = Capability('video')
        np.protocol.capabilities.register_ability('video', lambda: None)

        tp = TaskParameters(cap, when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        task.to_json_string = MagicMock(return_value='yaml')
        msg = Message(CfgIds.negotiation, NegotiationProtocol.announce,
                      task, from_whom=peer)
        net_q = queue.Queue()

        # Fresh sequence per delivery: a flood is distinct invitations for one
        # task, not one invitation redelivered. The replay case is refused by
        # the freshness gate ahead of this counter — see
        # TestHandleInviteFreshness.
        for n in range(np.max_task_duplicates + 1):
            task.seq = n + 1
            assert np.handle_invite({CfgIds.network: net_q}, msg) is True

        # Counter advanced once per invite and was NOT cleared by _add_task.
        assert np.flood_counts[task.uuid] == np.max_task_duplicates + 1
        # Iteration past the threshold trips refuse-and-return; peer
        # is NOT demoted (canonical action mirrors C's handle_invite).
        np.peers.demote.assert_not_called()
        last_msg = list(net_q.queue)[-1]
        assert last_msg.function == NegotiationProtocol.refusal
    """Cover Full exception paths in handle_haggle (lines 167-168, 172-173)."""

    def test_flexible_task_full_queue(self):
        """Full exception when sending announce for flexible task."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', _flexible=True,
                            when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        task.to_json_string = MagicMock(return_value='yaml')
        msg = Message(CfgIds.negotiation, NegotiationProtocol.response,
                      task, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.handle_haggle({CfgIds.network: full_q}, msg)
        assert result is True

    def test_inflexible_task_full_queue(self):
        """Full exception in _cancel_participant for non-flexible task."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', _flexible=False,
                            when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=2)
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None
        msg = Message(CfgIds.negotiation, NegotiationProtocol.response,
                      task, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.handle_haggle({CfgIds.network: queue.Queue(), CfgIds.main: full_q}, msg)
        assert result is True


class TestHandleRefuseFullException:
    """Cover Full exception in handle_refuse (lines 192-193)."""

    def test_refuse_full_queue(self):
        """Full exception in _cancel_participant during handle_refuse."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=2)
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None
        msg = Message(CfgIds.negotiation, NegotiationProtocol.refusal,
                      task, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.handle_refuse({CfgIds.main: full_q}, msg)
        assert result is True


class TestHandleStatReqFullException:
    """Cover Full exception in handle_stat_req (lines 207-208)."""

    def test_stat_req_not_in_stack_full_queue(self):
        """Full exception when forwarding status_req to main queue."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_req,
                      task, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.handle_stat_req({CfgIds.main: full_q}, msg)
        assert result is True


class TestForwardStatusFullException:
    """Cover Full exception in forward_status (lines 220-221)."""

    def test_forward_status_full_queue(self):
        """Full exception when putting status_resp onto network queue."""
        np = _make_neg_process()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        mock_requestor = MagicMock(spec=Identity)
        task = Task(tp, mock_requestor)
        ts = TaskStatus(task=task, status=Status.running)
        ts.to_json_string = MagicMock(return_value='mock_yaml')
        ts.requestor = mock_requestor
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.forward_status({CfgIds.network: full_q}, ts)
        assert result is True


class TestHandleStatRespFullException:
    """Cover Full exception in handle_stat_resp (lines 245-246)."""

    def test_stat_resp_dead_full_queue(self):
        """Full exception in _cancel_participant during handle_stat_resp with dead status."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=2)
        ts = TaskStatus(task=task, status=Status.dead)
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None
        msg = Message(CfgIds.negotiation, NegotiationProtocol.status_resp,
                      ts, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.handle_stat_resp({CfgIds.main: full_q}, msg)
        assert result is True


class TestForwardResultFullException:
    """Cover Full exception in forward_result (lines 256-257)."""

    def test_forward_result_full_queue(self):
        """Full exception when putting result onto network queue."""
        np = _make_neg_process()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        mock_requestor = MagicMock(spec=Identity)
        task = Task(tp, mock_requestor)
        tr = TaskResult(task=task, result=42)
        tr.to_json_string = MagicMock(return_value='mock_yaml')
        tr.requestor = mock_requestor
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.forward_result({CfgIds.network: full_q}, tr)
        assert result is True


class TestHandleResultsFullException:
    """Cover Full exception in handle_results (lines 272-273)."""

    def test_results_complete_full_queue(self):
        """Full exception when forwarding completed results to main queue."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=1)
        task.result = 'done'
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None
        msg = Message(CfgIds.negotiation, NegotiationProtocol.result,
                      task, from_whom=peer)
        full_q = MagicMock()
        full_q.put = MagicMock(side_effect=queue.Full)
        result = np.handle_results({CfgIds.main: full_q}, msg)
        assert result is True


class TestHandleResultsComplete:
    """Cover handle_results complete path (lines 264-271): results complete, forward to main."""

    def test_results_complete_forwards_to_main(self):
        """All results collected → put task on main queue and remove from my_tasks."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=1)
        task.result = 'finished'
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer.uuid] = None
        msg = Message(CfgIds.negotiation, NegotiationProtocol.result,
                      task, from_whom=peer)
        main_q = queue.Queue()
        result = np.handle_results({CfgIds.main: main_q}, msg)
        assert result is True
        assert not main_q.empty()
        forwarded = main_q.get_nowait()
        assert forwarded.uuid == task.uuid
        # Task removed from my_tasks after results collected
        assert task.uuid not in np.my_tasks

    def test_results_incomplete_not_forwarded(self):
        """Not enough results yet → do NOT put to main queue.

        size=3 means we need 3 entries in results before forwarding.
        We pre-populate 3 slots (all None) and only one peer reports back,
        so len(results)==3 >= task.size==3 would trigger forwarding. Instead
        we use size=4 so that 3 tracked results don't reach the threshold.
        """
        np = _make_neg_process()
        peer1 = _make_mock_peer(nickname='p1')
        peer2 = _make_mock_peer(nickname='p2', address='10.0.0.2')
        peer3 = _make_mock_peer(nickname='p3', address='10.0.0.3')
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        # size=4 → need 4 results; only 3 participants tracked → won't forward
        task = Task(tp, peer1, size=4)
        task.result = 'partial'
        np.my_tasks[task.uuid] = TaskTracker(task)
        np.my_tasks[task.uuid].results[peer1.uuid] = None
        np.my_tasks[task.uuid].results[peer2.uuid] = None
        np.my_tasks[task.uuid].results[peer3.uuid] = None
        # Only peer1 reports back
        msg = Message(CfgIds.negotiation, NegotiationProtocol.result,
                      task, from_whom=peer1)
        main_q = queue.Queue()
        result = np.handle_results({CfgIds.main: main_q}, msg)
        assert result is True
        assert main_q.empty()  # 3 results tracked, need 4 → not forwarded


class TestHandleTierLost:
    """Cover handle_tier_lost (trust-tiers.md §7.2)."""

    def test_wrong_function_returns_false(self):
        np = _make_neg_process()
        msg = Message(CfgIds.negotiation, 'wrong', '["x", 0]')
        result = np.handle_tier_lost({}, msg)
        assert result is False

    def test_bad_payload_logs_and_returns_true(self):
        np = _make_neg_process()
        # Single-element JSON list (insufficient fields)
        from autonomous_trust.core.identity.protocol import IdentityProtocol
        msg = Message(CfgIds.negotiation, IdentityProtocol.tier_lost,
                      '["only-one"]')
        result = np.handle_tier_lost({}, msg)
        assert result is True

    def test_bad_uuid_logs_and_returns_true(self):
        np = _make_neg_process()
        from autonomous_trust.core.identity.protocol import IdentityProtocol
        msg = Message(CfgIds.negotiation, IdentityProtocol.tier_lost,
                      '["not-a-uuid", 1]')
        result = np.handle_tier_lost({}, msg)
        assert result is True

    def test_cancels_worker_side_job_from_demoted_requestor(self):
        """A scheduled job whose requestor was demoted is dropped from task_stack."""
        np = _make_neg_process()
        # Requestor whose tier just dropped to 1
        demoted = _make_mock_peer(nickname='demoted')
        # Capability requires tier 3 — demotion to 1 should cancel
        cap = Capability('high-tier-cap', required_tier=3)
        tp = TaskParameters(cap, when=datetime(2025, 1, 1, tzinfo=UTC))
        task = Task(tp, demoted)
        np._add_task(task)
        assert len(np.task_stack) == 1

        # Also schedule a benign job from a different requestor that
        # must NOT be cancelled.
        other = _make_mock_peer(nickname='other')
        tp2 = TaskParameters(cap, when=datetime(2025, 1, 2, tzinfo=UTC))
        keep_task = Task(tp2, other)
        np._add_task(keep_task)

        from autonomous_trust.core.identity.protocol import IdentityProtocol
        payload = '["%s", 1]' % str(demoted.uuid)
        msg = Message(CfgIds.negotiation, IdentityProtocol.tier_lost, payload)
        result = np.handle_tier_lost({CfgIds.main: queue.Queue()}, msg)
        assert result is True
        assert len(np.task_stack) == 1
        # The remaining job is the "keep" one
        remaining = np.task_stack._heap[0][2].task
        assert remaining.uuid == keep_task.uuid

    def test_keeps_worker_side_job_when_required_tier_still_met(self):
        """A scheduled job whose requestor's new tier still meets required_tier is kept."""
        np = _make_neg_process()
        demoted = _make_mock_peer(nickname='demoted')
        cap = Capability('mid-tier-cap', required_tier=1)
        tp = TaskParameters(cap, when=datetime(2025, 1, 1, tzinfo=UTC))
        task = Task(tp, demoted)
        np._add_task(task)

        from autonomous_trust.core.identity.protocol import IdentityProtocol
        # Demote to tier 2: still >= required_tier 1, so keep.
        payload = '["%s", 2]' % str(demoted.uuid)
        msg = Message(CfgIds.negotiation, IdentityProtocol.tier_lost, payload)
        np.handle_tier_lost({CfgIds.main: queue.Queue()}, msg)
        assert len(np.task_stack) == 1

    def test_drops_demoted_peer_from_my_tasks_tracker(self):
        """A requestor-side tracker drops the demoted participant when capability tier > new tier."""
        np = _make_neg_process()
        demoted = _make_mock_peer(nickname='demoted')
        cap = Capability('high-cap', required_tier=3)
        tp = TaskParameters(cap, when=datetime(2025, 1, 1, tzinfo=UTC))
        # Two-participant task; I'm the requestor.
        me = MagicMock(spec=Identity)
        me.uuid = uuid4()
        task = Task(tp, me, size=2)
        tracker = TaskTracker(task)
        other = _make_mock_peer(nickname='other')
        tracker.results[demoted.uuid] = None
        tracker.results[other.uuid] = None
        np.my_tasks[task.uuid] = tracker

        from autonomous_trust.core.identity.protocol import IdentityProtocol
        payload = '["%s", 1]' % str(demoted.uuid)
        msg = Message(CfgIds.negotiation, IdentityProtocol.tier_lost, payload)
        main_q = queue.Queue()
        result = np.handle_tier_lost({CfgIds.main: main_q}, msg)
        assert result is True
        # Demoted peer dropped, tracker still has the other peer
        assert demoted.uuid not in tracker.results
        assert other.uuid in tracker.results
        # Task not cancelled (tracker still has participants)
        assert task.uuid in np.my_tasks
        assert main_q.empty()

    def test_emits_cancelled_result_when_tracker_emptied(self):
        """If dropping demoted peer empties the tracker, emit Status.cancelled and remove entry."""
        np = _make_neg_process()
        demoted = _make_mock_peer(nickname='demoted')
        cap = Capability('high-cap', required_tier=3)
        tp = TaskParameters(cap, when=datetime(2025, 1, 1, tzinfo=UTC))
        me = MagicMock(spec=Identity)
        me.uuid = uuid4()
        task = Task(tp, me, size=1)
        tracker = TaskTracker(task)
        tracker.results[demoted.uuid] = None
        np.my_tasks[task.uuid] = tracker

        from autonomous_trust.core.identity.protocol import IdentityProtocol
        payload = '["%s", 1]' % str(demoted.uuid)
        msg = Message(CfgIds.negotiation, IdentityProtocol.tier_lost, payload)
        main_q = queue.Queue()
        np.handle_tier_lost({CfgIds.main: main_q}, msg)
        assert task.uuid not in np.my_tasks
        assert not main_q.empty()
        cancelled = main_q.get_nowait()
        assert isinstance(cancelled, TaskResult)
        assert cancelled.result == Status.cancelled

    def test_no_op_when_tier_still_meets_required(self):
        """Demotion to a tier that still meets the capability tier leaves my_tasks intact."""
        np = _make_neg_process()
        demoted = _make_mock_peer(nickname='demoted')
        cap = Capability('mid-cap', required_tier=1)
        tp = TaskParameters(cap, when=datetime(2025, 1, 1, tzinfo=UTC))
        me = MagicMock(spec=Identity)
        me.uuid = uuid4()
        task = Task(tp, me)
        tracker = TaskTracker(task)
        tracker.results[demoted.uuid] = None
        np.my_tasks[task.uuid] = tracker

        from autonomous_trust.core.identity.protocol import IdentityProtocol
        # Demoted to tier 2 — still ≥ required 1
        payload = '["%s", 2]' % str(demoted.uuid)
        msg = Message(CfgIds.negotiation, IdentityProtocol.tier_lost, payload)
        main_q = queue.Queue()
        np.handle_tier_lost({CfgIds.main: main_q}, msg)
        assert task.uuid in np.my_tasks
        assert demoted.uuid in tracker.results
        assert main_q.empty()


class TestHandleInviteFreshness:
    """The invitation's replay gate: a per-process monotonic sequence on the
    task (``TaskInfo.seq``, field 12 of ``negotiation/task.proto``) against the
    receiver's per-(sender, verb) high-water mark.

    The invitation is the negotiation verb that asks a peer to RUN something,
    and it was the one whose payload carried no freshness token of its own.
    See ``core/freshness.py`` and ``doc/architecture/security-hardening.md``,
    "Replay resistance, per verb".
    """


    @pytest.fixture(autouse=True)
    def _cold_freshness_root(self, tmp_path, monkeypatch):
        """A private, empty config root for each test in this class.

        Freshness state is deliberately persisted under
        ``Configuration.get_cfg_dir()`` -- a sender that rewound its counter
        would have its next messages refused by peers whose marks it cannot
        see. That is the right production behaviour and the wrong test
        behaviour: without an isolated root, the counter and marks carry over
        from whichever earlier test last pointed the config root somewhere
        writable, and the sequence numbers below stop being predictable.
        """
        monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
        (tmp_path / 'etc' / 'at').mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _invite(np, peer, seq, task=None, cap_name='video'):
        """A stamped invitation for a capable, acceptable task."""
        # A real registration, not a mocked __contains__: the tier gate reads
        # `required_tier` off the LOCALLY registered capability, and a MagicMock
        # there makes the gate refuse before the freshness behaviour under test
        # can be observed.
        np.protocol.capabilities.register_ability(cap_name, lambda: None)
        if task is None:
            tp = TaskParameters(Capability(cap_name),
                                when=datetime(2020, 1, 1, tzinfo=UTC))
            task = Task(tp, peer)
            task.to_json_string = MagicMock(return_value='yaml')
            task.parameters.acceptable = MagicMock(return_value=True)
        task.seq = seq
        return task, Message(CfgIds.negotiation, NegotiationProtocol.announce,
                             task, from_whom=peer)

    def test_first_stamped_invitation_is_accepted(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        task, msg = self._invite(np, peer, 1)
        net_q = queue.Queue()
        assert np.handle_invite({CfgIds.network: net_q}, msg) is True
        assert not net_q.empty()
        assert net_q.get_nowait().function == NegotiationProtocol.acceptance
        assert np.freshness.mark(str(peer.uuid),
                                 NegotiationProtocol.announce) == 1

    def test_replayed_invitation_is_refused_silently(self):
        """The same stamped invitation, redelivered, is dropped: no second
        admission, and no reply at all -- answering would spend a message on a
        sender we cannot vouch for and disclose where the mark sits."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        task, msg = self._invite(np, peer, 1)
        net_q = queue.Queue()
        assert np.handle_invite({CfgIds.network: net_q}, msg) is True
        net_q.get_nowait()  # the acceptance for the genuine delivery

        assert np.handle_invite({CfgIds.network: net_q}, msg) is True
        assert net_q.empty()
        # The replay never reached the flood counter either.
        assert np.flood_counts[task.uuid] == 1

    def test_unstamped_invitation_is_refused(self):
        """seq 0 -- an omitted proto field, a stripped JSON key, or a peer that
        has not been rebuilt. There is deliberately no lenient path: a receiver
        that accepts unstamped invitations is one an attacker selects by not
        stamping (doc/architecture/reputation.md, "Quorum attestation")."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        task, msg = self._invite(np, peer, 0)
        net_q = queue.Queue()
        assert np.handle_invite({CfgIds.network: net_q}, msg) is True
        assert net_q.empty()
        assert task.uuid not in np.flood_counts
        assert len(np.task_stack) == 0

    def test_stale_sequence_is_refused(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        _, msg = self._invite(np, peer, 5)
        net_q = queue.Queue()
        assert np.handle_invite({CfgIds.network: net_q}, msg) is True
        net_q.get_nowait()

        task, older = self._invite(np, peer, 4)
        assert np.handle_invite({CfgIds.network: net_q}, older) is True
        assert net_q.empty()

    def test_marks_are_per_sender(self):
        """Two requestors' sequences do not interfere: the mark is keyed
        per (sender, verb), so one peer's seq 1 does not consume another's."""
        np = _make_neg_process()
        alice, bob = _make_mock_peer(), _make_mock_peer(nickname='peer2')
        net_q = queue.Queue()
        for peer in (alice, bob):
            _, msg = self._invite(np, peer, 1)
            assert np.handle_invite({CfgIds.network: net_q}, msg) is True
            assert net_q.get_nowait().function == NegotiationProtocol.acceptance

    def test_replay_cannot_trip_the_flood_refusal(self):
        """The reason the freshness gate sits AHEAD of the flood counter.

        Redelivering one captured invitation past ``max_task_duplicates`` would
        otherwise make us emit a refusal -- which the requestor reads as "this
        worker is out" (``_cancel_participant``), turning a replay into a way
        of evicting a worker from a task it had already accepted.
        """
        np = _make_neg_process()
        peer = _make_mock_peer()
        task, msg = self._invite(np, peer, 1)
        net_q = queue.Queue()
        for _ in range(np.max_task_duplicates + 3):
            assert np.handle_invite({CfgIds.network: net_q}, msg) is True
        # One admission, one acceptance, and no refusal at any point.
        assert np.flood_counts[task.uuid] == 1
        emitted = [m.function for m in list(net_q.queue)]
        assert emitted == [NegotiationProtocol.acceptance]


class TestInvitationStamping:
    """The sender half: every invitation this process emits carries a fresh,
    monotonically increasing sequence."""


    @pytest.fixture(autouse=True)
    def _cold_freshness_root(self, tmp_path, monkeypatch):
        """A private, empty config root for each test in this class.

        Freshness state is deliberately persisted under
        ``Configuration.get_cfg_dir()`` -- a sender that rewound its counter
        would have its next messages refused by peers whose marks it cannot
        see. That is the right production behaviour and the wrong test
        behaviour: without an isolated root, the counter and marks carry over
        from whichever earlier test last pointed the config root somewhere
        writable, and the sequence numbers below stop being predictable.
        """
        monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
        (tmp_path / 'etc' / 'at').mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _capable(np, peer, cap_name='video'):
        np.protocol.peer_capabilities.items = MagicMock(
            return_value=[(cap_name, [peer.uuid])])
        np.protocol.peers.find_by_uuid = MagicMock(return_value=peer)

    def test_start_task_stamps_one_sequence_for_the_whole_fanout(self):
        """One stamp per announcement, not per peer: the invitation is a single
        act fanned out, and each receiver keeps its own mark."""
        np = _make_neg_process()
        peer_a = _make_mock_peer()
        peer_b = _make_mock_peer(nickname='peer2', address='10.0.0.2')
        np.protocol.peer_capabilities.items = MagicMock(
            return_value=[('video', [peer_a.uuid, peer_b.uuid])])
        np.protocol.peers.find_by_uuid = MagicMock(
            side_effect=lambda u: peer_a if u == peer_a.uuid else peer_b)

        tp = TaskParameters(Capability('video'),
                            when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer_a)
        task.to_json_string = MagicMock(return_value='yaml')
        net_q = queue.Queue()
        assert np.start_task({CfgIds.network: net_q}, Message(
            CfgIds.negotiation, NegotiationProtocol.start, task)) is True

        assert task.seq == 1
        assert len(list(net_q.queue)) == 2
        # Stamped before the fan-out, so both copies carry the one sequence.
        assert task.to_json_string.call_count == 2

    def test_successive_announcements_increase(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        self._capable(np, peer)
        seqs = []
        for _ in range(3):
            tp = TaskParameters(Capability('video'),
                                when=datetime(2020, 1, 1, tzinfo=UTC))
            task = Task(tp, peer)
            task.to_json_string = MagicMock(return_value='yaml')
            np.start_task({CfgIds.network: queue.Queue()}, Message(
                CfgIds.negotiation, NegotiationProtocol.start, task))
            seqs.append(task.seq)
        assert seqs == [1, 2, 3]

    def test_haggle_reannounce_draws_a_new_sequence(self):
        """The haggle resolution is a NEW invitation. Reusing the first
        invitation's sequence would have the peer refuse the resolution as a
        replay -- correctly, since it cannot tell the two apart otherwise."""
        np = _make_neg_process()
        peer = _make_mock_peer()
        self._capable(np, peer)

        tp = TaskParameters(Capability('video'), _flexible=True,
                            when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        task.to_json_string = MagicMock(return_value='yaml')
        assert np.start_task({CfgIds.network: queue.Queue()}, Message(
            CfgIds.negotiation, NegotiationProtocol.start, task)) is True
        assert task.seq == 1

        # The peer counter-proposes a later start time.
        counter_tp = TaskParameters(Capability('video'), _flexible=True,
                                    when=datetime(2020, 1, 2, tzinfo=UTC))
        counter = Task(counter_tp, peer, uuid=task.uuid, seq=task.seq)
        tracker = np.my_tasks[task.uuid]
        tracker.to_json_string = MagicMock(return_value='yaml')
        net_q = queue.Queue()
        assert np.handle_haggle({CfgIds.network: net_q}, Message(
            CfgIds.negotiation, NegotiationProtocol.response,
            counter, from_whom=peer)) is True

        out = list(net_q.queue)
        assert [m.function for m in out] == [NegotiationProtocol.announce]
        # Above the first invitation's sequence, so the peer's mark accepts it.
        assert tracker.seq == 2
        # And the conceded schedule actually moved.
        assert tracker.parameters.when == counter_tp.when
