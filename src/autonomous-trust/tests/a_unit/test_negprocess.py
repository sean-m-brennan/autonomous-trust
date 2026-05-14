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
        for _ in range(np.max_task_duplicates + 2):
            np.handle_invite({CfgIds.network: queue.Queue()}, msg)
        np.protocol.peers.demote.assert_not_called()


class TestHandleHaggleDeeper:
    def test_flexible_task(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        task.to_json_string = MagicMock(return_value='yaml')
        task.parameters.flexible = True
        msg = Message(CfgIds.negotiation, NegotiationProtocol.response,
                      task, from_whom=peer)
        net_q = queue.Queue()
        result = np.handle_haggle({CfgIds.network: net_q}, msg)
        assert result is True
        assert not net_q.empty()

    def test_inflexible_task(self):
        np = _make_neg_process()
        peer = _make_mock_peer()
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        task.parameters.flexible = False
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

        for _ in range(np.max_task_duplicates + 1):
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
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer)
        task.to_json_string = MagicMock(return_value='yaml')
        task.parameters.flexible = True
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
        tp = TaskParameters('cap1', when=datetime(2020, 1, 1, tzinfo=UTC))
        task = Task(tp, peer, size=2)
        task.parameters.flexible = False
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
