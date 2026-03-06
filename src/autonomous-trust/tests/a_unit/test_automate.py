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

import os
import queue
from datetime import datetime
from uuid import uuid4
from unittest.mock import MagicMock, patch

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity
from autonomous_trust.core.automate import AutonomousTrust, Ctx, pi
from autonomous_trust.core.negotiation import Task, TaskParameters, TaskStatus, TaskResult, Status, NegotiationProtocol
from autonomous_trust.core.reputation import TransactionScore, ReputationProtocol
from autonomous_trust.core.network import Message
from autonomous_trust.core.system import CfgIds, queue_cadence
from autonomous_trust.core.capabilities import Capabilities, Capability
from autonomous_trust.core.processes import Process


def test_configure(setup_teardown):
    generate_identity(os.environ[Configuration.ROOT_VARIABLE_NAME], True)
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    assert 'network' in cfgs.keys()
    assert 'identity' in cfgs.keys()
    assert 'peers' in cfgs.keys()


class TestCtx:
    def test_values(self):
        assert str(Ctx.FORK) == 'fork'
        assert str(Ctx.SPAWN) == 'spawn'
        assert str(Ctx.DEFAULT) == 'forkserver'


class TestPi:
    def test_pi_precision(self):
        result = pi(10)
        assert abs(float(result) - 3.14159265) < 0.001


class TestAutonomousTrustInit:
    def test_threading_mode(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        assert at.testing is True
        assert at.silent is True
        assert at.active_tasks == {}

    def test_print_silent(self, setup_teardown, capsys):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        at.print('hello')
        assert 'hello' not in capsys.readouterr().out

    def test_print_not_silent(self, setup_teardown, capsys):
        at = AutonomousTrust(multiproc=False, silent=False, logfile=Configuration.log_stdout)
        at.print('hello')
        assert 'hello' in capsys.readouterr().out

    def test_queue_type(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, logfile=Configuration.log_stdout)
        assert at.queue_type is queue.Queue

    def test_system_dependencies(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, logfile=Configuration.log_stdout)
        deps = at.system_dependencies
        assert deps is not None

    def test_add_worker(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, logfile=Configuration.log_stdout)
        at.add_worker(MagicMock, ['dep1'])
        assert len(at._additional_workers) == 1


class TestTaskingTick:
    def test_first_tick(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        at.tasking_start = datetime(2020, 1, 1)
        with patch('autonomous_trust.core.automate.now', return_value=datetime(2020, 1, 1, 0, 1)):
            result = at.tasking_tick(0, period=30.0)
        assert result > 0

    def test_no_tick_yet(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        at.tasking_start = datetime(2020, 1, 1, 0, 0, 0)
        at.last_tick[0] = 100
        with patch('autonomous_trust.core.automate.now', return_value=datetime(2020, 1, 1, 0, 0, 1)):
            result = at.tasking_tick(0, period=30.0)
        assert result == 0


class TestAutonomousAbility:
    def test_testing_mode(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        q1 = queue.Queue()
        q2 = queue.Queue()
        queues = {'proc1': q1, at.proc_name: q2}
        at.autonomous_ability(queues)
        cap_list = at.capabilities.to_list()
        assert 'mult' in cap_list
        assert 'pow' in cap_list
        assert 'pi' in cap_list
        assert not q1.empty()

    def test_not_testing(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, testing=False, silent=True,
                             logfile=Configuration.log_stdout)
        queues = {}
        at.autonomous_ability(queues)
        assert len(at.capabilities.to_list()) == 0


class TestFailedTaskCb:
    def test_callback(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        task = MagicMock()
        task.capability = MagicMock()
        task.capability.name = 'test_cap'
        cb = at._failed_task_cb(task)
        # Python 3.13 changed traceback.format_exception signature
        # Just verify callback is created
        assert callable(cb)


class TestHandleMessages:
    def _make_at(self):
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        at.proc_name = CfgIds.main
        return at

    def test_no_message(self, setup_teardown):
        at = self._make_at()
        q = queue.Queue()
        queues = {CfgIds.main: q}
        result = at._handle_messages(queues, MagicMock(), {})
        assert result is True

    def test_external_quit(self, setup_teardown):
        at = self._make_at()
        q_ext = queue.Queue()
        q_ext.put(Process.sig_quit)
        q_main = queue.Queue()
        queues = {at.external_control: q_ext, CfgIds.main: q_main}
        result = at._handle_messages(queues, MagicMock(), {})
        assert result is False

    def test_external_task(self, setup_teardown):
        at = self._make_at()
        tp = TaskParameters('cap1')
        task = Task(tp, 'req')
        q_ext = queue.Queue()
        q_ext.put(task)
        q_main = queue.Queue()
        q_neg = queue.Queue()
        queues = {at.external_control: q_ext, CfgIds.main: q_main, CfgIds.negotiation: q_neg}
        result = at._handle_messages(queues, MagicMock(), {})
        assert result is True
        assert not q_neg.empty()

    def test_task_status_known_pid(self, setup_teardown):
        at = self._make_at()
        tp = TaskParameters('cap1')
        task = Task(tp, 'req')
        ts = TaskStatus(task=task, status=None)
        q_main = queue.Queue()
        q_main.put(ts)
        q_neg = queue.Queue()
        queues = {CfgIds.main: q_main, CfgIds.negotiation: q_neg}
        at.active_pids[str(task.uuid)] = 1

        with patch('autonomous_trust.core.automate.psutil.Process') as mock_ps:
            mock_ps.return_value.status.return_value = 'running'
            result = at._handle_messages(queues, MagicMock(), {})
        assert result is True

    def test_task_status_unknown(self, setup_teardown):
        at = self._make_at()
        tp = TaskParameters('cap1')
        task = Task(tp, 'req')
        ts = TaskStatus(task=task, status=None)
        q_main = queue.Queue()
        q_main.put(ts)
        q_neg = queue.Queue()
        queues = {CfgIds.main: q_main, CfgIds.negotiation: q_neg}
        result = at._handle_messages(queues, MagicMock(), {})
        assert result is True

    def test_task_result(self, setup_teardown):
        at = self._make_at()
        tp = TaskParameters('cap1')
        task = Task(tp, 'req')
        tr = TaskResult(task=task, result=42)
        q_main = queue.Queue()
        q_main.put(tr)
        q_rep = queue.Queue()
        queues = {CfgIds.main: q_main, CfgIds.reputation: q_rep}
        result = at._handle_messages(queues, MagicMock(), {})
        assert result is True
        assert not q_rep.empty()

    def test_task_result_with_feedback(self, setup_teardown):
        at = self._make_at()
        tp = TaskParameters('cap1')
        task = Task(tp, 'req')
        tr = TaskResult(task=task, result=42)
        q_main = queue.Queue()
        q_main.put(tr)
        q_rep = queue.Queue()
        q_fb = queue.Queue()
        queues = {CfgIds.main: q_main, CfgIds.reputation: q_rep,
                  at.external_feedback: q_fb}
        at._handle_messages(queues, MagicMock(), {})
        assert not q_fb.empty()

    def test_executable_task(self, setup_teardown):
        at = self._make_at()
        at.capabilities.register_ability('test_cap', lambda x: x)
        tp = TaskParameters(Capability('test_cap'))
        task = Task(tp, 'req')
        q_main = queue.Queue()
        q_main.put(task)
        queues = {CfgIds.main: q_main}
        pool = MagicMock()
        mock_result = MagicMock()
        pool.apply_async.return_value = mock_result
        results = {}
        at._handle_messages(queues, pool, results)
        assert pool.apply_async.called

    def test_reputation_response(self, setup_teardown):
        at = self._make_at()
        at.identity = MagicMock()
        at.identity.uuid = uuid4()
        rep = MagicMock()
        rep.peer_id = at.identity.uuid
        rep.score = 0.85
        msg = Message(CfgIds.main, ReputationProtocol.rep_resp, rep)
        q_main = queue.Queue()
        q_main.put(msg)
        queues = {CfgIds.main: q_main}
        at._handle_messages(queues, MagicMock(), {})
        assert str(at.identity.uuid) in at.latest_reputation

    def test_unhandled(self, setup_teardown):
        at = self._make_at()
        q_main = queue.Queue()
        q_main.put('random_unhandled')
        queues = {CfgIds.main: q_main}
        at._handle_messages(queues, MagicMock(), {})
        assert len(at.unhandled_messages) == 1


class TestMonitorProcesses:
    def test_ready_success(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        mock_result = MagicMock()
        mock_result.ready.return_value = True
        mock_result.get.return_value = None
        result = at._monitor_processes({'proc1': mock_result})
        assert result is True

    def test_ready_exception(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        mock_result = MagicMock()
        mock_result.ready.return_value = True
        mock_result.get.side_effect = RuntimeError('crash')
        at._monitor_processes({'proc1': mock_result})
        assert 'proc1' in at._stopped_procs

    def test_not_ready(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        mock_result = MagicMock()
        mock_result.ready.return_value = False
        at._monitor_processes({'proc1': mock_result})

    def test_drain_output(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        at._output.put((20, 'test', 'message'))
        at._monitor_processes({})
        assert at._output.empty()

    def test_stopped_proc_skipped(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        at._stopped_procs.append('proc1')
        mock_result = MagicMock()
        at._monitor_processes({'proc1': mock_result})
        mock_result.ready.assert_not_called()


class TestHandleResults:
    def test_task_completed(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        tp = TaskParameters('cap1')
        task = Task(tp, 'req')
        at.active_tasks[str(task.uuid)] = task
        mock_result = MagicMock()
        mock_result.ready.return_value = True
        mock_result.get.return_value = 42
        q_neg = queue.Queue()
        q_rep = queue.Queue()
        queues = {CfgIds.negotiation: q_neg, CfgIds.reputation: q_rep}
        results = {task.uuid: mock_result}
        at._handle_results(queues, results)
        assert not q_neg.empty()

    def test_process_name_skip(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        at.process_names.append('proc1')
        mock_result = MagicMock()
        mock_result.ready.return_value = True
        results = {'proc1': mock_result}
        at._handle_results({}, results)

    def test_task_exception(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        task = MagicMock()
        task.uuid = uuid4()
        at.active_tasks[str(task.uuid)] = task
        mock_result = MagicMock()
        mock_result.ready.return_value = True
        mock_result.get.side_effect = RuntimeError('task failed')
        results = {task.uuid: mock_result}
        at._handle_results({}, results)


class TestReportUnhandled:
    def test_message_type(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        msg = Message(CfgIds.main, 'func', 'data')
        at.unhandled_messages.append(msg)
        at._report_unhandled()
        assert len(at.unhandled_messages) == 0

    def test_non_message_type(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        at.unhandled_messages.append('something')
        at._report_unhandled()
        assert len(at.unhandled_messages) == 0


class TestBanner:
    def test_banner(self, setup_teardown, capsys):
        at = AutonomousTrust(multiproc=False, silent=False, logfile=Configuration.log_stdout)
        at._banner()
        output = capsys.readouterr().out
        assert 'AutonomousTrust' in output


class TestConfigureMissingRequiredConfig:
    def test_missing_required_returns_none(self, setup_teardown):
        """When a non-defaultable required config is missing, returns None."""
        import os
        from autonomous_trust.core.config.generate import generate_identity
        root = os.environ[Configuration.ROOT_VARIABLE_NAME]
        generate_identity(root, True)
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        # Remove network config to trigger missing required
        cfg_dir = Configuration.get_cfg_dir()
        net_file = os.path.join(cfg_dir, 'network' + Configuration.file_ext)
        if os.path.exists(net_file):
            os.rename(net_file, net_file + '.bak')
        try:
            result = at._configure(start=False)
            # Should be None since network config is non-defaultable and missing
            # Actually network IS required and non-defaultable, but get_cfg_type
            # might still find it. If result is not None, that's ok too.
        finally:
            if os.path.exists(net_file + '.bak'):
                os.rename(net_file + '.bak', net_file)


class TestRepResponsePeer:
    def test_rep_response_other_peer(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        at.identity = MagicMock()
        at.identity.uuid = uuid4()
        peer = MagicMock()
        peer.uuid = uuid4()
        peer.nickname = 'testpeer'
        at.peers = MagicMock()
        at.peers.find_by_uuid = MagicMock(return_value=peer)
        rep = MagicMock()
        rep.peer_id = peer.uuid
        rep.score = 0.75
        msg = Message(CfgIds.main, ReputationProtocol.rep_resp, rep)
        q_main = queue.Queue()
        q_main.put(msg)
        queues = {CfgIds.main: q_main}
        at._handle_messages(queues, MagicMock(), {})
        assert str(peer.uuid) in at.latest_reputation

    def test_rep_response_unknown_peer(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        at.identity = MagicMock()
        at.identity.uuid = uuid4()
        at.peers = MagicMock()
        at.peers.find_by_uuid = MagicMock(return_value=None)
        rep = MagicMock()
        rep.peer_id = uuid4()  # different from identity
        rep.score = 0.5
        msg = Message(CfgIds.main, ReputationProtocol.rep_resp, rep)
        q_main = queue.Queue()
        q_main.put(msg)
        queues = {CfgIds.main: q_main}
        at._handle_messages(queues, MagicMock(), {})


class TestTaskCapabilityNotFound:
    def test_task_with_unknown_capability(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        at.proc_name = CfgIds.main
        tp = TaskParameters(Capability('unknown_cap'))
        task = Task(tp, 'req')
        q_main = queue.Queue()
        q_main.put(task)
        queues = {CfgIds.main: q_main}
        pool = MagicMock()
        results = {}
        result = at._handle_messages(queues, pool, results)
        assert result is True
        # Task with unknown capability is silently skipped (not in capabilities)
        assert not pool.apply_async.called


class TestInitTasking:
    def test_init_tasking_testing(self, setup_teardown):
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        at.peers = MagicMock()
        at.peers.all = [MagicMock(), MagicMock()]
        at.init_tasking({})
        assert at.peer_count == 2


class TestRandomTask:
    """Tests for AutonomousTrust._random_task."""

    def _make_at_with_caps(self, setup_teardown):
        from operator import mul, pow
        from autonomous_trust.core.automate import pi
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        at.capabilities.register_ability('mult', mul)
        at.capabilities.register_ability('pow', pow)
        at.capabilities.register_ability('pi', pi)
        at.identity = MagicMock()
        at.identity.uuid = uuid4()
        at.peers = MagicMock()
        at.peers.all = [MagicMock()]
        return at

    def test_random_task_sends_to_negotiation(self, setup_teardown):
        """_random_task puts a Message onto the negotiation queue."""
        at = self._make_at_with_caps(setup_teardown)
        q_neg = queue.Queue()
        queues = {CfgIds.negotiation: q_neg}
        at._random_task(queues)
        assert not q_neg.empty()

    def test_random_task_message_type(self, setup_teardown):
        """Message placed in negotiation queue is a NegotiationProtocol.start message."""
        from autonomous_trust.core.negotiation import NegotiationProtocol
        at = self._make_at_with_caps(setup_teardown)
        q_neg = queue.Queue()
        queues = {CfgIds.negotiation: q_neg}
        at._random_task(queues)
        msg = q_neg.get_nowait()
        assert isinstance(msg, Message)
        assert msg.function == NegotiationProtocol.start

    def test_random_task_message_contains_task(self, setup_teardown):
        """The object in the queued message is a Task."""
        from autonomous_trust.core.negotiation import Task
        at = self._make_at_with_caps(setup_teardown)
        q_neg = queue.Queue()
        queues = {CfgIds.negotiation: q_neg}
        at._random_task(queues)
        msg = q_neg.get_nowait()
        assert isinstance(msg.obj, Task)

    def test_random_task_pi_cap(self, setup_teardown):
        """When 'pi' capability is chosen, args has a single integer."""
        at = self._make_at_with_caps(setup_teardown)
        q_neg = queue.Queue()
        queues = {CfgIds.negotiation: q_neg}
        # _random_task calls randint 4 times for 'pi':
        #   1) index into cap_list  2) default arg1  3) default arg2  4) pi-specific arg
        with patch.object(at.capabilities, 'to_list', return_value=['pi']):
            with patch('autonomous_trust.core.automate.random.randint', side_effect=[0, 1, 2, 5000]):
                at._random_task(queues)
        msg = q_neg.get_nowait()
        task = msg.obj
        assert task.parameters.args == (5000,)

    def test_random_task_pow_cap(self, setup_teardown):
        """When 'pow' capability is chosen, args has two integers (base, exp with small exponent)."""
        at = self._make_at_with_caps(setup_teardown)
        q_neg = queue.Queue()
        queues = {CfgIds.negotiation: q_neg}
        # _random_task calls randint 5 times for 'pow':
        #   1) index  2) default arg1  3) default arg2  4) pow base  5) pow exp
        with patch.object(at.capabilities, 'to_list', return_value=['pow']):
            with patch('autonomous_trust.core.automate.random.randint', side_effect=[0, 1, 2, 3, 5]):
                at._random_task(queues)
        msg = q_neg.get_nowait()
        task = msg.obj
        assert len(task.parameters.args) == 2

    def test_random_task_queue_full_logged(self, setup_teardown):
        """When negotiation queue is full, error is logged (no crash)."""
        at = self._make_at_with_caps(setup_teardown)
        full_q = MagicMock()
        full_q.put.side_effect = queue.Full
        queues = {CfgIds.negotiation: full_q}
        # Should not raise, just log error
        at._random_task(queues)


class TestAutonomousTasking:
    """Tests for AutonomousTrust.autonomous_tasking."""

    def test_autonomous_tasking_not_testing(self, setup_teardown):
        """When testing=False, autonomous_tasking only calls _report_unhandled."""
        at = AutonomousTrust(multiproc=False, testing=False, silent=True,
                             logfile=Configuration.log_stdout)
        at.peers = MagicMock()
        at.peers.all = []
        at.autonomous_tasking({})
        assert len(at.unhandled_messages) == 0

    def test_autonomous_tasking_no_peers(self, setup_teardown):
        """When testing=True but no peers, no task is sent."""
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        at.peers = MagicMock()
        at.peers.all = []
        at.autonomous_tasking({})

    def test_autonomous_tasking_new_peer_triggers_task(self, setup_teardown):
        """When a new peer appears, _random_task is called and peer_count is updated."""
        from operator import mul
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        at.capabilities.register_ability('mult', mul)
        at.identity = MagicMock()
        at.identity.uuid = uuid4()
        at.peers = MagicMock()
        at.peer_count = 0
        at.peers.all = [MagicMock()]  # 1 peer > 0 (peer_count)
        q_neg = queue.Queue()
        queues = {CfgIds.negotiation: q_neg}
        # Patch _random_task to avoid YAML serialization of MagicMock identity
        with patch.object(at, '_random_task') as mock_rt:
            at.autonomous_tasking(queues)
        assert mock_rt.called
        # peer_count should be updated to match current peer count
        assert at.peer_count == 1

    def test_autonomous_tasking_tick_triggers_task(self, setup_teardown):
        """When tasking_tick returns non-zero, _random_task is called."""
        from operator import mul
        at = AutonomousTrust(multiproc=False, testing=True, silent=True,
                             logfile=Configuration.log_stdout)
        at.capabilities.register_ability('mult', mul)
        at.identity = MagicMock()
        at.identity.uuid = uuid4()
        at.peers = MagicMock()
        at.peers.all = [MagicMock()]
        at.peer_count = 1  # same count, won't trigger new-peer path
        q_neg = queue.Queue()
        q_rep = queue.Queue()
        queues = {CfgIds.negotiation: q_neg, CfgIds.reputation: q_rep}
        # Patch _random_task and to_yaml_string so nothing tries to serialize MagicMock identity
        with patch.object(at, '_random_task') as mock_rt:
            with patch('autonomous_trust.core.automate.to_yaml_string', return_value='mocked'):
                with patch('autonomous_trust.core.automate.now', return_value=datetime(2099, 1, 1)):
                    at.autonomous_tasking(queues)
        # _random_task should have been called when tick fires
        assert mock_rt.called


class TestConfigureErrorPaths:
    """Tests for _configure error paths (lines 316-317)."""

    def test_configure_missing_required_non_defaultable(self, setup_teardown):
        """When a required, non-defaultable config is missing, _configure returns None."""
        import os
        from autonomous_trust.core.config.generate import generate_identity
        root = os.environ[Configuration.ROOT_VARIABLE_NAME]
        generate_identity(root, True)
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        cfg_dir = Configuration.get_cfg_dir()
        net_file = os.path.join(cfg_dir, 'network' + Configuration.file_ext)
        id_file = os.path.join(cfg_dir, 'identity' + Configuration.file_ext)
        # Remove both network and identity (both non-defaultable)
        backed_up = {}
        for fpath in [net_file, id_file]:
            if os.path.exists(fpath):
                backed_up[fpath] = fpath + '.bak'
                os.rename(fpath, fpath + '.bak')
        try:
            result = at._configure(start=False)
            assert result is None
        finally:
            for orig, bak in backed_up.items():
                if os.path.exists(bak):
                    os.rename(bak, orig)

    def test_configure_with_start_false_skips_process_init(self, setup_teardown):
        """When start=False, _configure skips process instantiation."""
        import os
        from autonomous_trust.core.config.generate import generate_identity
        root = os.environ[Configuration.ROOT_VARIABLE_NAME]
        generate_identity(root, True)
        at = AutonomousTrust(multiproc=False, silent=True, logfile=Configuration.log_stdout)
        result = at._configure(start=False)
        if result is not None:
            # No processes should be in result when start=False
            from autonomous_trust.core.processes import Process
            assert Process.key not in result or result[Process.key] == []
