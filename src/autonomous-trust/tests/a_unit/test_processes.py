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
import logging
from unittest.mock import MagicMock, patch
from io import StringIO

from autonomous_trust.core.processes import (
    ProcessTracker, LogLevel, ProcMeta, Process, ProcessLogger, Mockery,
)


class TestProcessTracker:
    def test_init_empty(self):
        pt = ProcessTracker()
        assert len(pt) == 0
        assert pt.classes == {}
        assert pt.ordered == []

    def test_register_subsystem(self):
        pt = ProcessTracker()
        pt.register_subsystem('network', 'autonomous_trust.core.network.UDPNetworkProcess')
        assert len(pt) == 1
        assert 'network' in pt
        assert pt['network'] is not None

    def test_classes_property(self):
        pt = ProcessTracker()
        pt.register_subsystem('network', 'autonomous_trust.core.network.UDPNetworkProcess')
        cls = pt.classes
        assert 'network' in cls

    def test_names_property(self):
        pt = ProcessTracker()
        pt.register_subsystem('network', 'autonomous_trust.core.network.UDPNetworkProcess')
        assert 'network' in pt.names

    def test_to_yaml_string(self):
        pt = ProcessTracker()
        pt.register_subsystem('network', 'autonomous_trust.core.network.UDPNetworkProcess')
        yml = pt.to_yaml_string()
        assert 'network' in yml

    def test_from_yaml_string(self):
        pt = ProcessTracker()
        pt.register_subsystem('network', 'autonomous_trust.core.network.UDPNetworkProcess')
        yml = pt.to_yaml_string()
        pt2 = ProcessTracker()
        pt2.from_yaml_string(yml)
        assert len(pt2) == 1

    def test_iter(self):
        pt = ProcessTracker()
        pt.register_subsystem('network', 'autonomous_trust.core.network.UDPNetworkProcess')
        keys = list(pt)
        assert 'network' in keys

    def test_ordered(self):
        pt = ProcessTracker()
        pt.register_subsystem('network', 'autonomous_trust.core.network.UDPNetworkProcess')
        assert len(pt.ordered) == 1


class TestLogLevel:
    def test_values(self):
        assert LogLevel.CRITICAL == logging.CRITICAL
        assert LogLevel.ERROR == logging.ERROR
        assert LogLevel.WARNING == logging.WARNING
        assert LogLevel.INFO == logging.INFO
        assert LogLevel.DEBUG == logging.DEBUG
        assert LogLevel.VERBOSE == logging.DEBUG - 1


class TestProcMeta:
    def test_creates_class(self):
        TestProc = ProcMeta('TestProc', (), {}, proc_name='test', description='A test')
        assert TestProc.name == 'test'
        assert TestProc.description == 'A test'
        assert TestProc.cfg_name == 'test'

    def test_cfg_name_default(self):
        TestProc = ProcMeta('TestProc', (), {}, proc_name='myproc')
        assert TestProc.cfg_name == 'myproc'

    def test_cfg_name_explicit(self):
        TestProc = ProcMeta('TestProc', (), {}, proc_name='myproc', cfg_name='custom')
        assert TestProc.cfg_name == 'custom'


class TestProcessLogger:
    def test_init(self):
        q = queue.Queue()
        pl = ProcessLogger('test', q)
        assert pl.name == 'test'
        assert pl.suppress is False

    def test_log_to_queue(self):
        q = queue.Queue()
        pl = ProcessLogger('test', q)
        pl.info('hello')
        level, name, msg = q.get_nowait()
        assert level == LogLevel.INFO
        assert name == 'test'
        assert msg == 'hello'

    def test_log_suppressed(self):
        q = queue.Queue()
        pl = ProcessLogger('test', q, suppress=True)
        pl.info('hello')
        assert q.empty()

    def test_log_no_queue(self):
        pl = ProcessLogger('test', None)
        pl.info('hello')  # should use logger fallback, not crash

    def test_verbose(self):
        q = queue.Queue()
        pl = ProcessLogger('test', q)
        pl.verbose('v')
        level, _, _ = q.get_nowait()
        assert level == LogLevel.VERBOSE

    def test_debug(self):
        q = queue.Queue()
        pl = ProcessLogger('test', q)
        pl.debug('d')
        level, _, _ = q.get_nowait()
        assert level == LogLevel.DEBUG

    def test_warning(self):
        q = queue.Queue()
        pl = ProcessLogger('test', q)
        pl.warning('w')
        level, _, _ = q.get_nowait()
        assert level == LogLevel.WARNING

    def test_error(self):
        q = queue.Queue()
        pl = ProcessLogger('test', q)
        pl.error('e')
        level, _, _ = q.get_nowait()
        assert level == LogLevel.ERROR

    def test_critical(self):
        q = queue.Queue()
        pl = ProcessLogger('test', q)
        pl.critical('c')
        level, _, _ = q.get_nowait()
        assert level == LogLevel.CRITICAL

    def test_flush_with_handler(self):
        pl = ProcessLogger('test', None)
        handler = MagicMock()
        pl.logger.addHandler(handler)
        pl.flush()
        handler.flush.assert_called_once()
        pl.logger.removeHandler(handler)

    def test_flush_no_handler(self):
        pl = ProcessLogger('test', None)
        pl.flush()  # should not crash


class TestProcess:
    def _make_process(self, deps=None):
        log_q = queue.Queue()
        # Create a minimal mock subsystems/configurations setup
        mock_proc_cls = MagicMock()
        mock_proc_cls.name = 'network'
        configs = {
            'processes': [mock_proc_cls],
        }
        subsystems = ProcessTracker()
        return Process(configs, subsystems, log_q, dependencies=deps or [])

    def test_init(self):
        p = self._make_process()
        assert p.dependencies == []
        assert p.loop_start is None
        assert p.mocks == []

    def test_unmet_dependency_raises(self):
        log_q = queue.Queue()
        configs = {'processes': []}
        subsystems = ProcessTracker()
        with pytest.raises(RuntimeError, match='Unmet dependency'):
            Process(configs, subsystems, log_q, dependencies=['missing_dep'])

    def test_keep_running_no_signal(self):
        p = self._make_process()
        sig = queue.Queue()
        assert p.keep_running(sig) is True
        assert p.loop_start is not None

    def test_keep_running_quit_signal(self):
        p = self._make_process()
        sig = queue.Queue()
        sig.put(Process.sig_quit)
        assert p.keep_running(sig) is False

    def test_sleep_until(self):
        p = self._make_process()
        sig = queue.Queue()
        p.keep_running(sig)  # sets loop_start
        p.sleep_until(0)  # delta should be negative, no sleep

    def test_getstate_setstate(self):
        p = self._make_process()
        state = p.__getstate__()
        assert isinstance(state, dict)
        p2 = self._make_process()
        p2.__setstate__(state)

    def test_report_exception(self):
        p = self._make_process()
        try:
            raise ValueError('test error')
        except ValueError as e:
            p.report_exception(e, 'test_func')
        # Check it logged
        level, name, msg = p.log_queue.get_nowait()
        assert 'ValueError' in msg
        assert 'test_func' in msg

    def test_report_exception_no_function(self):
        p = self._make_process()
        try:
            raise RuntimeError('oops')
        except RuntimeError as e:
            p.report_exception(e)
        level, name, msg = p.log_queue.get_nowait()
        assert 'RuntimeError' in msg

    def test_update(self):
        p = self._make_process()
        q1 = queue.Queue()
        q2 = queue.Queue()
        # Process.name is set by ProcMeta to 'unknown' by default
        queues = {'other_proc': q1, 'unknown': q2}
        msg = 'test_msg'
        p.update(msg, queues)
        assert q1.get_nowait() == 'test_msg'
        assert q2.empty()  # should not send to self

    def test_process_not_implemented(self):
        p = self._make_process()
        with pytest.raises(NotImplementedError):
            p.process({}, queue.Queue())

    def test_log_level_from_config(self):
        log_q = queue.Queue()
        mock_proc = MagicMock()
        mock_proc.name = 'network'
        configs = {
            'processes': [mock_proc],
            Process.level: LogLevel.DEBUG,
        }
        p = Process(configs, ProcessTracker(), log_q)
        assert p.log_level == LogLevel.DEBUG


class TestMockery:
    def test_init(self):
        m = Mockery('some.path')
        assert m.name == 'some.path'
        assert m.obj is None
        assert m.value is None

    def test_patch_name_only(self):
        m = Mockery('some.path')
        mocker = MagicMock()
        m.patch(mocker)
        mocker.patch.assert_called_once_with('some.path')

    def test_patch_obj_no_value(self):
        obj = MagicMock()
        m = Mockery('attr', obj=obj)
        mocker = MagicMock()
        m.patch(mocker)
        mocker.patch.object.assert_called_once_with(obj, 'attr')

    def test_patch_obj_with_value(self):
        obj = MagicMock()
        m = Mockery('attr', obj=obj, value=42)
        mocker = MagicMock()
        m.patch(mocker)
        mocker.patch.object.assert_called_once_with(obj, 'attr', return_value=42)
