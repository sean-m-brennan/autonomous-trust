import queue
from unittest.mock import MagicMock, patch

import pytest

try:
    from autonomous_trust.inspector.inspector import InspectorProcess, Inspector
    from autonomous_trust.core.system import CfgIds
    has_inspector = True
except (ImportError, ModuleNotFoundError) as _e:
    has_inspector = False

pytestmark = pytest.mark.skipif(not has_inspector,
                                reason='inspector dependencies not available')


class TestInspectorProcess:
    def test_command_deck(self):
        assert 'package_hash' in InspectorProcess.command_deck
        assert 'log-level' in InspectorProcess.command_deck
        assert 'processes' in InspectorProcess.command_deck
        for item in CfgIds:
            assert item in InspectorProcess.command_deck

    def test_process_empty_queue(self):
        proc = MagicMock(spec=InspectorProcess)
        proc.name = 'monitor'
        proc.q_cadence = 0.01
        proc.configs = {}
        proc.command_deck = InspectorProcess.command_deck
        proc.keep_running = MagicMock(side_effect=[True, False])
        proc.process = InspectorProcess.process.__get__(proc)
        my_q = queue.Queue()
        queues = {proc.name: my_q, 'main': queue.Queue()}
        proc.process(queues, MagicMock())

    def test_process_valid_command(self):
        proc = MagicMock(spec=InspectorProcess)
        proc.name = 'monitor'
        proc.q_cadence = 0.01
        proc.configs = {'log-level': 'INFO'}
        proc.command_deck = InspectorProcess.command_deck
        proc.keep_running = MagicMock(side_effect=[True, False])
        proc.process = InspectorProcess.process.__get__(proc)
        my_q = queue.Queue()
        my_q.put('log-level')
        main_q = queue.Queue()
        queues = {proc.name: my_q, 'main': main_q}
        proc.process(queues, MagicMock())
        assert not main_q.empty()

    def test_process_invalid_command(self):
        proc = MagicMock(spec=InspectorProcess)
        proc.name = 'monitor'
        proc.q_cadence = 0.01
        proc.configs = {}
        proc.command_deck = InspectorProcess.command_deck
        proc.keep_running = MagicMock(side_effect=[True, False])
        proc.process = InspectorProcess.process.__get__(proc)
        my_q = queue.Queue()
        my_q.put('not-a-command')
        main_q = queue.Queue()
        queues = {proc.name: my_q, 'main': main_q}
        proc.process(queues, MagicMock())
        assert main_q.empty()

    def test_process_non_string_command(self):
        proc = MagicMock(spec=InspectorProcess)
        proc.name = 'monitor'
        proc.q_cadence = 0.01
        proc.configs = {}
        proc.command_deck = InspectorProcess.command_deck
        proc.keep_running = MagicMock(side_effect=[True, False])
        proc.process = InspectorProcess.process.__get__(proc)
        my_q = queue.Queue()
        my_q.put(42)  # not a string
        main_q = queue.Queue()
        queues = {proc.name: my_q, 'main': main_q}
        proc.process(queues, MagicMock())
        assert main_q.empty()
