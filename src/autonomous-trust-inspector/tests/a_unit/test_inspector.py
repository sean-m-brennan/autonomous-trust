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
