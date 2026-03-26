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
from uuid import uuid4
from unittest.mock import MagicMock, patch

from autonomous_trust.core.capabilities import Capability, Capabilities, PeerCapabilities


class TestCapability:
    def test_init(self):
        cap = Capability('task1')
        assert cap.name == 'task1'
        assert cap.function is None

    def test_eq(self):
        c1 = Capability('task1')
        c2 = Capability('task1')
        c3 = Capability('task2')
        assert c1 == c2
        assert not (c1 == c3)

    def test_to_dict(self):
        cap = Capability('task1')
        d = cap.to_dict()
        assert d == {'name': 'task1'}

    def test_execute(self):
        func = MagicMock(return_value=42)
        cap = Capability('task1', function=func)
        task = MagicMock()
        task.parameters.args = (1, 2)
        task.parameters.kwargs = {'x': 3}
        pid_q = MagicMock()
        with patch('autonomous_trust.core.capabilities.multiprocessing') as mock_mp:
            mock_mp.current_process.return_value.pid = 123
            result = cap.execute(task, pid_q)
        assert result == 42
        func.assert_called_once_with(1, 2, x=3)
        pid_q.put_nowait.assert_called_once_with(123)


class TestCapabilities:
    def test_init_empty(self):
        caps = Capabilities()
        assert len(caps) == 0

    def test_register_ability(self):
        caps = Capabilities()
        caps.register_ability('task1', lambda: None)
        assert len(caps) == 1
        assert caps['task1'].name == 'task1'

    def test_contains(self):
        caps = Capabilities()
        caps.register_ability('task1', lambda: None)
        assert caps['task1'] in caps

    def test_to_list(self):
        caps = Capabilities()
        caps.register_ability('task1', lambda: None)
        caps.register_ability('task2', lambda: None)
        names = caps.to_list()
        assert 'task1' in names
        assert 'task2' in names

    def test_iter(self):
        caps = Capabilities()
        caps.register_ability('task1', lambda: None)
        keys = list(caps)
        assert 'task1' in keys


class TestPeerCapabilities:
    def test_init_empty(self):
        pc = PeerCapabilities()
        assert len(pc) == 0

    def test_register(self):
        pc = PeerCapabilities()
        pid = uuid4()
        pc.register(pid, ['cap1', 'cap2'])
        assert len(pc) == 2
        assert pid in pc['cap1']
        assert pid in pc['cap2']

    def test_register_multiple_peers(self):
        pc = PeerCapabilities()
        p1, p2 = uuid4(), uuid4()
        pc.register(p1, ['cap1'])
        pc.register(p2, ['cap1'])
        assert len(pc['cap1']) == 2

    def test_iter(self):
        pc = PeerCapabilities()
        pc.register(uuid4(), ['cap1', 'cap2'])
        keys = list(pc)
        assert 'cap1' in keys
        assert 'cap2' in keys

    def test_init_with_listing(self):
        pc = PeerCapabilities(_listing={'cap1': [uuid4()]})
        assert len(pc) == 1
