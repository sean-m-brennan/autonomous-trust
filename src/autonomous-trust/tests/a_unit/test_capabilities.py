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
import pytest
from uuid import uuid4
from unittest.mock import MagicMock, patch

from autonomous_trust.core.capabilities import (
    Capability, Capabilities, PeerCapabilities, sanitize_descriptor,
    MAX_DESCRIPTION_LEN, MAX_KIND_LEN, MAX_ARG_SCHEMA_ENTRIES)


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
        assert d == {'name': 'task1', 'required_tier': 0, 'transaction_weight': 1}

    def test_descriptor_fields_are_runtime_only_not_on_wire(self):
        # Descriptor metadata must not ride the wire (no conformance impact):
        # it survives sync_to_message but a wire round-trip clears it.
        cap = Capability('task1', required_tier=2, description='desc',
                         kind='service', arg_schema={'a': 'int'})
        restored = Capability.from_wire_bytes(cap.to_wire_bytes())
        assert restored.name == 'task1'
        assert restored.required_tier == 2          # this IS on the wire
        assert restored.description == ''            # runtime-only, cleared
        assert restored.kind == ''
        assert restored.arg_schema is None

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

    def test_register_ability_with_descriptor(self):
        caps = Capabilities()
        caps.register_ability('video', lambda: None, required_tier=1,
                              description='live video feed', kind='data_stream',
                              arg_schema={'fps': 'int'})
        cap = caps['video']
        assert cap.description == 'live video feed'
        assert cap.kind == 'data_stream'
        assert cap.arg_schema == {'fps': 'int'}
        assert cap.required_tier == 1

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


class TestSanitizeDescriptor:
    def test_description_truncated(self):
        out = sanitize_descriptor({'description': 'x' * 10_000})
        assert len(out['description']) == MAX_DESCRIPTION_LEN

    def test_kind_truncated(self):
        out = sanitize_descriptor({'kind': 'k' * 1000})
        assert len(out['kind']) == MAX_KIND_LEN

    def test_arg_schema_entry_cap_and_field_lengths(self):
        big_schema = {('k%d' % i): 'v' for i in range(100)}
        big_schema['x' * 500] = 'y' * 500
        out = sanitize_descriptor({'arg_schema': big_schema})
        assert len(out['arg_schema']) <= MAX_ARG_SCHEMA_ENTRIES
        for k, v in out['arg_schema'].items():
            assert len(k) <= 64
            assert len(v) <= 64

    def test_required_tier_int_only(self):
        assert sanitize_descriptor({'required_tier': 3})['required_tier'] == 3
        # bools and non-ints are rejected
        assert 'required_tier' not in sanitize_descriptor({'required_tier': True})
        assert 'required_tier' not in sanitize_descriptor({'required_tier': 'hi'})

    def test_unknown_keys_dropped(self):
        out = sanitize_descriptor({'evil': 'x' * 10_000, 'description': 'ok'})
        assert out == {'description': 'ok'}

    def test_non_dict_returns_empty(self):
        assert sanitize_descriptor('not a dict') == {}


class TestPeerCapabilitiesDescriptors:
    def test_register_descriptor_sanitizes(self):
        pc = PeerCapabilities()
        pc.register_descriptor('video', {'required_tier': 1,
                                         'description': 'd' * 10_000,
                                         'kind': 'data_stream'})
        d = pc.descriptors['video']
        assert d['required_tier'] == 1
        assert len(d['description']) == MAX_DESCRIPTION_LEN
        assert d['kind'] == 'data_stream'

    def test_empty_descriptor_ignored(self):
        pc = PeerCapabilities()
        pc.register_descriptor('video', {})
        pc.register_descriptor('video', None)
        assert 'video' not in pc.descriptors

    def test_descriptors_not_serialized(self):
        # Descriptors are runtime-only: not on the protobuf wire / persist form.
        pc = PeerCapabilities()
        pid = uuid4()
        pc.register(pid, ['video'])
        pc.register_descriptor('video', {'required_tier': 2})
        restored = PeerCapabilities.from_wire_bytes(pc.to_wire_bytes())
        assert 'video' in restored          # name survives (in _listing)
        assert restored.descriptors == {}   # descriptor does not
