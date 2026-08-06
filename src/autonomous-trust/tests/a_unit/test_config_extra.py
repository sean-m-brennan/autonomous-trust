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
import os
import pytest
from io import StringIO
from datetime import timedelta
from decimal import Decimal

from nacl.signing import SigningKey

from autonomous_trust.core.config.configuration import (
    Configuration, InitializableConfig, EmptyObject, SerializeMode,
    to_yaml_string, from_yaml_string,
)

from .. import TEST_DIR


class SimpleCfg(Configuration):
    def __init__(self, name='test', value=42):
        self.name = name
        self.value = value


class NestedCfg(Configuration):
    def __init__(self, inner=None, label='outer'):
        self.inner = inner
        self.label = label


class TestSerializeMode:
    def test_values(self):
        assert SerializeMode.PROTO.value == 1
        assert SerializeMode.JSON.value == 2
        assert SerializeMode.PJSON.value == 3


class TestConfiguration:
    def test_to_dict(self):
        cfg = SimpleCfg('hello', 99)
        d = cfg.to_dict()
        assert d['name'] == 'hello'
        assert d['value'] == 99

    def test_to_yaml_string(self):
        cfg = SimpleCfg('hello', 99)
        s = cfg.to_yaml_string()
        assert 'SimpleCfg' in s
        assert 'hello' in s

    def test_from_yaml_string(self):
        cfg = SimpleCfg('roundtrip', 77)
        s = cfg.to_yaml_string()
        cfg2 = Configuration.from_yaml_string(s)
        assert cfg2.name == 'roundtrip'
        assert cfg2.value == 77

    def test_to_string_from_string(self):
        cfg = SimpleCfg('test', 42)
        s = cfg.to_string()
        cfg2 = Configuration.from_string(s)
        assert cfg2.name == 'test'

    def test_to_stream_from_stream(self):
        cfg = SimpleCfg('stream', 10)
        sio = StringIO()
        cfg.to_stream(sio)
        sio.seek(0)
        cfg2 = Configuration.from_stream(sio)
        assert cfg2.name == 'stream'

    def test_to_file_from_file(self, setup_teardown):
        cfg = SimpleCfg('file_test', 55)
        filepath = os.path.join(TEST_DIR, 'test_cfg_extra')
        cfg.to_file(filepath)
        cfg2 = Configuration.from_file(filepath)
        assert cfg2.name == 'file_test'
        assert cfg2.value == 55

    def test_nested_roundtrip(self):
        inner = SimpleCfg('inner', 1)
        outer = NestedCfg(inner=inner, label='outer')
        s = outer.to_yaml_string()
        result = Configuration.from_yaml_string(s)
        assert result.label == 'outer'
        assert result.inner.name == 'inner'

    def test_repr(self):
        cfg = SimpleCfg('repr_test', 100)
        r = repr(cfg)
        assert 'SimpleCfg' in r

    def test_str(self):
        cfg = SimpleCfg('str_test', 200)
        s = str(cfg)
        assert 'SimpleCfg' in s


class TestEmptyObject:
    def test_create(self):
        eo = EmptyObject()
        assert isinstance(eo, Configuration)


class TestHelperFunctions:
    def test_to_yaml_string_dict(self):
        d = {'key': 'value', 'num': 42}
        s = to_yaml_string(d)
        assert 'key' in s

    def test_to_yaml_string_list(self):
        lst = [1, 2, 3]
        s = to_yaml_string(lst)
        assert '1' in s

    def test_from_yaml_string_dict(self):
        s = '{"key": "value", "num": 42}'
        result = from_yaml_string(s)
        assert result['key'] == 'value'

    def test_roundtrip_tuple(self):
        t = (1, 'hello', 3.14)
        s = to_yaml_string(t)
        result = from_yaml_string(s)
        assert len(result) == 3

    def test_get_cfg_dir(self, setup_teardown):
        d = Configuration.get_cfg_dir()
        assert d is not None

    def test_get_data_dir(self, setup_teardown):
        d = Configuration.get_data_dir()
        assert d is not None

    def test_get_cfg_dir_when_root_already_has_cfg_path(self):
        """get_cfg_dir returns root unchanged when it already ends with CFG_PATH (line 80-81)."""
        original = os.environ.get(Configuration.ROOT_VARIABLE_NAME)
        try:
            # Set root to a path that already ends with the CFG_PATH component
            fake_root = '/tmp/fakeat/' + Configuration.CFG_PATH
            os.environ[Configuration.ROOT_VARIABLE_NAME] = fake_root
            result = Configuration.get_cfg_dir()
            assert result == fake_root
            assert result.endswith(Configuration.CFG_PATH)
        finally:
            if original is None:
                del os.environ[Configuration.ROOT_VARIABLE_NAME]
            else:
                os.environ[Configuration.ROOT_VARIABLE_NAME] = original


class TestInitializableConfig:
    def test_initialize_raises_not_implemented(self):
        ic = InitializableConfig()
        with pytest.raises(NotImplementedError):
            ic.initialize()

    def test_initialize_with_args_raises_not_implemented(self):
        ic = InitializableConfig()
        with pytest.raises(NotImplementedError):
            ic.initialize('some_name', count=3)

    def test_is_configuration_subclass(self):
        assert issubclass(InitializableConfig, Configuration)

    def test_instance_is_configuration(self):
        ic = InitializableConfig()
        assert isinstance(ic, Configuration)


class TestEmptyObjectExtended:
    def test_to_dict_empty(self):
        eo = EmptyObject()
        assert eo.to_dict() == {}

    def test_json_roundtrip(self):
        eo = EmptyObject()
        s = eo.to_yaml_string()
        assert 'EmptyObject' in s
        result = Configuration.from_yaml_string(s)
        assert isinstance(result, EmptyObject)

    def test_repr_contains_classname(self):
        eo = EmptyObject()
        assert 'EmptyObject' in repr(eo)
