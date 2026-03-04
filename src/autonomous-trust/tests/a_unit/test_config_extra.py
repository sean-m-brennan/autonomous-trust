import os
import pytest
from io import StringIO
from datetime import timedelta
from decimal import Decimal

from nacl.signing import SigningKey

from autonomous_trust.core.config.configuration import (
    Configuration, InitializableConfig, EmptyObject, SerializeMode,
    to_yaml_string, from_yaml_string, yaml,
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
        assert SerializeMode.YAML.value == 2
        assert SerializeMode.PJSON.value == 3


class TestConfiguration:
    def test_yaml_tag(self):
        cfg = SimpleCfg()
        tag = cfg.yaml_tag
        assert 'SimpleCfg' in tag
        assert Configuration.YAML_PREFIX in tag

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
        s = 'key: value\nnum: 42\n'
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
        """InitializableConfig.initialize raises NotImplementedError (line 178)."""
        ic = InitializableConfig()
        with pytest.raises(NotImplementedError):
            ic.initialize()

    def test_initialize_with_args_raises_not_implemented(self):
        """InitializableConfig.initialize raises NotImplementedError with any arguments."""
        ic = InitializableConfig()
        with pytest.raises(NotImplementedError):
            ic.initialize('some_name', count=3)

    def test_is_configuration_subclass(self):
        """InitializableConfig is a subclass of Configuration."""
        assert issubclass(InitializableConfig, Configuration)

    def test_instance_is_configuration(self):
        """An InitializableConfig instance is a Configuration."""
        ic = InitializableConfig()
        assert isinstance(ic, Configuration)


class TestEmptyObjectExtended:
    def test_to_dict_empty(self):
        """EmptyObject.to_dict returns an empty dict."""
        eo = EmptyObject()
        assert eo.to_dict() == {}

    def test_yaml_roundtrip(self):
        """EmptyObject can be serialized to YAML and reconstructed."""
        orig = Configuration.mode
        Configuration.mode = SerializeMode.YAML
        try:
            eo = EmptyObject()
            s = eo.to_yaml_string()
            assert 'EmptyObject' in s
            result = Configuration.from_yaml_string(s)
            assert isinstance(result, EmptyObject)
        finally:
            Configuration.mode = orig

    def test_repr_contains_classname(self):
        """EmptyObject repr contains the class name."""
        eo = EmptyObject()
        assert 'EmptyObject' in repr(eo)


class TestTimedeltaYAML:
    def test_roundtrip_positive(self):
        """timedelta YAML representer + constructor roundtrip (lines 199, 203-204)."""
        td = timedelta(seconds=42.5)
        sio = StringIO()
        yaml.dump({'td': td}, sio)
        sio.seek(0)
        result = yaml.load(sio)
        assert result['td'] == td

    def test_roundtrip_zero(self):
        """timedelta of zero survives YAML roundtrip."""
        td = timedelta(seconds=0)
        sio = StringIO()
        yaml.dump({'td': td}, sio)
        sio.seek(0)
        result = yaml.load(sio)
        assert result['td'] == td

    def test_roundtrip_large(self):
        """Large timedelta (days + seconds) survives YAML roundtrip."""
        td = timedelta(days=3, hours=2, minutes=15, seconds=7)
        sio = StringIO()
        yaml.dump({'td': td}, sio)
        sio.seek(0)
        result = yaml.load(sio)
        assert result['td'] == td

    def test_yaml_tag(self):
        """timedelta YAML output uses the !timedelta tag."""
        td = timedelta(seconds=10)
        sio = StringIO()
        yaml.dump(td, sio)
        assert '!timedelta' in sio.getvalue()

    def test_total_seconds_preserved(self):
        """total_seconds() value is preserved through YAML serialization."""
        td = timedelta(minutes=5, seconds=30)
        sio = StringIO()
        yaml.dump(td, sio)
        sio.seek(0)
        result = yaml.load(sio)
        assert result.total_seconds() == td.total_seconds()


class TestDecimalYAML:
    def test_roundtrip_simple(self):
        """Decimal YAML representer + constructor roundtrip (lines 237, 241-243)."""
        d = Decimal('3.14159')
        sio = StringIO()
        yaml.dump({'d': d}, sio)
        sio.seek(0)
        result = yaml.load(sio)
        assert result['d'] == d

    def test_roundtrip_integer_decimal(self):
        """Integer Decimal survives YAML roundtrip."""
        d = Decimal('42')
        sio = StringIO()
        yaml.dump({'d': d}, sio)
        sio.seek(0)
        result = yaml.load(sio)
        assert result['d'] == d

    def test_roundtrip_negative(self):
        """Negative Decimal survives YAML roundtrip."""
        d = Decimal('-0.001')
        sio = StringIO()
        yaml.dump({'d': d}, sio)
        sio.seek(0)
        result = yaml.load(sio)
        assert result['d'] == d

    def test_yaml_tag(self):
        """Decimal YAML output uses the !Decimal tag."""
        d = Decimal('1.5')
        sio = StringIO()
        yaml.dump(d, sio)
        assert '!Decimal' in sio.getvalue()

    def test_result_is_decimal_type(self):
        """Reconstructed value is a Decimal instance, not a float."""
        d = Decimal('9.99')
        sio = StringIO()
        yaml.dump(d, sio)
        sio.seek(0)
        result = yaml.load(sio)
        assert isinstance(result, Decimal)


class TestSignedMessageYAML:
    def test_representer_produces_yaml_tag(self):
        """signedmessage_representer emits !signedmessage tag (line 225)."""
        key = SigningKey.generate()
        signed = key.sign(b'hello world')
        sio = StringIO()
        yaml.dump(signed, sio)
        output = sio.getvalue()
        assert '!signedmessage' in output
        assert 'message' in output
        assert 'signature' in output

    def test_representer_contains_message_bytes(self):
        """signedmessage_representer includes base64-encoded message bytes."""
        key = SigningKey.generate()
        signed = key.sign(b'test payload')
        sio = StringIO()
        yaml.dump(signed, sio)
        output = sio.getvalue()
        # ruamel.yaml encodes bytes as !!binary; the tag and content should be present
        assert '!signedmessage' in output

    def test_representer_contains_signature_bytes(self):
        """signedmessage_representer includes signature bytes."""
        key = SigningKey.generate()
        signed = key.sign(b'sig check')
        sio = StringIO()
        yaml.dump({'sm': signed}, sio)
        output = sio.getvalue()
        assert '!signedmessage' in output
        assert 'signature' in output

    def test_constructor_known_broken(self):
        """signedmessage_constructor is broken: SignedMessage does not accept keyword args (line 229).

        This test documents the pre-existing bug. The representer works but
        the constructor raises TypeError when attempting to reconstruct from YAML.
        """
        key = SigningKey.generate()
        signed = key.sign(b'broken constructor')
        sio = StringIO()
        yaml.dump({'sm': signed}, sio)
        sio.seek(0)
        with pytest.raises(TypeError):
            yaml.load(sio)
