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

import io
import os
import sys
import json
import base64
import tempfile
from contextlib import contextmanager
from io import StringIO
from datetime import datetime, timedelta
from dateutil import parser
from uuid import UUID
from decimal import Decimal, getcontext
from enum import Enum

from google.protobuf.json_format import MessageToJson, Parse as ParseJson
from nacl.signing import SignedMessage

from ..util import ClassEnumMeta


_ALLOWED_CONFIG_TYPES: set = set()
_ALLOWED_ENUM_TYPES: set = set()


@contextmanager
def atomic_write(filepath, mode='w'):
    """Write a file atomically: serialize into a temp file in the same
    directory, then os.replace() it onto the target.

    A plain open(filepath, 'w') truncates the file to empty *before* the new
    contents are written, so a concurrent reader (e.g.
    discover.load_configs -> Configuration.from_file -> json.load, often in
    another process) can catch the empty/partial window and raise
    "JSONDecodeError: Expecting value: line 1 column 1". os.replace is atomic
    on POSIX, so readers always see either the previous complete file or the
    new complete file. The temp name does not end in Configuration.file_ext,
    so discover.load_configs' os.listdir filter ignores it even if it races
    the rename.

    Use as a drop-in for open(path, 'w') when writing config snapshots:

        with atomic_write(path) as f:
            json.dump(obj, f, ...)
    """
    directory = os.path.dirname(filepath) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(filepath) + '.',
                               suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, mode) as f:
            yield f
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, filepath)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def register_config_type(cls):
    type_name = cls.__module__ + '.' + cls.__qualname__
    _ALLOWED_CONFIG_TYPES.add(type_name)


def register_enum_type(cls):
    """Register an Enum type as allowed for deserialization."""
    type_name = cls.__module__ + '.' + cls.__qualname__
    _ALLOWED_ENUM_TYPES.add(type_name)
    return cls


@register_enum_type
class SerializeMode(Enum):
    PROTO = 1
    JSON = 2
    PJSON = 3


@register_enum_type
class WireFormat(Enum):
    BINARY = 1
    JSON = 2


class NetWireFormat(object, metaclass=ClassEnumMeta):
    """Which envelope encoding an inter-host network message rides in
    (doc/architecture/network-wire-format.md). Mirrors C's ``net_wire_format_t``.

    Distinct from :class:`WireFormat` above, which selects how a
    *Configuration* serializes itself (on disk, and as a message *payload*).
    This selects how the *envelope around* that payload is encoded, and the two
    are independent: a proto-mode cohort still carries whatever payload form
    ``AT_SERIALIZE_MODE`` asks for.

    A node does not choose this per message or per peer -- it is a property of
    the GROUP (``Group.wire_format``), and everything outside a group
    (discovery, pre-admission) is :attr:`json` unconditionally. Detecting a
    peer's format is deliberately not implemented; see
    doc/architecture/network-wire-format.md.

    Values are the strings that ride the canonical group wire form, so C's
    ``group_to_json`` and this agree without a mapping table.

    Lives here rather than in the network package because ``identity/group.py``
    carries the value and must reach it without importing ``core.network``
    (which imports identity -- a cycle). ``config`` is already below both.
    """
    json = 'json'
    proto = 'proto'


#: The one-byte format marker that prefixes every packed protobuf envelope
#: (``network/net_message.proto``). A JSON envelope always begins ``{``
#: (0x7B), so a receiver can refuse a frame in a format it does not speak
#: WITHOUT running the other parser over peer-supplied bytes -- which is the
#: point, given that format detection is a deliberate non-goal
#: (doc/architecture/network-wire-format.md). It also
#: serves as the envelope version slot: an incompatible future proto envelope
#: takes 0xAC and is distinguishable rather than guessed. Must match C's
#: ``NET_WIRE_PROTO_MAGIC`` (network/net_message.h).
NET_WIRE_PROTO_MAGIC = 0xAB


class Configuration(object):
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        register_config_type(cls)

    ROOT_VARIABLE_NAME = 'AUTONOMOUS_TRUST_ROOT'
    CFG_PATH = os.path.join('etc', 'at')
    DATA_PATH = os.path.join('var', 'at')
    mode = SerializeMode(int(os.environ.get('AT_SERIALIZE_MODE', SerializeMode.JSON.value)))
    wire_format = WireFormat(int(os.environ.get('AT_WIRE_FORMAT', WireFormat.JSON.value)))
    _file_ext_map = {SerializeMode.JSON: '.cfg.json', SerializeMode.PJSON: '.cfg.json',
                     SerializeMode.PROTO: '.cfg.pb'}
    file_ext = _file_ext_map.get(mode, '.cfg.json')
    log_stdout = hex(sum([ord(x) for x in 'stdout']))
    # Companion destination sentinel to log_stdout. Needed because
    # `silent=True` suppresses the stdout log handler (it is what keeps the
    # console clean), so `silent=True` + `logfile=log_stdout` asks for logs on a
    # stream that is being suppressed -- AT resolves that by discarding them, and
    # log_level goes inert. Callers that want no console chatter but DO want logs
    # (the diag harness, any operator wanting a debug trace out of a quiet node)
    # name this instead and get a stderr handler regardless of `silent`.
    log_stderr = hex(sum([ord(x) for x in 'stderr']))
    _msg_class = None

    def __init__(self, msg_class=None):
        mc = msg_class or self.__class__._msg_class
        if mc:
            self.message = mc()

    @classmethod
    def get_cfg_dir(cls):
        root = os.environ.get(cls.ROOT_VARIABLE_NAME, os.path.abspath(os.sep))
        if not root.endswith(cls.CFG_PATH):
            return os.path.join(root, cls.CFG_PATH)
        return root

    @classmethod
    def get_data_dir(cls):
        return cls.get_cfg_dir().removesuffix(cls.CFG_PATH) + cls.DATA_PATH

    def __repr__(self):
        attrs = []
        for k, v in sorted(self.to_dict().items()):
            if isinstance(v, str):
                attrs.append(k + '=' + v)
            else:
                attrs.append(k + '=' + repr(v))
        return '%s(%s)' % (self.__class__.__name__, ', '.join(attrs))

    def to_dict(self):
        d = dict(self.__dict__)
        if 'message' in d:
            del d['message']
        return d

    def sync_to_message(self):
        raise NotImplementedError

    def to_stream(self, stream):
        if self.mode == SerializeMode.JSON:
            stream.write(json.dumps(self, cls=ConfigJSONEncoder))
        else:
            self.sync_to_message()
            if self.wire_format == WireFormat.BINARY:
                stream.write(self.message.SerializeToString())
            else:
                stream.write(MessageToJson(self.message))

    def to_json_string(self):
        return str(self)

    # Backward-compat alias
    to_yaml_string = to_json_string

    def to_string(self):
        if self.mode == SerializeMode.PROTO and self.wire_format == WireFormat.BINARY:
            buf = io.BytesIO()
            self.to_stream(buf)
            return buf.getvalue()
        return str(self)

    def __str__(self):
        sio = StringIO()
        self.to_stream(sio)
        return sio.getvalue()


    def to_wire_bytes(self):
        if hasattr(self, 'message') and self._msg_class is not None:
            self.sync_to_message()
            return self.message.SerializeToString()
        return self.to_yaml_string().encode('utf-8')

    @classmethod
    def from_wire_bytes(cls, data):
        if cls._msg_class is not None:
            obj = object.__new__(cls)
            obj.message = cls._msg_class()
            obj.message.ParseFromString(data)
            obj.sync_from_message()
            return obj
        return cls.from_string(data.decode('utf-8'))

    def to_file(self, filepath):
        # Atomic write (see atomic_write): a plain open(filepath, 'w') would
        # expose an empty/partial file to a concurrent load_configs reader.
        with atomic_write(filepath) as cfg:
            json.dump(self, cfg, cls=ConfigJSONEncoder, indent=2)

    def sync_from_message(self):
        raise NotImplementedError

    @classmethod
    def from_stream(cls, stream):
        if cls.mode == SerializeMode.JSON:
            data = stream.read()
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            return json.loads(data, object_hook=config_json_decoder)
        else:
            obj = cls.__new__(cls)
            msg_class = cls._msg_class
            if msg_class is None:
                raise ValueError('No _msg_class defined for %s' % cls.__name__)
            obj.message = msg_class()
            data = stream.read()
            if cls.wire_format == WireFormat.BINARY:
                obj.message.ParseFromString(data)
            else:
                if isinstance(data, bytes):
                    data = data.decode('utf-8')
                ParseJson(data, obj.message)
            obj.sync_from_message()
            return obj

    @classmethod
    def from_json_string(cls, string):
        return cls.from_string(string)

    # Backward-compat alias
    from_yaml_string = from_json_string

    @classmethod
    def from_string(cls, string):
        if cls.mode == SerializeMode.PROTO and cls.wire_format == WireFormat.BINARY:
            buf = io.BytesIO(string)
            return cls.from_stream(buf)
        if isinstance(string, bytes):
            string = string.decode('utf-8')
        sio = StringIO(string)
        return cls.from_stream(sio)

    @classmethod
    def from_file(cls, filepath):
        with open(filepath, 'r') as cfg:
            return json.load(cfg, object_hook=config_json_decoder)


register_config_type(Configuration)


class InitializableConfig(Configuration):
    def initialize(self, *args, **kwargs):
        raise NotImplementedError


class EmptyObject(Configuration):
    pass


class ConfigJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Configuration):
            type_name = obj.__class__.__module__ + '.' + obj.__class__.__name__
            d = {'__type__': type_name}
            d.update(obj.to_dict())
            return d
        if isinstance(obj, Enum):
            type_name = 'Enumcfg:' + obj.__class__.__module__ + '.' + obj.__class__.__name__
            return {'__type__': type_name, '__value__': obj.name}
        if isinstance(obj, datetime):
            return {'__type__': 'datetime', '__value__': obj.isoformat('T')}
        if isinstance(obj, timedelta):
            return {'__type__': 'timedelta', '__value__': obj.total_seconds()}
        if isinstance(obj, UUID):
            return {'__type__': 'UUID', '__value__': str(obj)}
        if isinstance(obj, Decimal):
            return {'__type__': 'Decimal', '__value__': str(obj)}
        if isinstance(obj, bytes):
            return {'__type__': 'bytes', '__value__': base64.b64encode(obj).decode('ascii')}
        if isinstance(obj, SignedMessage):
            return {'__type__': 'signedmessage', '__value__': {
                'message': base64.b64encode(obj.message).decode('ascii'),
                'signature': base64.b64encode(obj.signature).decode('ascii'),
            }}
        return super().default(obj)


def config_json_decoder(dct):
    if '__type__' not in dct:
        return dct
    type_name = dct['__type__']
    if type_name == 'datetime':
        return parser.parse(dct['__value__'])
    if type_name == 'timedelta':
        return timedelta(seconds=float(dct['__value__']))
    if type_name == 'UUID':
        return UUID(dct['__value__'])
    if type_name == 'Decimal':
        value = dct['__value__']
        getcontext().prec = len(value)
        return Decimal(value)
    if type_name == 'bytes':
        return base64.b64decode(dct['__value__'])
    if type_name == 'signedmessage':
        val = dct['__value__']
        sig = base64.b64decode(val['signature'])
        msg = base64.b64decode(val['message'])
        return SignedMessage._from_parts(signature=sig, message=msg, combined=sig + msg)
    if type_name.startswith('Enumcfg:'):
        enum_path = type_name[len('Enumcfg:'):]
        if enum_path not in _ALLOWED_ENUM_TYPES:
            raise ValueError(f"Enum type '{enum_path}' not in allowed enum types")
        module_name, class_name = enum_path.rsplit('.', 1)
        try:
            module = sys.modules[module_name]
        except KeyError:
            from importlib import import_module
            module = import_module(module_name)
        cls = getattr(module, class_name)
        return cls[dct['__value__']]
    if '.' in type_name:
        if type_name not in _ALLOWED_CONFIG_TYPES:
            raise ValueError(f"Type '{type_name}' not in allowed configuration types")
        module_name, class_name = type_name.rsplit('.', 1)
        try:
            module = sys.modules[module_name]
        except KeyError:
            from importlib import import_module
            module = import_module(module_name)
        cls = getattr(module, class_name)
        kwargs = {k: v for k, v in dct.items() if k != '__type__'}
        return cls(**kwargs)
    return dct


# Module-level serialization functions
def to_json_string(item):
    return json.dumps(item, cls=ConfigJSONEncoder)


def from_json_string(string):
    return json.loads(string, object_hook=config_json_decoder)


# Backward-compat aliases
to_yaml_string = to_json_string
from_yaml_string = from_json_string
