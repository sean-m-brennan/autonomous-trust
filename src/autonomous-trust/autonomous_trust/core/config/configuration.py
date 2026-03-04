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

import base64
import os
import sys
from io import StringIO
from datetime import datetime, timedelta
from dateutil import parser
from uuid import UUID
from decimal import Decimal, getcontext
from enum import Enum

import ruamel.yaml
from nacl.signing import SignedMessage

from ..util import ClassEnumMeta

yaml = ruamel.yaml.YAML(typ='safe')
yaml.default_flow_style = False


class SerializeMode(Enum):
    PROTO = 1
    YAML = 2
    PJSON = 3


def to_yaml_string(item):
    if Configuration.mode == SerializeMode.PROTO and isinstance(item, Configuration) and hasattr(item, 'message') and item._msg_class is not None:
        return item.to_string()  # uses !PB: prefix
    sio = StringIO()
    yaml.dump(item, sio)
    return sio.getvalue()


def from_yaml_string(string):
    if isinstance(string, str) and string.startswith('!PB:'):
        return Configuration.from_string(string)
    sio = StringIO(string) if isinstance(string, str) else StringIO(string.decode('utf-8'))
    return yaml.load(sio)



class Configuration(object):
    ROOT_VARIABLE_NAME = 'AUTONOMOUS_TRUST_ROOT'
    CFG_PATH = os.path.join('etc', 'at')
    DATA_PATH = os.path.join('var', 'at')
    YAML_PREFIX = u'!Cfg'
    PROTO_PREFIX = '!PB:'
    mode = SerializeMode.PROTO
    file_ext = '.cfg.yaml'  # disk is always YAML regardless of mode
    log_stdout = hex(sum([ord(x) for x in 'stdout']))
    _msg_class = None  # subclasses with protos override this

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

    @property
    def yaml_tag(self):
        return '%s:%s.%s' % (Configuration.YAML_PREFIX, self.__class__.__module__, self.__class__.__name__)

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

    @staticmethod
    def yaml_representer(dumper, data):
        return dumper.represent_mapping(data.yaml_tag, data.to_dict())

    def sync_to_message(self):
        raise NotImplementedError

    def to_stream(self, stream):
        yaml.dump(self, stream)

    def to_yaml_string(self):
        sio = StringIO()
        self.to_stream(sio)
        return sio.getvalue()

    def to_string(self):
        if self.mode == SerializeMode.PROTO and hasattr(self, 'message') and self._msg_class is not None:
            self.sync_to_message()
            class_tag = '%s.%s' % (self.__class__.__module__, self.__class__.__name__)
            return self.PROTO_PREFIX + class_tag + ':' + base64.b64encode(self.message.SerializeToString()).decode('ascii')
        sio = StringIO()
        self.to_stream(sio)
        return sio.getvalue()

    def __str__(self):
        return self.to_string()

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
        with open(filepath, 'w') as cfg:
            self.to_stream(cfg)

    @staticmethod
    def yaml_constructor(loader, tag_suffix, node):
        modulename, classname = tag_suffix[1:].rsplit('.', 1)
        cls = getattr(sys.modules[modulename], classname)
        return cls(**loader.construct_mapping(node, deep=True))

    def sync_from_message(self):
        raise NotImplementedError

    @classmethod
    def from_stream(cls, stream):
        return yaml.load(stream)

    @classmethod
    def from_yaml_string(cls, string):
        sio = StringIO(string)
        return cls.from_stream(sio)

    @classmethod
    def from_string(cls, string):
        if isinstance(string, str) and string.startswith(cls.PROTO_PREFIX):
            rest = string[len(cls.PROTO_PREFIX):]
            if ':' in rest:
                class_tag, b64data = rest.split(':', 1)
                data = base64.b64decode(b64data)
                # If called on base Configuration, resolve the actual class
                if cls is Configuration or cls._msg_class is None:
                    modulename, classname = class_tag.rsplit('.', 1)
                    target_cls = getattr(sys.modules[modulename], classname)
                    return target_cls.from_wire_bytes(data)
                return cls.from_wire_bytes(data)
            else:
                data = base64.b64decode(rest)
                return cls.from_wire_bytes(data)
        sio = StringIO(string)
        return cls.from_stream(sio)

    @classmethod
    def from_file(cls, filepath):
        with open(filepath, 'r') as cfg:
            return cls.from_stream(cfg)


yaml.representer.add_multi_representer(Configuration, Configuration.yaml_representer),
yaml.constructor.add_multi_constructor(Configuration.YAML_PREFIX, Configuration.yaml_constructor)


class InitializableConfig(Configuration):
    def initialize(self, *args, **kwargs):
        raise NotImplementedError


class EmptyObject(Configuration):
    pass


def datetime_representer(dumper, data: datetime):
    return dumper.represent_scalar(u'!datetime', u'%s' % data.isoformat('T'))


def datetime_constructor(loader, node):
    value = loader.construct_scalar(node)
    return parser.parse(value)


yaml.representer.add_representer(datetime, datetime_representer),
yaml.constructor.add_constructor(u'!datetime', datetime_constructor)


def timedelta_representer(dumper, data: timedelta):
    return dumper.represent_scalar(u'!timedelta', u'%s' % data.total_seconds())


def timedelta_constructor(loader, node):
    value = loader.construct_scalar(node)
    return timedelta(seconds=float(value))


yaml.representer.add_representer(timedelta, timedelta_representer),
yaml.constructor.add_constructor(u'!timedelta', timedelta_constructor)


def uuid_representer(dumper, data: UUID):
    return dumper.represent_scalar(u'!UUID', u'%s' % str(data))


def uuid_constructor(loader, node):
    value = loader.construct_scalar(node)
    return UUID(value)


yaml.representer.add_representer(UUID, uuid_representer),
yaml.constructor.add_constructor(u'!UUID', uuid_constructor)


def signedmessage_representer(dumper, data: SignedMessage):
    return dumper.represent_mapping(u'!signedmessage', dict(message=data.message, signature=data.signature))


def signedmessage_constructor(loader, node):
    return SignedMessage(**loader.construct_mapping(node, deep=True))


yaml.representer.add_representer(SignedMessage, signedmessage_representer),
yaml.constructor.add_constructor(u'!signedmessage', signedmessage_constructor)


def decimal_representer(dumper, data: Decimal):
    return dumper.represent_scalar(u'!Decimal', u'%s' % str(data))


def decimal_constructor(loader, node):
    value = loader.construct_scalar(node)
    getcontext().prec = len(value)
    return Decimal(value)


yaml.representer.add_representer(Decimal, decimal_representer),
yaml.constructor.add_constructor(u'!Decimal', decimal_constructor)
