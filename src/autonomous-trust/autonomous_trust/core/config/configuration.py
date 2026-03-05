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

import io
import os
import sys
import json
import base64
from io import StringIO
from datetime import datetime, timedelta
from dateutil import parser
from uuid import UUID
from decimal import Decimal, getcontext
from enum import Enum

import ruamel.yaml
from google.protobuf.json_format import MessageToJson, Parse as ParseJson
from nacl.signing import SignedMessage

from ..util import ClassEnumMeta

yaml = ruamel.yaml.YAML(typ='safe')
yaml.default_flow_style = False


class SerializeMode(Enum):
    PROTO = 1
    YAML = 2
    PJSON = 3


class WireFormat(Enum):
    BINARY = 1
    JSON = 2


def to_yaml_string(item):
    sio = StringIO()
    if Configuration.mode == SerializeMode.YAML:
        yaml.dump(item, sio)
    else:
        # assumes Message type
        sio.write(item.SerializeToString())
    return sio.getvalue()


def from_yaml_string(string):
    sio = StringIO(string)
    if Configuration.mode == SerializeMode.YAML:
        return yaml.load(sio)
    #else: #FIXME remove both?



class Configuration(object):
    ROOT_VARIABLE_NAME = 'AUTONOMOUS_TRUST_ROOT'
    CFG_PATH = os.path.join('etc', 'at')
    DATA_PATH = os.path.join('var', 'at')
    YAML_PREFIX = u'!Cfg'
    # FIXME from config
    #mode = SerializeMode.PROTO
    mode = SerializeMode.YAML
    wire_format = WireFormat.JSON
    file_ext = '.cfg.json'
    log_stdout = hex(sum([ord(x) for x in 'stdout']))
    _msg_class = None

    def __init__(self, msg_class=None):
        if msg_class:
            self.message = msg_class()

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
        if self.mode == SerializeMode.YAML:
            yaml.dump(self, stream)
        else:
            self.sync_to_message()
            if self.wire_format == WireFormat.BINARY:
                stream.write(self.message.SerializeToString())
            else:
                stream.write(MessageToJson(self.message))

    def to_yaml_string(self):
        return str(self)

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

    def to_file(self, filepath):
        with open(filepath, 'w') as cfg:
            json.dump(self, cfg, cls=ConfigJSONEncoder, indent=2)

    @staticmethod
    def yaml_constructor(loader, tag_suffix, node):
        modulename, classname = tag_suffix[1:].rsplit('.', 1)
        cls = getattr(sys.modules[modulename], classname)
        return cls(**loader.construct_mapping(node, deep=True))

    def sync_from_message(self):
        raise NotImplementedError

    @classmethod
    def from_stream(cls, stream):
        if cls.mode == SerializeMode.YAML:
            return yaml.load(stream)
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
    def from_yaml_string(cls, string):
        return cls.from_string(string)

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


class ConfigJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Configuration):
            type_name = obj.__class__.__module__ + '.' + obj.__class__.__name__
            d = {'__type__': type_name}
            d.update(obj.to_dict())
            return d
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
    if '.' in type_name:
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
