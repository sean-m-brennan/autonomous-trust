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
    mode = SerializeMode.PROTO
    file_ext = '.cfg.yaml' if mode == SerializeMode.YAML else '.cfg.pb'  # FIXME protobuf file_ext
    log_stdout = hex(sum([ord(x) for x in 'stdout']))

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
            if not self.message.IsInitialized:
                self.sync_to_message()
            stream.write(self.message.SerializeToString())

    def to_string(self):
        return str(self)

    def __str__(self):
        sio = StringIO()
        self.to_stream(sio)
        return sio.getvalue()

    def to_file(self, filepath):
        mode = 'w'
        if self.mode == SerializeMode.PROTO:
            mode = 'wb'
        with open(filepath, mode) as cfg:
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
        if cls.mode == SerializeMode.YAML:
            return yaml.load(stream)
        else:
            obj = cls()
            obj.message.ParseFromString(stream.read())
            obj.sync_from_message()

    @classmethod
    def from_yaml_string(cls, string):
        return cls.from_string(string)

    @classmethod
    def from_string(cls, string):
        sio = StringIO(string)
        return cls.from_stream(sio)

    @classmethod
    def from_file(cls, filepath):  # FIXME Configuration.from_file(cfg_file), class is unknown
        with open(filepath, 'rb') as cfg:
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
