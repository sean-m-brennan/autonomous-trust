import sys
from enum import Enum

from autonomous_trust.core.config.configuration import yaml


TAG_PREFIX = '!Enumcfg'  # distinct from Configuration prefix


class SerializableEnum(Enum):
    def yaml_tag(self):
        return '%s:%s.%s' % (TAG_PREFIX, self.__class__.__module__, self.__class__.__name__)

    @staticmethod
    def yaml_representer(dumper, data):
        data_str = str(data)
        dot = data_str.find('.') + 1
        return dumper.represent_scalar(data.yaml_tag(), data_str[dot:])

    @staticmethod
    def yaml_constructor(_, tag_suffix, node):
        modulename, classname = tag_suffix[1:].rsplit('.', 1)
        cls = getattr(sys.modules[modulename], classname)
        return cls.__dict__[node.value]


yaml.representer.add_multi_representer(SerializableEnum, SerializableEnum.yaml_representer),
yaml.constructor.add_multi_constructor(TAG_PREFIX, SerializableEnum.yaml_constructor)
