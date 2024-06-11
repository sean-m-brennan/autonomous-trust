# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import sys
import threading
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


lock = threading.Lock()


class Singleton(type):
    """Thread-safe singleton, used as a metaclass"""
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            with lock:
                if cls not in cls._instances:
                    cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
