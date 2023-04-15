import os
import sys
from ruamel.yaml import YAML

yaml = YAML(typ='safe')
yaml.default_flow_style = False


class Configuration(object):
    VARIABLE_NAME = 'AUTONOMOUS_TRUST_CONFIG'
    PATH_DEFAULT = os.path.join(os.path.abspath(os.sep), 'etc', 'at')
    YAML_PREFIX = u'!Cfg'

    @property
    def yaml_tag(self):
        return '%s:%s.%s' % (Configuration.YAML_PREFIX, self.__class__.__module__, self.__class__.__name__)

    def __repr__(self):
        attrs = []
        for k, v in sorted(vars(self).items()):
            if isinstance(v, str):
                attrs.append(k + '=' + v)
            else:
                attrs.append(k + '=' + repr(v))
        return '%s(%s)' % (self.__class__.__name__, ', '.join(attrs))

    def to_dict(self):
        return dict(self.__dict__)

    @staticmethod
    def yaml_representer(dumper, data):
        return dumper.represent_mapping(data.yaml_tag, data.to_dict())

    def to_stream(self, stream):
        yaml.dump(self, stream)

    def to_file(self, filepath):
        with open(filepath, 'w') as cfg:
            self.to_stream(cfg)

    @staticmethod
    def yaml_constructor(loader, tag_suffix, node):
        modulename, classname = tag_suffix[1:].rsplit('.', 1)
        cls = getattr(sys.modules[modulename], classname)
        return cls(**loader.construct_mapping(node, deep=True))

    @staticmethod
    def from_stream(stream):
        return yaml.load(stream)

    @staticmethod
    def from_file(filepath):
        with open(filepath, 'rb') as cfg:
            return Configuration.from_stream(cfg)


yaml.representer.add_multi_representer(Configuration, Configuration.yaml_representer),
yaml.constructor.add_multi_constructor(Configuration.YAML_PREFIX, Configuration.yaml_constructor)
