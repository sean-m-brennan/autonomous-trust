import os
import sys
import logging
from importlib import import_module
from queue import Empty
from collections.abc import Mapping

from aenum import IntEnum
from ruamel.yaml import YAML

from .configuration import Configuration

yaml = YAML(typ='safe')


class ProcessTracker(Mapping):
    default_filename = 'subsystems.yaml'

    def __init__(self):
        self._classes = []
        self._registry = dict({})

    @property
    def classes(self):
        return {k: v for k, v in self._classes}

    def register_subsystem(self, cfg_name, class_spec):
        self._classes.append((cfg_name, class_spec))
        module_name, class_name = class_spec.rsplit('.', 1)
        module = sys.modules[module_name]
        try:
            cls = getattr(module, class_name)
        except KeyError:  # module_name not imported yet
            pkg_name, mod_name = module_name.rsplit('.', 1)
            module = import_module(mod_name, pkg_name)
            cls = getattr(module, class_name)
        self._registry[cfg_name] = cls  # given cfg from CfgIds, yield proc

    def _validate_path(self, path):
        if path is None or path == '':
            path = os.path.join(Configuration.get_cfg_dir(), self.default_filename)
        if os.path.isdir(path):
            path = os.path.join(path, self.default_filename)
        return path

    def to_file(self, filename=None):
        with open(self._validate_path(filename), 'w') as spec:
            yaml.dump(self.classes, spec)

    def from_file(self, filename=None):
        with open(self._validate_path(filename), 'r') as spec:
            name_dict = yaml.load(spec)
            for cfg, proc in name_dict.items():
                self.register_subsystem(cfg, proc)

    def __getitem__(self, key):
        return self._registry[key]

    def __len__(self):
        return len(self._registry)

    def __iter__(self):
        return iter(self._registry)


SUBSYSTEMS = ProcessTracker()


class LogLevel(IntEnum):
    CRITICAL = logging.CRITICAL
    ERROR = logging.ERROR
    WARNING = logging.WARNING
    INFO = logging.INFO
    DEBUG = logging.DEBUG
    VERBOSE = logging.DEBUG - 1


class ProcMeta(type):
    def __new__(mcs, name, bases, namespace, **kwargs):
        return super().__new__(mcs, name, bases, namespace)

    def __init__(cls, name, bases, namespace,
                 proc_name='unknown', description='unknown', cfg_name=None):
        super().__init__(name, bases, namespace)
        cls.name = proc_name
        cls.description = description
        cls.cfg_name = cfg_name
        if cfg_name is None:
            cls.cfg_name = proc_name


class Process(metaclass=ProcMeta):
    key = 'processes'
    output_timeout = 1
    sig_quit = 'quit'
    cadence = 0.1
    exit_timeout = 30

    def __init__(self, configurations, dependencies=None, log_level=LogLevel.INFO):
        self.configs = configurations
        self.dependencies = dependencies
        if dependencies is None:
            self.dependencies = []
        for dep in self.dependencies:
            if dep not in map(lambda x: x.name, configurations['processes']):
                raise RuntimeError('Unmet dependency for %s: %s' % (self.name, dep))
        self.log_level = log_level
        self.logger = logging.getLogger(self.__class__.__name__)

    def __getstate__(self):
        state = self.__dict__.copy()
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

    def log(self, level, msg):
        self.logger.log(level, msg)

    def verbose(self, msg):
        self.log(LogLevel.VERBOSE, msg)

    def debug(self, msg):
        self.log(LogLevel.DEBUG, msg)

    def info(self, msg):
        self.log(LogLevel.INFO, msg)

    def warning(self, msg):
        self.log(LogLevel.WARNING, msg)

    def error(self, msg):
        self.log(LogLevel.ERROR, msg)

    def critical(self, msg):
        self.log(LogLevel.CRITICAL, msg)

    def keep_running(self, signal):
        running = True
        try:
            sig = signal.get_nowait()
            self.warning('Quit')
            if sig == self.sig_quit:
                running = False
        except Empty:
            pass
        return running

    def listen(self, queues, output, signal):
        raise NotImplementedError

    def speak(self, queues, output, signal):
        raise NotImplementedError
