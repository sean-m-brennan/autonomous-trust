import os
import queue
import sys
import logging
import time
from importlib import import_module
from io import StringIO
from collections.abc import Mapping
from collections import OrderedDict

from enum import IntEnum

from ruamel.yaml import YAML

from .config import Configuration
from .system import cadence, queue_cadence, now

yaml = YAML(typ='safe')


class ProcessTracker(Mapping):
    default_filename = 'subsystems.yaml'

    def __init__(self):
        self._classes = []
        self._registry = OrderedDict()
        self._order = []

    @property
    def classes(self):
        d = OrderedDict()
        for k, v in self._classes:
            d[k] = v
        return d

    @property
    def ordered(self):
        return self._order

    @property
    def names(self):
        return self._registry

    def register_subsystem(self, cfg_name, class_spec):
        self._classes.append((cfg_name, class_spec))
        module_name, class_name = class_spec.rsplit('.', 1)
        try:
            module = sys.modules[module_name]
            cls = getattr(module, class_name)
        except KeyError:  # module_name not imported yet
            module = import_module(module_name)
            cls = getattr(module, class_name)
        self._registry[cfg_name] = cls  # given cfg from CfgIds, yield proc
        if cls not in self._order:
            self._order.append(cls)

    def _validate_path(self, path):
        if path is None or path == '':
            path = os.path.join(Configuration.get_cfg_dir(), self.default_filename)
        if os.path.isdir(path):
            path = os.path.join(path, self.default_filename)
        return path

    def to_yaml_string(self):
        sio = StringIO()
        yaml.dump(self.classes, sio)
        return sio.getvalue()

    def to_file(self, filename=None):
        with open(self._validate_path(filename), 'w') as spec:
            yaml.dump(self.classes, spec)

    def from_yaml_string(self, yml):
        name_dict = yaml.load(yml)
        for cfg, proc in name_dict.items():
            self.register_subsystem(cfg, proc)

    def from_file(self, filename=None):
        with open(self._validate_path(filename), 'r') as spec:
            self.from_yaml_string(spec)

    def __getitem__(self, key):
        return self._registry[key]

    def __len__(self):
        return len(self._registry)

    def __iter__(self):
        return iter(self._registry)


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
    level = 'log-level'
    output_timeout = 1
    sig_quit = 'quit'
    cadence = cadence
    q_cadence = queue_cadence
    exit_timeout = 5

    def __init__(self, configurations, subsystems, log_queue, dependencies=None,
                 log_level=LogLevel.INFO, suppress_log=False):
        self.configs = configurations
        self.subsystems = subsystems
        self.log_queue = log_queue
        self.dependencies = dependencies
        if dependencies is None:
            self.dependencies = []
        for dep in self.dependencies:
            if dep not in map(lambda x: x.name, configurations['processes']):
                raise RuntimeError('Unmet dependency for %s: %s' % (self.name, dep))
        self.log_level = log_level
        if Process.level in self.configs:
            self.log_level = self.configs[Process.level]
        self.logger = ProcessLogger(self.__class__.__name__, log_queue, suppress_log)
        self.loop_start = None
        self.mocks = []  # list of Mockery objs
        self.package_hash = None

    def __getstate__(self):
        state = self.__dict__.copy()
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

    def keep_running(self, signal):
        running = True
        try:
            sig = signal.get_nowait()
            self.logger.debug('Quit %s' % self.__class__.__name__)
            if sig == self.sig_quit:
                running = False
        except queue.Empty:
            pass
        self.loop_start = now()
        return running

    def sleep_until(self, how_long):
        delta = how_long - (now() - self.loop_start).total_seconds()
        if delta > 0:
            time.sleep(delta)

    def update(self, msg, queues):
        for name, q in queues.items():
            if name != self.name:
                q.put(msg, block=True, timeout=self.q_cadence)

    def process(self, queues, signal):
        raise NotImplementedError


class ProcessLogger(object):
    def __init__(self, name, log_q, suppress=False):
        self.name = name
        self.log_queue = log_q
        self.logger = logging.getLogger(name)
        self.suppress = suppress

    def log(self, level, msg):
        if self.suppress:
            return
        if self.log_queue is not None:
            self.log_queue.put((level, self.name, msg), block=True, timeout=0.001)
        else:
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


class Mockery(object):  # FIXME move to testing
    def __init__(self, name, obj=None, value=None):
        self.name = name
        self.obj = obj
        self.value = value
        # FIXME assert

    def patch(self, mocker):
        if self.obj is None:
            mocker.patch(self.name)  # always relative to SUBSYSTEMS
        else:
            if self.value is None:
                mocker.patch.object(self.obj, self.name)
            else:
                mocker.patch.object(self.obj, self.name, return_value=self.value)

    def assertion(self):
        pass  # FIXME
