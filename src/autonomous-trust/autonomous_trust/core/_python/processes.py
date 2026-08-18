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

import json
import os
import queue
import sys
import logging
import time
import traceback
from importlib import import_module
from collections.abc import Mapping
from collections import OrderedDict

from enum import IntEnum
from typing import Any

from .config import Configuration
from .config.configuration import atomic_write
from .system import cadence, queue_cadence, now, QueueType


class ProcessTracker(Mapping):
    default_filename = 'subsystems.cfg.json'

    def __init__(self):
        #self.message = processes_pb2.ProcessTracker()
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

    def to_json_string(self):
        return json.dumps(self.classes, indent=2)

    # Backward-compat alias
    to_yaml_string = to_json_string

    def to_file(self, filename=None):
        # Atomic write: load_configs may read subsystems.cfg.json concurrently;
        # a raw open(...,'w') exposes an empty window mid-write.
        with atomic_write(self._validate_path(filename)) as spec:
            json.dump(self.classes, spec, indent=2)

    def from_json_string(self, data):
        name_dict = json.loads(data)
        for cfg, proc in name_dict.items():
            self.register_subsystem(cfg, proc)

    # Backward-compat alias
    from_yaml_string = from_json_string

    def from_file(self, filename=None):
        with open(self._validate_path(filename), 'r') as spec:
            name_dict = json.load(spec)
        for cfg, proc in name_dict.items():
            self.register_subsystem(cfg, proc)

    def __getitem__(self, key):
        return self._registry[key]

    def __len__(self):
        return len(self._registry)

    def __iter__(self):
        return iter(self._registry)


#: The one log-line shape for the whole project.
#:
#: Every AT handler already used these bytes; what drifted is that each
#: entry-point script called `logging.basicConfig` with a shape of its own
#: (`%(asctime)s %(levelname)s %(name)s: %(message)s`). In those scripts BOTH
#: handlers are live at once -- AT's, on its class-named logger, and root's,
#: from basicConfig -- so a single framework event printed twice, in two
#: different shapes, which is exactly the confusion that made the module-logger
#: trap so hard to read. Defining it once here means a change lands everywhere
#: instead of in eight of nine places.
#:
#: NB no `%(name)s`: an AT message says who it is in its own text (the
#: `'%s: ...', self.name` prefix the processes use), and adding the field would
#: change every line the framework already emits.
LOG_FORMAT = '%(asctime)s.%(msecs)03d - %(levelname)s %(message)s'
LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'


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

    def __init__(self, configurations: dict[str, Any], subsystems: ProcessTracker, log_queue: QueueType,
                 dependencies: list[str] = None, log_level=LogLevel.INFO, suppress_log=False):
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

    def report_exception(self, exception, function=None):
        if function is None:
            function = ':'
        else:
            function = ' in ' + function + ':'
        self.logger.error('%s%s %s\n%s', exception.__class__.__name__, function, exception, traceback.format_exc())

    def keep_running(self, signal):
        running = True
        try:
            sig = signal.get_nowait()
            self.logger.debug('Quit %s', self.__class__.__name__)
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
        # Per-queue best-effort: if one queue is full, log via probe and
        # continue with the rest. The original implementation let a Full
        # exception propagate up and abort the loop, so a single slow
        # queue (e.g. main proc backlogged with rep_resp traffic) would
        # silently block updates from reaching every queue iterated
        # AFTER it — manifested as PeerCapabilities updates landing on
        # main but never on bridge-data-rcvr in the multi-agency demo.
        from queue import Full as _Full
        try:
            from . import _probes
        except Exception:
            _probes = None
        for name, q in queues.items():
            if name == self.name:
                continue
            try:
                q.put(msg, block=True, timeout=self.q_cadence)
            except _Full:
                if _probes is not None:
                    try:
                        _probes.counter('proc.update', 'queue_full', name)
                    except Exception:
                        pass

    def process(self, queues, signal):
        raise NotImplementedError


class ProcessLogger(object):
    def __init__(self, name, log_q, suppress=False):
        self.name = name
        self.log_queue = log_q
        self.logger = logging.getLogger(name)
        self.suppress = suppress

    def flush(self):
        if self.logger.handlers:
            self.logger.handlers[0].flush()

    def log(self, level, msg, *args):
        # Match stdlib Logger semantics: formatting is deferred until a
        # handler actually emits. Here we pre-format because the message
        # travels through a queue as a plain string.
        if args:
            try:
                msg = msg % args
            except Exception:
                msg = f"{msg} {args!r}"
        if self.suppress:
            return
        if self.log_queue is not None:
            try:
                self.log_queue.put((level, self.name, msg), block=True, timeout=0.001)
            except queue.Full:
                pass  # drop log message rather than crash
        else:
            self.logger.log(level, msg)

    def verbose(self, msg, *args):
        self.log(LogLevel.VERBOSE, msg, *args)

    def debug(self, msg, *args):
        self.log(LogLevel.DEBUG, msg, *args)

    def info(self, msg, *args):
        self.log(LogLevel.INFO, msg, *args)

    def warning(self, msg, *args):
        self.log(LogLevel.WARNING, msg, *args)

    def error(self, msg, *args):
        self.log(LogLevel.ERROR, msg, *args)

    def critical(self, msg, *args):
        self.log(LogLevel.CRITICAL, msg, *args)


class Mockery(object):
    """Test mock wrapper for Process.mocks (kept here due to Process dependency)."""

    def __init__(self, name, obj=None, value=None, assert_fn=None):
        self.name = name
        self.obj = obj
        self.value = value
        self.assert_fn = assert_fn

    def patch(self, mocker):
        if self.obj is None:
            mocker.patch(self.name)  # always relative to SUBSYSTEMS
        else:
            if self.value is None:
                mocker.patch.object(self.obj, self.name)
            else:
                mocker.patch.object(self.obj, self.name, return_value=self.value)

    def assertion(self):
        if self.assert_fn is not None:
            self.assert_fn()
