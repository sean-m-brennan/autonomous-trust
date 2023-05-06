from __future__ import annotations
import os
import sys
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import traceback
import queue
from enum import Enum
from typing import Union
import multiprocessing as mp
from multiprocessing import Pool as ProcessPool
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing.pool import AsyncResult  # noqa

try:
    from . import __version__ as version
except ImportError:
    version = '?.?.?'
from .config import Configuration, CfgIds
from .processes import Process, LogLevel, ProcessTracker
from .identity import Peers
from .system import PackageHash

PoolType = Union[ProcessPool, ThreadPool]
QueueType = Union[queue.Queue, mp.Queue]


class Ctx(str, Enum):
    FORK = 'fork'
    SPAWN = 'spawn'
    DEFAULT = FORKSERVER = 'forkserver'

    def __str__(self) -> str:
        return str.__str__(self)


class AutonomousTrust(object):
    """
    Creates an AutonomousTrust machine
    """
    external_control = 'extern_out'
    external_feedback = 'extern_in'

    # default to production values
    def __init__(self, multiproc: Union[bool, None] = True, log_level: int = LogLevel.WARNING,
                 logfile: str = None, context: str = Ctx.DEFAULT):
        self._stopped_procs = []
        if multiproc:
            # Multiprocessing
            self._pool_type = ProcessPool
            ctx = mp.get_context(context)
            manager = ctx.Manager()
            self._queue_type = manager.Queue  # noqa
        else:
            # Threading
            self._pool_type = ThreadPool
            self._queue_type = queue.Queue
            # FIXME monkeypatch shutdown?

        self._log_level = log_level
        self.name = self.__class__.__name__
        if logfile is None:
            logfile = os.path.join(Configuration.get_data_dir(), 'autonomous_trust.log')
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        if logfile == Configuration.log_stdout:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter('%(message)s'))
        else:
            handler = TimedRotatingFileHandler(logfile, when="midnight", interval=1, backupCount=5)
            handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d - %(levelname)s %(message)s',
                                                   '%Y-%m-%d %H:%M:%S'))
        handler.setLevel(log_level)
        self._logger = logging.getLogger(self.name)
        self._logger.addHandler(handler)
        self._output = self.queue_type()  # process logging
        self._subsystems = ProcessTracker()
        self._additional_workers = []
        self._my_queue = self.queue_type()

    @property
    def queue_type(self) -> type[QueueType]:
        return self._queue_type

    @property
    def logger(self) -> logging.Logger:
        return self._logger

    @property
    def system_dependencies(self) -> list[str]:
        return self._subsystems.names

    def add_worker(self, process: type[Process], dependencies: list[str] = None) -> None:
        """
        Add custom concurrency, must be called in __init__()
        :param process: object derived from autonomous_trust.processes.Process
        :param dependencies: list of process names that must precede this one
        :return: None
        """
        self._additional_workers.append((process, dependencies))

    def autonomous_loop(self, results: dict[str, AsyncResult], queues: dict[str, QueueType],
                        signals: dict[str, QueueType]) -> None:
        """
        Override this to do something more inside the main loop.
        :param results: subprocess AsyncResults
        :param queues: Interprocess communication queues to each process
        :param signals: queues listening for a quit signal
        :return: None
        """
        while True:
            try:
                self._monitor_processes(results)
                if self.external_control in queues:
                    try:
                        cmd = queues[self.external_control].get_nowait()
                        if cmd == Process.sig_quit:
                            self.logger.debug(self.name + ": External signal to quit")
                            break
                    except queue.Empty:
                        pass

                # do nothing else

                time.sleep(Process.cadence)
            except KeyboardInterrupt:
                for sig in signals.values():
                    sig.put_nowait(Process.sig_quit)
                break

    def run_forever(self, q_in: QueueType = None, q_out: QueueType = None):
        """
        Start the autonomous machinery as the lead process
        :return: None
        """
        os.makedirs(Configuration.get_data_dir(), exist_ok=True)
        configs = self._configure()
        procs = configs[Process.key]
        if self._log_level <= LogLevel.WARNING:
            self._banner()
        self.logger.info(self.name + ':  Package signature %s' % configs[PackageHash.key])
        identity = configs[CfgIds.identity.value]
        self.logger.info(self.name + ":  Configuring '%s' at %s for %s" %
                         (identity.fullname, identity.address, '(unknown domain)'))
        self.logger.info(self.name + ':  Signature: %s' % identity.signature.publish())
        # FIXME these might be wrong for passing around
        self.logger.info(self.name + ':  Public key: %s' % identity.encryptor.publish())

        if procs is None:
            return
        queues = dict(zip(list(map(lambda x: x.name, procs)),
                          [self.queue_type() for _ in range(len(procs))]))
        queues['main'] = self._my_queue
        signals = {}
        results = {}
        with self._pool_type(len(procs)) as pool:
            for proc in procs:
                self.logger.info(self.name + ':  Starting %s ...' % proc.name)
                signals[proc.name] = self.queue_type()
                results[proc.name] = pool.apply_async(proc.process, (queues, signals[proc.name]))
            if q_in is not None:
                queues[self.external_control] = q_in  # main loop must watch/process
            if q_out is not None:
                queues[self.external_feedback] = q_out  # main loop must upload to this
            pool.close()  # no more tasks
            self.logger.info(self.name + ':                                          Ready.')

            self.autonomous_loop(results, queues, signals)

        self.logger.info(self.name + ':  Shutdown')

    ####################
    # Protected methods

    @staticmethod
    def _banner():
        print("")
        print("You are using\033[94m AutonomousTrust\033[00m v%s from\033[96m TekFive\033[00m." % version)
        print("")

    @staticmethod
    def _get_cfg_type(path):
        if path.endswith(Configuration.yaml_file_ext):
            return os.path.basename(path).removesuffix(Configuration.yaml_file_ext)

    def _configure(self, start=True):
        # Pull initial state from configuration files
        required = [CfgIds.network.value, CfgIds.identity.value, CfgIds.peers.value]
        defaultable = {CfgIds.peers.value: Peers, }

        configs = {}
        cfg_dir = Configuration.get_cfg_dir()
        self._subsystems.from_file(cfg_dir)

        # find missing, set defaults
        config_files = os.listdir(cfg_dir)
        cfg_types = list(map(self._get_cfg_type, config_files))
        for cfg_name in required:
            if cfg_name not in cfg_types:
                if cfg_name in defaultable:
                    defaultable[cfg_name]().to_file(os.path.join(cfg_dir, cfg_name + Configuration.yaml_file_ext))
                else:
                    self.logger.error(self.name + ':  Required %s configuration missing' % cfg_name)
                    return None

        # load configs
        config_files = [x for x in os.listdir(cfg_dir) if x.endswith(Configuration.yaml_file_ext)]
        config_paths = list(map(lambda x: os.path.join(cfg_dir, x), config_files))
        for cfg_file in config_paths:
            configs[self._get_cfg_type(cfg_file)] = Configuration.from_file(cfg_file)

        package_hash = PackageHash()
        configs[PackageHash.key] = package_hash.digest
        configs[Process.level] = self._log_level
        configs[Process.key] = []

        net_cfg = configs[CfgIds.network.value]
        identity = configs[CfgIds.identity.value]
        # FIXME cross-reference addresses, identity.address is as appropriate for net protocol

        if start:
            # init configured process classes
            sub_sys_list = self._subsystems.ordered
            for sub_sys_cls in sub_sys_list:
                configs[Process.key].append(sub_sys_cls(configs, self._subsystems, self._output))
            for worker_cls, deps in self._additional_workers:
                configs[Process.key].append(worker_cls(configs, self._subsystems, self._output, deps))
        return configs

    def _monitor_processes(self, proc_results, show_output=True):
        """
        Should be included in any main-loop override function
        :param proc_results: dict of process names to multiprocessing.pool.AsyncResults
        :return: whether to keep going or not
        """
        # record subprocess exceptions
        for name, result in proc_results.items():
            if name in self._stopped_procs:
                continue
            if result.ready():
                try:
                    result.get(0)
                except mp.TimeoutError:
                    pass
                except Exception as ex:
                    self.logger.error(self.name + ':  ' +
                                      ''.join(traceback.TracebackException.from_exception(ex).format()))
                    self._stopped_procs.append(name)

        if show_output:
            # record subprocess outputs, if any
            try:
                level, name, msg = self._output.get_nowait()
                self.logger.log(level, '%s: %s' % (name, msg))
            except queue.Empty:
                pass
        return True
