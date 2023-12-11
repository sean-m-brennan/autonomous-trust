from __future__ import annotations

import os
import random
import sys
import time
import logging
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler, SysLogHandler
import traceback
import queue
from enum import Enum
from typing import Any, Union
import multiprocessing as mp
from multiprocessing import Pool as ProcessPool
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing.pool import AsyncResult  # noqa
from operator import mul, pow
from decimal import Decimal, getcontext

import psutil

try:
    from . import __version__ as version
except ImportError:
    version = '?.?.?'
from .config import Configuration, to_yaml_string, ConfigMap
from .config.discover import get_cfg_type, load_configs
from .processes import Process, LogLevel, ProcessTracker
from .identity import Peers
from .capabilities import Capabilities, Capability, PeerCapabilities
from .system import CfgIds, PackageHash, queue_cadence, max_concurrency, now, preferred_proto_ver, QueueType
from .protocol import Protocol
from .negotiation import Task, TaskParameters, TaskStatus, Status, TaskResult, NegotiationProtocol
from .network import Message
from .reputation import TransactionScore, ReputationProtocol
from .queue_pool import QueuePool

PoolType = Union[ProcessPool, ThreadPool]


def pi(precision):  # intentionally non-trivial, arbitrary precision
    getcontext().prec = precision
    return sum(1 / Decimal(16) ** k *
               (Decimal(4) / (8 * k + 1) -
                Decimal(2) / (8 * k + 4) -
                Decimal(1) / (8 * k + 5) -
                Decimal(1) / (8 * k + 6)) for k in range(precision))


class Ctx(str, Enum):
    FORK = 'fork'
    SPAWN = 'spawn'
    DEFAULT = FORKSERVER = 'forkserver'

    def __str__(self) -> str:
        return str.__str__(self)


################################################################################


class AutonomousTrust(Protocol):
    """
    Creates an AutonomousTrust machine
    """
    external_control = 'extern_out'
    external_feedback = 'extern_in'

    # default to production values
    def __init__(self, multiproc: bool = True, log_level: int = LogLevel.WARNING,
                 logfile: str = None, log_classes: list[str] = None, syslog: bool = False,
                 context: str = Ctx.DEFAULT, testing: bool = False, silent: bool = False):
        self._stopped_procs: list[str] = []
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
        self.queue_pool: QueuePool = QueuePool(self._queue_type)

        self._log_level: int = log_level
        self.name: str = self.__class__.__name__
        if logfile is None:
            logfile = os.path.join(Configuration.get_data_dir(), 'autonomous_trust.log')
        self.classes_to_log = log_classes
        if log_classes is None:
            self.classes_to_log = list(CfgIds)
        root: logging.Logger = logging.getLogger()
        root.setLevel(logging.DEBUG)
        if logfile == Configuration.log_stdout:
            handler = logging.StreamHandler(sys.stdout)
        else:
            handler = TimedRotatingFileHandler(logfile, when="midnight", interval=1, backupCount=5)
        handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d - %(levelname)s %(message)s',
                                               '%Y-%m-%d %H:%M:%S'))
        handler.setLevel(log_level)
        self._logger: logging.Logger = logging.getLogger(self.name)
        self._logger.addHandler(handler)
        if syslog:
            syslog_handler = SysLogHandler(address='/dev/log')
            self._logger.addHandler(syslog_handler)
        super().__init__(CfgIds.main, self._logger, None)
        self.identity = None  # of type Identity (can't import)

        self.process_names: list[str] = []
        self.capabilities: Capabilities = Capabilities()
        self._output: QueueType = self.queue_type()  # subsystem logging
        self._subsystems: ProcessTracker = ProcessTracker()
        self._additional_workers: list[tuple[type[Process], list[str], dict[str, Any]]] = []
        self._my_queue: QueueType = self.queue_type()
        self.testing: bool = testing
        self.silent = silent
        self.active_tasks: dict[str, Task] = {}
        self.active_pids: dict[str, int] = {}
        self.last_tick: dict[int, int] = {}
        self.tasking_start: datetime = now()
        self.latest_reputation: dict[str, Any] = {}
        self.unhandled_messages: list[Message] = []
        self.peer_count = 0

    def print(self, str):
        if not self.silent:
            print(str)

    @property
    def queue_type(self):
        return self._queue_type

    @property
    def system_dependencies(self) -> list[str]:
        return self._subsystems.names

    def add_worker(self, process: type[Process], dependencies: list[str] = None, **kwargs) -> None:
        """
        Adds custom concurrency (Process), must be called in __init__()
        :param process: object derived from autonomous_trust.core.processes.Process
        :param dependencies: list of process names that must precede this one
        :return: None
        """
        self._additional_workers.append((process, dependencies, kwargs))

    def autonomous_ability(self, queues: dict[str, QueueType]):
        """
        Override this to register real services (Capability).
        :param queues: Interprocess communication queues to each process
        :return: None
        """
        if self.testing:
            self.capabilities.register_ability('mult', mul)
            self.capabilities.register_ability('pow', pow)
            self.capabilities.register_ability('pi', pi)

            for q_name in queues:
                if q_name != self.proc_name:
                    queues[q_name].put(self.capabilities, block=True, timeout=queue_cadence)

    def init_tasking(self, queues: dict[str, QueueType]):
        """
        Override this for pre-loop initializations
        :param queues: Interprocess communication queues to each process
        :return: None
        """
        self.tasking_start = now()
        if self.testing:
            self.peer_count = len(self.peers.all)  # noqa

    def tasking_tick(self, t_id: int, period: float = 30.0):
        mark = (now() - self.tasking_start).total_seconds() / period
        if t_id not in self.last_tick:
            self.last_tick[t_id] = 0
        if mark > self.last_tick[t_id]:
            diff = mark - self.last_tick[t_id]
            self.last_tick[t_id] = mark
            return diff
        return 0

    def autonomous_tasking(self, queues: dict[str, QueueType]):
        """
        Override this for assigning tasks
        :param queues: Interprocess communication queues to each process
        :return: None
        """
        if self.testing:
            if len(self.peers.all) > 0:
                if len(self.peers.all) > self.peer_count:
                    self.peer_count = len(self.peers.all)  # noqa
                    self._random_task(queues)
                elif self.tasking_tick(0):
                    self._random_task(queues)
                    # check my own reputation
                    query = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                                    to_yaml_string((self.identity, self.proc_name)), self.identity)
                    queues[CfgIds.reputation].put(query, block=True, timeout=queue_cadence)
        self._report_unhandled()

    def cleanup(self):
        pass

    def autonomous_loop(self, results: dict[str, AsyncResult], queues: dict[str, QueueType],
                        signals: dict[str, QueueType]) -> None:
        """
        Override this for more control inside the main loop.
        Careful: equivalent message handling and monitoring is required.
        :param results: subprocess AsyncResults
        :param queues: Interprocess communication queues to each process
        :param signals: queues listening for a quit signal
        :return: None
        """
        self.autonomous_ability(queues)
        self.init_tasking(queues)
        with self._pool_type(max_concurrency) as pool:
            while True:
                try:
                    self._monitor_processes(results)
                    if not self._handle_messages(queues, pool, results):
                        break
                    self._handle_results(queues, results)
                    self.autonomous_tasking(queues)
                    time.sleep(Process.cadence)
                except KeyboardInterrupt:
                    for sig in signals.values():
                        sig.put_nowait(Process.sig_quit)
                    break
                except Exception as err:
                    self.logger.error(self.name + ':  ' +
                                      ''.join(traceback.TracebackException.from_exception(err).format()))
        self.cleanup()

    def run_forever(self, q_in: QueueType = None, q_out: QueueType = None):
        """
        Start the autonomous machinery as the lead process
        :return: None
        """
        os.makedirs(Configuration.get_data_dir(), exist_ok=True)
        configs = self._configure()
        procs: list[Process] = configs[Process.key]
        if self._log_level <= LogLevel.WARNING:
            self._banner()
        self.logger.info(self.name + ':  Package signature %s' % configs[PackageHash.key])
        self.logger.info(self.name + ":  Configuring '%s' at %s for %s" %
                         (self.identity.fullname, self.identity.address, '(unknown domain)'))
        self.logger.info(self.name + ':  Signature: %s' % self.identity.signature.publish())
        self.logger.info(self.name + ':  Public key: %s' % self.identity.encryptor.publish())

        if procs is None:
            return
        queues = dict(zip(list(map(lambda x: x.name, procs)),
                          [self.queue_type() for _ in range(len(procs))]))
        queues[self.proc_name] = self._my_queue
        signals: dict[str, QueueType] = {}
        results: dict[str, AsyncResult] = {}
        with self._pool_type(len(procs)) as pool:
            for proc in procs:  # FIXME split system procs from additional
                self.logger.info(self.name + ':  Starting %s ...' % proc.name)
                self.process_names.append(proc.name)
                signals[proc.name] = self.queue_type()
                results[proc.name] = pool.apply_async(proc.process, (queues, signals[proc.name]))
            if q_in is not None:
                queues[self.external_control] = q_in  # main loop must watch/process
            if q_out is not None:
                queues[self.external_feedback] = q_out  # main loop must upload to this
            pool.close()  # no more system tasks (use separate pool for dynamic tasks)
            self.logger.info(self.name + ':                                          Ready.')  # FIXME not really ready

            self.autonomous_loop(results, queues, signals)

        self.logger.info(self.name + ':  Shutdown')

    ####################
    # Protected methods

    def _banner(self):
        self.print("")
        self.print("You are using\033[94m AutonomousTrust\033[00m v%s from\033[96m TekFive\033[00m." % version)
        self.print("")

    def _configure(self, start: bool = True):
        # Pull initial state from configuration files
        required = [CfgIds.network, CfgIds.identity, CfgIds.peers, CfgIds.capabilities]
        defaultable = {CfgIds.peers: Peers, CfgIds.capabilities: PeerCapabilities, }

        configs: ConfigMap = {}
        cfg_dir = Configuration.get_cfg_dir()
        self._subsystems.from_file(cfg_dir)

        # find missing configs, set defaults
        config_files = os.listdir(cfg_dir)
        cfg_types = list(map(get_cfg_type, config_files))
        for cfg_name in required:
            if cfg_name not in cfg_types:
                if cfg_name in defaultable:
                    defaultable[cfg_name]().to_file(os.path.join(cfg_dir, cfg_name + Configuration.yaml_file_ext))
                else:
                    self.logger.error('%s:  Required %s configuration missing' % (self.name, cfg_name))
                    return None

        # load configs
        configs = load_configs()

        package_hash = PackageHash()
        configs[PackageHash.key] = package_hash.digest
        configs[Process.level] = self._log_level

        net_cfg = configs[CfgIds.network]
        self.identity = configs[CfgIds.identity]
        self.identity.address = net_cfg.ip4
        if preferred_proto_ver == 6:
            self.identity.address = net_cfg.ip6
        self.peers = configs[CfgIds.peers]

        if start:
            # init configured process classes
            sub_sys_list = self._subsystems.ordered
            for sub_sys_cls in sub_sys_list:
                suppress = True
                if sub_sys_cls.cfg_name in self.classes_to_log:
                    suppress = False
                configs[Process.key].append(sub_sys_cls(configs, self._subsystems, self._output, suppress_log=suppress))
            # FIXME wait for system to be operational before running these??
            for worker_cls, deps, kwargs in self._additional_workers:
                configs[Process.key].append(worker_cls(configs, self._subsystems, self._output, deps, **kwargs))
        return configs

    def _monitor_processes(self, proc_results: dict[str, AsyncResult], show_output: bool = True):
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
                    self.logger.debug('Check process %s' % name)
                    result.get(0)
                except mp.TimeoutError:
                    pass
                except KeyboardInterrupt:
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

    def _failed_task_cb(self, task: Task):
        def report_error(err: Exception):
            self.logger.error('Task %s failed: %s' %
                              (task.capability.name, '\n'.join(traceback.format_exception(type(err), err))))

        return report_error

    def _handle_messages(self, queues: dict[str, QueueType], pool: PoolType, results: dict[str, AsyncResult]):
        if self.external_control in queues:
            try:
                cmd = queues[self.external_control].get_nowait()
                if isinstance(cmd, Task):
                    message = Message(CfgIds.negotiation, NegotiationProtocol.start, cmd)
                    queues[CfgIds.negotiation].put(message, block=True, timeout=queue_cadence)
                elif cmd == Process.sig_quit:
                    self.logger.debug(self.name + ": External signal to quit")
                    return False
            except queue.Empty:
                pass
            except queue.Full:
                self.logger.error(self.name + ': Negotiation queue full')

        message = None
        try:
            message = queues[self.proc_name].get(block=True, timeout=queue_cadence)
        except queue.Empty:
            pass

        if message is not None:
            if not self.run_message_handlers(queues, message):
                if isinstance(message, TaskStatus):
                    if message.uuid in self.active_pids:
                        pid = self.active_pids[message.uuid]
                        message.status = Status.from_ps(psutil.Process(pid).status())
                    else:
                        message.status = Status.unknown
                    queues[CfgIds.negotiation].put(message, block=True, timeout=queue_cadence)
                    self.logger.debug('Handled status: %s' % message.status)
                elif isinstance(message, TaskResult):
                    task = message
                    self.logger.debug(self.name + ': Task result recvd: %s' % task.result)
                    tx = TransactionScore(task.uuid, 0.5)  # FIXME relevant evaluation
                    queues[CfgIds.reputation].put(tx, block=True, timeout=queue_cadence)
                    if self.external_feedback in queues:
                        queues[self.external_feedback].put(task, block=True, timeout=queue_cadence)
                elif isinstance(message, Task):
                    task = message
                    if task.capability in self.capabilities:
                        capability = self.capabilities[task.capability.name]
                        pq = self.queue_type()
                        self.logger.debug(self.name + ': Running task')
                        self.active_tasks[str(task.uuid)] = task
                        results[task.uuid] = pool.apply_async(capability.execute, (task, pq))
                        try:
                            pid = pq.get(block=True, timeout=1)
                            self.active_pids[str(task.uuid)] = pid
                        except queue.Empty:
                            self.logger.error(self.name + ': Process failed')  # FIXME more info
                elif isinstance(message, Message) and message.function == ReputationProtocol.rep_resp:
                    rep = message.obj
                    if rep.peer_id == self.identity.uuid:
                        self.print('My current reputation score:\033[31m %s\033[00m' % rep.score)
                    else:
                        peer = self.peers.find_by_uuid(rep.peer_id)
                        if peer:
                            self.print("%s's current reputation score:\033[31m %s\033[00m" % (peer.nickname, rep.score))
                    self.latest_reputation[str(rep.peer_id)] = rep
                else:
                    self.unhandled_messages.append(message)
        return True

    def _report_unhandled(self):
        while len(self.unhandled_messages) > 0:
            message = self.unhandled_messages.pop()
            if isinstance(message, Message):
                self.logger.error(self.name + ': Unhandled message %s' % message.function)
            else:
                self.logger.error(self.name + ': Unhandled message of type %s' % message.__class__.__name__)  # noqa

    def _handle_results(self, queues: dict[str, QueueType], results: dict[str, AsyncResult]):
        for key in list(results.keys()):
            if results[key].ready():
                if key in list(self.process_names):
                    self.logger.error('unexpected termination of process %s' % key)
                    continue
                try:
                    self.logger.debug(self.name + ': %s Task' % key)
                    result = results[key].get()
                    self.logger.debug(self.name + ': %s Task completed %s' % (key, result))
                    tr = TaskResult(self.active_tasks[key], result)
                    queues[CfgIds.negotiation].put(tr, block=True, timeout=queue_cadence)
                    tx = TransactionScore(tr.uuid, 0.6)  # FIXME relevant evaluation
                    queues[CfgIds.reputation].put(tx, block=True, timeout=queue_cadence)
                except KeyboardInterrupt:
                    pass
                except Exception:
                    self.logger.error('Task Exception - ' + traceback.format_exc())
                    # FIXME send error result to negotiation
                del results[key]

    def _random_task(self, queues: dict[str, QueueType]):
        cap_list = self.capabilities.to_list()
        cap = Capability(cap_list[random.randint(0, len(cap_list) - 1)])
        args = (random.randint(2, 1000000), random.randint(2, 1000000))
        if cap.name == 'pi':
            args = (random.randint(1000, 10000),)
        try:
            task = Task(TaskParameters(cap, args=args), self.identity)
            msg = Message(CfgIds.negotiation, NegotiationProtocol.start, task)
            queues[CfgIds.negotiation].put(msg, block=True, timeout=queue_cadence)
            self.logger.debug(self.name + ': Send task to %d peers' % len(self.peers.all))
        except queue.Full:
            self.logger.error(self.name + ': Test task: negotiation queue full')
