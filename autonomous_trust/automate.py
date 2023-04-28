import os
import sys
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import traceback
from multiprocessing import get_context
import queue
from concurrent.futures import TimeoutError, CancelledError

from .config import Configuration, CfgIds
from .processes import Process, LogLevel, ProcessTracker
from .identity import Peers


class AutonomousTrust(object):
    # default to production values
    def __init__(self, multiproc=True, log_level=LogLevel.WARNING, logfile=None, context='forkserver'):
        self.mp = multiproc
        if multiproc:
            # Multiprocessing
            from pebble import ProcessPool
            self.pool_type = ProcessPool
            ctx = get_context(context)
            self.pool_kwargs = {'context': ctx}
            manager = ctx.Manager()
            self.queue_type = manager.Queue  # noqa
        else:
            # Threading
            from pebble import ThreadPool
            self.pool_type = ThreadPool
            self.pool_kwargs = {}
            self.queue_type = queue.Queue
            # FIXME monkeypatch shutdown?

        self.log_level = log_level
        self.log_file = logfile
        self.name = self.__class__.__name__
        if logfile is None:
            self.log_file = os.path.join(Configuration.get_data_dir(), 'autonomous_trust.log')
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
        self.logger = logging.getLogger(self.name)
        self.logger.addHandler(handler)
        self.output = self.queue_type()

        self.subsystems = ProcessTracker()

    @staticmethod
    def banner():
        print("")
        print("You are using\033[94m AutonomousTrust\033[00m from\033[96m TekFive\033[00m.")
        print("")

    @staticmethod
    def _get_cfg_type(path):
        if path.endswith(Configuration.yaml_file_ext):
                return os.path.basename(path).removesuffix(Configuration.yaml_file_ext)

    def configure(self, start=True):
        required = [CfgIds.network.value, CfgIds.identity.value, CfgIds.peers.value]
        defaultable = {CfgIds.peers.value: Peers, }

        configs = {}
        cfg_dir = Configuration.get_cfg_dir()
        self.subsystems.from_file(cfg_dir)

        # find missing, set defaults
        config_files = os.listdir(cfg_dir)
        cfg_types = list(map(self._get_cfg_type, config_files))
        for cfg_name in required:
            if cfg_name not in cfg_types:
                if cfg_name in defaultable.keys():
                    defaultable[cfg_name]().to_file(os.path.join(cfg_dir, cfg_name + Configuration.yaml_file_ext))
                else:
                    self.logger.error(self.name + ':  Required %s configuration missing' % cfg_name)
                    return None

    # load configs
        config_files = [x for x in os.listdir(cfg_dir) if x.endswith(Configuration.yaml_file_ext)]
        config_paths = list(map(lambda x: os.path.join(cfg_dir, x), config_files))
        for cfg_file in config_paths:
            configs[self._get_cfg_type(cfg_file)] = Configuration.from_file(cfg_file)

        net_cfg = configs[CfgIds.network.value]
        identity = configs[CfgIds.identity.value]
        # FIXME cross-reference addresses, identity.address is as appropriate for net protocol

        self.logger.info(self.name + ":  Configuring '%s' at %s for %s" %
                         (identity.fullname, identity.address, '(unknown domain)'))
        self.logger.info(self.name + ':  Signature: %s' % identity.signature.publish())  # FIXME these might be wrong for passing around
        self.logger.info(self.name + ':  Public key: %s' % identity.encryptor.publish())

        configs[Process.level] = self.log_level
        configs[Process.key] = []
        if start:
            # init configured process classes
            sub_sys_list = self.subsystems.ordered
            for sub_sys_cls in sub_sys_list:
                configs[Process.key].append(sub_sys_cls(configs, self.subsystems, self.output))
        return configs

    def __main_loop(self, future_info, signals):
        while True:
            try:
                # record subprocess exceptions
                for name, future in future_info.items():
                    if future.done():
                        try:
                            ex = future.exception(0)
                            self.logger.error(self.name + ':  ' +
                                              ''.join(traceback.TracebackException.from_exception(ex).format()))
                        except (TimeoutError, CancelledError):
                            pass
                # record subprocess outputs, if any
                try:
                    level, name, msg = self.output.get_nowait()
                    self.logger.log(level, '%s: %s' % (name, msg))
                except queue.Empty:
                    pass
                time.sleep(Process.cadence)
            except KeyboardInterrupt:
                for sig in signals.values():
                    sig.put_nowait(Process.sig_quit)
                break

    def run_forever(self, override_loop=None):
        os.makedirs(Configuration.get_data_dir(), exist_ok=True)
        if self.log_level <= LogLevel.INFO:
            self.banner()
        procs = self.configure()[Process.key]
        if procs is None:
            return
        queues = dict(zip(list(map(lambda x: x.name, procs)), [self.queue_type() for _ in range(len(procs))]))
        signals = {}
        with self.pool_type(max_workers=len(procs), **self.pool_kwargs) as pool:
            future_info = {}
            for proc in procs:
                self.logger.info(self.name + ':  Starting %s ...' % proc.name)
                signals[proc.name] = self.queue_type()
                future_info[proc.name] = pool.schedule(proc.process, (queues, signals[proc.name]))
            pool.close()  # no more tasks
            self.logger.info(self.name + ':                                          Ready.')

            # loop
            if override_loop is not None:
                override_loop(self, future_info, signals)
            else:
                self.__main_loop(future_info, signals)

            # halt
            futures = list(future_info.items())
            futures.reverse()
            for name, future in futures:
                if self.mp and not future.done():
                    future.cancel()
                self.logger.info(self.name + ':  %s halted' % name)
            pool.stop()
            if self.mp:
                pool.join(Process.exit_timeout)
            # FIXME shutdown of threads
        self.logger.info(self.name + ':  Shutdown')


def main(multiproc=True, log_level=LogLevel.WARNING, logfile=None, override_loop=None):
    AutonomousTrust(multiproc, log_level, logfile).run_forever(override_loop)
