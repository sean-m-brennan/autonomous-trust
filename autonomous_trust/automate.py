import os
import sys
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import traceback
from multiprocessing import Manager
from queue import Empty
from concurrent.futures import TimeoutError, CancelledError

from .configuration import Configuration, CfgIds
from .processes import Process, LogLevel, SUBSYSTEMS
from .identity import Peers


def banner():
    print("")
    print("You are using\033[94m AutonomousTrust\033[00m from\033[96m TekFive\033[00m.")
    print("")


def configure(logger):
    required = [CfgIds.network.value, CfgIds.identity.value, CfgIds.peers.value]
    defaultable = {CfgIds.peers.value: Peers, }

    configs = {}
    cfg_dir = Configuration.get_cfg_dir()
    SUBSYSTEMS.from_file(cfg_dir)

    def get_cfg_type(path):
        if path.endswith(Configuration.yaml_file_ext):
            return os.path.basename(path).removesuffix(Configuration.yaml_file_ext)

    # find missing, set defaults
    config_files = os.listdir(cfg_dir)
    cfg_types = list(map(get_cfg_type, config_files))
    for cfg_name in required:
        if cfg_name not in cfg_types:
            if cfg_name in defaultable.keys():
                defaultable[cfg_name]().to_file(os.path.join(cfg_dir, cfg_name + Configuration.yaml_file_ext))
            else:
                logger.error('Required %s configuration missing' % cfg_name)
                return None

    # load configs
    config_files = [x for x in os.listdir(cfg_dir) if x.endswith(Configuration.yaml_file_ext)]
    config_paths = list(map(lambda x: os.path.join(cfg_dir, x), config_files))
    for cfg_file in config_paths:
        configs[get_cfg_type(cfg_file)] = Configuration.from_file(cfg_file)

    # cross-reference
    net_cfg = configs[CfgIds.network.value]
    identity = configs[CfgIds.identity.value]
    if identity.address != net_cfg.ip:  # TODO other addressing (and do this somewhere else, net_impl?)
        logger.error('Identity and network addresses differ: %s vs %s' % (identity.address, net_cfg.ip))
        logger.warning('  Using the network addresses in identity and saving')
        identity.address = net_cfg.ip
        identity.to_file(os.path.join(cfg_dir, CfgIds.identity.value + Configuration.yaml_file_ext))

    logger.info("Configuring '%s' at %s for %s" % (identity.fullname, identity.address, '(unknown domain)'))
    logger.info('Signature: %s' % identity.signature.publish())  # FIXME these might be wrong for passing around
    logger.info("Public key: %s" % identity.encryptor.publish())

    # init configured process classes
    configs[Process.key] = []
    for sub_sys_cls in SUBSYSTEMS.values():
        configs[Process.key].append(sub_sys_cls(configs))
    return configs


# default to production values
def main(multiproc=False, log_level=LogLevel.WARNING, logfile=None):
    os.makedirs(Configuration.get_data_dir(), exist_ok=True)
    if multiproc:
        from pebble import ProcessPool as ExecPool
    else:
        from pebble import ThreadPool as ExecPool

    if logfile is None:
        logfile = os.path.join(Configuration.get_data_dir(), 'autonomous_trust.log')
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    if logfile == Configuration.log_stdout:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        handler.setFormatter(logging.Formatter('%(name)s: %(message)s'))
        root.addHandler(handler)
    else:
        log_fmt = '%(asctime)s.%(msecs)03d - %(levelname)s %(name)s  %(message)s'
        date_fmt = '%Y-%m-%d %H:%M:%S'
        handler = TimedRotatingFileHandler(logfile, when="midnight", interval=1, backupCount=5)
        handler.setLevel(log_level)
        handler.setFormatter(logging.Formatter(log_fmt, date_fmt))
        root.addHandler(handler)
    logger = logging.getLogger(__name__)
    if log_level <= LogLevel.INFO:
        banner()
    procs = configure(logger)[Process.key]
    if procs is None:
        return
    manager = Manager()
    queues = dict(zip(list(map(lambda x: x.name, procs)), [manager.Queue() for _ in range(len(procs))]))
    signals = {}
    output = manager.Queue()
    with ExecPool(max_workers=len(procs)*2) as pool:
        future_info = {}
        for proc in procs:
            # start all listeners first
            logger.info("Starting %s ..." % proc.name)
            task_name = proc.name.replace(' ', '_') + '.in'
            signals[task_name] = manager.Queue()
            future_info[task_name] = pool.schedule(proc.listen, (queues, output, signals[task_name]))
        for proc in procs:
            # then allow speakers - so no messages are lost
            task_name = proc.name.replace(' ', '_') + '.in'
            signals[task_name] = manager.Queue()
            future_info[task_name] = pool.schedule(proc.speak, (queues, output, signals[task_name]))
        pool.close()  # no more tasks
        logger.info('                                        Ready.')

        while True:
            try:
                # record subprocess exceptions
                for name, future in future_info.items():
                    if future.done():
                        try:
                            ex = future.exception(0)
                            logger.error(''.join(traceback.TracebackException.from_exception(ex).format()))
                        except (TimeoutError, CancelledError):
                            pass
                # record subprocess outputs, if any
                try:
                    level, name, msg = output.get_nowait()
                    logger.log(level, '%s: %s' % (name, msg))
                except Empty:
                    pass
                time.sleep(Process.cadence)
            except KeyboardInterrupt:
                for sig in signals.values():
                    sig.put_nowait(Process.sig_quit)
                break
        futures = list(future_info.items())
        futures.reverse()
        for name, future in futures:
            if not future.done():
                future.cancel()
            logger.info("%s halted" % name)
        pool.join(Process.exit_timeout)
    logger.info("Shutdown")
