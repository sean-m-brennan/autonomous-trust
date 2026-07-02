# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

"""Instrumented AT node entry point for metrics collection.

Identical to ``python -m autonomous_trust`` but registers a
MetricsCollector that observes all inter-process messages via
tee-queues.

Usage (Docker or host):
    python -m autonomous_trust.evaluation.instrumented [AT args] --metrics-output /path/to/metrics.json

Environment variable alternative:
    METRICS_OUTPUT=/path/to/metrics.json python -m autonomous_trust.evaluation.instrumented [AT args]
"""

import os
import signal
import sys
import argparse

from autonomous_trust.core._python.system import dev_root_dir, CfgIds
from autonomous_trust.core._python.automate import AutonomousTrust
from autonomous_trust.core._python.config import Configuration
from autonomous_trust.core._python.config.generate import random_config
from autonomous_trust.core._python.processes import Process, LogLevel

from .metrics.collector import MetricsCollector


class _TeeQueue:
    """Queue wrapper that copies put() calls to one or more observer queues."""

    def __init__(self, real_queue, observer_queues):
        self._real = real_queue
        if isinstance(observer_queues, list):
            self._observers = observer_queues
        else:
            self._observers = [observer_queues]

    def __getstate__(self):
        return {'_real': self._real, '_observers': self._observers}

    def __setstate__(self, state):
        self._real = state['_real']
        self._observers = state['_observers']

    def put(self, obj, block=True, timeout=None):
        self._real.put(obj, block=block, timeout=timeout)
        for obs in self._observers:
            try:
                obs.put_nowait(obj)
            except Exception:
                pass

    def put_nowait(self, obj):
        self._real.put_nowait(obj)
        for obs in self._observers:
            try:
                obs.put_nowait(obj)
            except Exception:
                pass

    def get(self, block=True, timeout=None):
        return self._real.get(block=block, timeout=timeout)

    def get_nowait(self):
        return self._real.get_nowait()

    def empty(self):
        return self._real.empty()

    def qsize(self):
        return self._real.qsize()


class InstrumentedAT(AutonomousTrust):
    """AT node that tees inter-process messages to a MetricsCollector."""

    _metrics_output = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._metrics_output:
            self.add_worker(MetricsCollector, output_path=self._metrics_output)

    def run_forever(self, q_in=None, q_out=None):
        """Override to wrap process queues with _TeeQueue."""
        os.makedirs(Configuration.get_data_dir(), exist_ok=True)
        configs = self._configure()
        procs = configs[Process.key]
        if self._log_level <= LogLevel.WARNING:
            self._banner()
        self.logger.info(self.name + ':  Configuring with metrics collection')

        if procs is None:
            return

        queues = dict(zip(
            [p.name for p in procs],
            [self.queue_type() for _ in range(len(procs))]
        ))
        queues[self.proc_name] = self._my_queue

        # Wrap all queues (except observers') with TeeQueue
        observer_names = [
            p.name for p in procs
            if getattr(p, 'is_tee_observer', False)
        ]
        if observer_names:
            observer_qs = [queues[n] for n in observer_names]
            for name in list(queues):
                if name not in observer_names:
                    queues[name] = _TeeQueue(queues[name], observer_qs)

        signals = {}
        results = {}
        with self._pool_type(len(procs)) as pool:
            for proc in procs:
                self.logger.info(self.name + ':  Starting %s ...' % proc.name)
                self.process_names.append(proc.name)
                signals[proc.name] = self.queue_type()
                results[proc.name] = pool.apply_async(
                    proc.process, (queues, signals[proc.name]))
            if q_in is not None:
                queues[self.external_control] = q_in
            if q_out is not None:
                queues[self.external_feedback] = q_out
            pool.close()
            self.logger.info(self.name + ':  Ready.')

            self.autonomous_loop(results, queues, signals)

        self.logger.info(self.name + ':  Shutdown')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ident', type=int, nargs='?', default=None,
                        help='optional integer for separating multiple node configs')
    parser.add_argument('--remote-debug', type=str, nargs='?', default=None,
                        help='activate remote debugging connection, in the form: ip_address:port')
    parser.add_argument('--exclude-logs', type=str, action='append',
                        help='exclude named classes from logging')
    parser.add_argument('--test', action='store_true',
                        help='run limited testing application')
    parser.add_argument('--live', action='store_true',
                        help='run in production environ')
    parser.add_argument('--log-level', type=str, default='info',
                        choices=['critical', 'error', 'warning', 'info', 'debug', 'verbose'],
                        help='set logging level (default: info)')
    parser.add_argument('--metrics-output', type=str, default=None,
                        help='path for metrics JSON output')
    args = parser.parse_args()

    if args.remote_debug is not None:
        ip, port = args.remote_debug.split(':', 1)
        print('Remote debugging to %s:%s' % (ip, port))
        import pydevd_pycharm
        pydevd_pycharm.settrace(ip, port=int(port), stdoutToServer=True, stderrToServer=True)

    if args.live:
        random_config(Configuration.get_cfg_dir(), args.ident)
    else:
        random_config(dev_root_dir, args.ident)
    to_log = None
    if args.exclude_logs is not None:
        to_log = [cls for cls in list(CfgIds) if cls not in args.exclude_logs]
    level = LogLevel[args.log_level.upper()]

    metrics_output = args.metrics_output or os.environ.get('METRICS_OUTPUT')
    InstrumentedAT._metrics_output = metrics_output

    # Convert SIGTERM (from docker stop) into KeyboardInterrupt so that
    # autonomous_loop sends sig_quit to subprocesses, allowing
    # MetricsCollector to write its report before shutdown.
    def _sigterm_handler(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, _sigterm_handler)

    InstrumentedAT(multiproc=True, log_level=level, logfile=Configuration.log_stdout,
                   log_classes=to_log, testing=args.test).run_forever()


if __name__ == '__main__':
    # Default to forkserver: 'fork' (Linux default through 3.13) forks a
    # multi-threaded process and can deadlock the child. Harmless on 3.14+.
    import multiprocessing as _mp
    _mp.set_start_method('forkserver', force=True)
    main()
