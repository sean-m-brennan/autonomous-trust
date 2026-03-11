#!/usr/bin/env python3
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

"""Run Appalachian mesh scenario in-process (no Docker required).

Launches the Simulator and MetricsCollector via multiprocessing.
The Simulator computes terrain-aware connectivity; the MetricsCollector
observes AT protocol messages and writes a JSON metrics report.

Usage:
    python -m autonomous_trust.simulator.scenarios.run_scenario [OPTIONS]

Options:
    --hilltop-only      Only 8 hilltop relay nodes (default: 20 nodes)
    --terrain-csv PATH  Path to SPLAT! path-loss CSV for terrain-aware RF
    --freq-mhz FREQ     Frequency to use from terrain CSV (default: 5800)
    --duration SEC       Simulation duration in seconds (default: 120)
    --steps N            Number of simulation time steps (default: 180)
    --output PATH        Path for metrics JSON output (default: metrics.json)
    --log-level LEVEL    Log level: debug, info, warning (default: info)
"""

import argparse
import json
import logging
import multiprocessing
import os
import signal
import sys
import tempfile
import time
from datetime import timedelta
from unittest.mock import patch

from autonomous_trust.core import Configuration, ProcessTracker, Process
from autonomous_trust.core.config.generate import generate_identity
from autonomous_trust.core._python.network.message import Message
from autonomous_trust.core.queue_pool import QueuePool
from autonomous_trust.core.system import QueueType

from ..metrics.collector import MetricsCollector
from ..simulator import Simulator
from .. import default_port, default_steps
from .appalachian import (
    create_appalachian_config, load_terrain_matrix,
    HILLTOP_NODES, VALLEY_NODES,
)


# Mock network addresses for in-process testing (no real network needed)
_MOCK_ADDRESSES = {
    'ip4': '192.168.1.100/24',
    'ip6': '::1/128',
    'mac': '00:11:22:33:44:55',
    'ip4_subnet': '255.255.255.0',
    'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'mac_bcast': 'ff:ff:ff:ff:ff:ff',
}


def setup_at_root(base_dir):
    """Create a minimal AT config directory with generated identity."""
    cfg_dir = os.path.join(base_dir, 'etc', 'at')
    os.makedirs(cfg_dir, exist_ok=True)
    os.environ[Configuration.ROOT_VARIABLE_NAME] = base_dir
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_MOCK_ADDRESSES):
        generate_identity(cfg_dir, randomize=True, silent=True)
    return cfg_dir


def run_simulator(cfg_file, steps, port, log_level, halt_event):
    """Run the Simulator in a subprocess."""
    try:
        sim = Simulator(cfg_file, max_time_steps=steps, log_level=log_level)
        # Run until halt_event is set
        sim.run(port)
    except Exception as e:
        print('Simulator error: %s' % e, file=sys.stderr)


def run_collector(configurations, subsystems, log_queue, output_path,
                  queues, signal_queue):
    """Run the MetricsCollector in a subprocess."""
    try:
        collector = MetricsCollector(
            configurations, subsystems, log_queue,
            dependencies=None, output_path=output_path)
        collector.process(queues, signal_queue)
    except Exception as e:
        print('MetricsCollector error: %s' % e, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Run Appalachian mesh scenario in-process')
    parser.add_argument('--hilltop-only', action='store_true',
                        help='Only 8 hilltop relay nodes')
    parser.add_argument('--terrain-csv', default=None,
                        help='Path to SPLAT! path-loss CSV')
    parser.add_argument('--freq-mhz', type=float, default=5800.0,
                        help='Frequency from terrain CSV (default: 5800)')
    parser.add_argument('--duration', type=int, default=120,
                        help='Simulation duration in seconds (default: 120)')
    parser.add_argument('--steps', type=int, default=default_steps,
                        help='Simulation time steps (default: %d)' % default_steps)
    parser.add_argument('--output', default='metrics.json',
                        help='Metrics output path (default: metrics.json)')
    parser.add_argument('--log-level', default='info',
                        choices=['debug', 'info', 'warning'],
                        help='Log level (default: info)')
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level.upper())
    logging.basicConfig(level=log_level,
                        format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    logger = logging.getLogger('run_scenario')

    nodes = list(HILLTOP_NODES)
    if not args.hilltop_only:
        nodes.extend(VALLEY_NODES)
    num_nodes = len(nodes)

    logger.info('=== Appalachian Scenario: %d nodes ===' % num_nodes)
    logger.info('Duration: %ds, Steps: %d' % (args.duration, args.steps))
    if args.terrain_csv:
        logger.info('Terrain CSV: %s @ %.0f MHz' % (args.terrain_csv,
                                                      args.freq_mhz))

    # Create temp working directory
    work_dir = tempfile.mkdtemp(prefix='muudd_scenario_')
    logger.info('Work dir: %s' % work_dir)

    try:
        # Step 1: Set up AT config directory
        logger.info('Setting up AT identity configs ...')
        setup_at_root(work_dir)

        # Step 2: Load terrain data if provided
        path_loss_matrix = None
        if args.terrain_csv:
            logger.info('Loading terrain path-loss matrix ...')
            node_names = [name for name, _, _, _ in nodes]
            path_loss_matrix = load_terrain_matrix(
                args.terrain_csv, args.freq_mhz, node_names)
            logger.info('  Loaded %d source nodes' % len(path_loss_matrix))

        # Step 3: Create scenario config
        logger.info('Creating scenario config ...')
        cfg_path = os.path.join(work_dir, 'appalachian.cfg')
        create_appalachian_config(
            output_file=cfg_path,
            duration=timedelta(seconds=args.duration),
            path_loss_matrix=path_loss_matrix,
            hilltop_only=args.hilltop_only,
        )

        # Step 4: Set up multiprocessing
        ctx = multiprocessing.get_context('forkserver')
        manager = ctx.Manager()

        subsystems = ProcessTracker()
        log_queue = manager.Queue()
        configurations = {
            Process.key: [],
            Process.level: log_level,
        }

        # Step 5: Launch Simulator
        logger.info('Launching Simulator on port %d ...' % default_port)
        sim_proc = ctx.Process(
            target=run_simulator,
            args=(cfg_path, args.steps, default_port, log_level, None),
            name='simulator')
        sim_proc.start()
        time.sleep(1)  # let simulator bind

        # Step 6: Launch MetricsCollector
        output_path = os.path.abspath(args.output)
        logger.info('Launching MetricsCollector (output: %s) ...' % output_path)

        collector_queues = {'metrics-collector': manager.Queue()}
        collector_signal = manager.Queue()

        collector_proc = ctx.Process(
            target=run_collector,
            args=(configurations, subsystems, log_queue, output_path,
                  collector_queues, collector_signal),
            name='metrics-collector')
        collector_proc.start()

        # Step 7: Run for duration
        logger.info('Running scenario for %ds ...' % args.duration)
        logger.info('  (Press Ctrl+C to stop early)')

        def handle_sigint(signum, frame):
            logger.info('Interrupted — shutting down ...')
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, handle_sigint)

        try:
            elapsed = 0
            interval = min(10, args.duration)
            while elapsed < args.duration:
                time.sleep(interval)
                elapsed += interval
                if elapsed < args.duration:
                    logger.info('  %ds / %ds ...' % (elapsed, args.duration))
        except KeyboardInterrupt:
            pass

        # Step 8: Shutdown and collect
        logger.info('Shutting down ...')

        # Stop collector — it writes the report on shutdown
        collector_signal.put(Process.sig_quit)
        collector_proc.join(timeout=10)
        if collector_proc.is_alive():
            logger.warning('MetricsCollector did not exit; terminating')
            collector_proc.terminate()

        # Stop simulator
        sim_proc.terminate()
        sim_proc.join(timeout=5)

        # Step 9: Print results
        print()
        print('=' * 60)
        print('SCENARIO RESULTS: %d-node Appalachian mesh' % num_nodes)
        print('=' * 60)

        if os.path.exists(output_path):
            with open(output_path) as f:
                report = json.load(f)
            print(json.dumps(report, indent=2))

            # Check against Phase 2 targets
            print()
            print('--- Target Assessment ---')
            conv = report.get('identity_convergence_s')
            if conv is not None:
                status = 'PASS' if conv < 60.0 else 'FAIL'
                print('Identity convergence: %.1fs (target <60s) [%s]'
                      % (conv, status))
            else:
                print('Identity convergence: no data')

            rep = report.get('reputation_stability_stddev')
            if rep is not None:
                status = 'PASS' if rep < 0.05 else 'FAIL'
                print('Reputation stability: sigma=%.4f (target <0.05) [%s]'
                      % (rep, status))
            else:
                print('Reputation stability: no data')

            rtt = report.get('negotiation_rtt_mean_s')
            if rtt is not None:
                print('Negotiation RTT: %.2fs (N=%d)'
                      % (rtt, report.get('negotiation_rtt_count', 0)))
            else:
                print('Negotiation RTT: no data')

            bw = report.get('bandwidth_overhead_fraction')
            if bw is not None:
                status = 'PASS' if bw < 0.15 else 'FAIL'
                print('Bandwidth overhead: %.1f%% (target <15%%) [%s]'
                      % (bw * 100, status))
            else:
                print('Bandwidth overhead: no data')
        else:
            print('WARNING: No metrics file produced at %s' % output_path)

    finally:
        # Cleanup
        logger.info('Cleaning up %s' % work_dir)
        import shutil
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
