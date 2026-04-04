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

Launches the Simulator via multiprocessing.  For full AT protocol
testing with metrics collection, use ``test-simulation-scenarios.sh`` which runs
Docker containers with the instrumented AT entry point.

This script is useful for testing the Simulator and terrain-aware RF
layer without needing Docker or a real network.

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

from ..simulator import Simulator
from .. import default_port, default_steps
from .appalachian import (
    create_appalachian_config, load_terrain_matrix,
    HILLTOP_NODES, VALLEY_NODES,
)


def run_simulator(cfg_file, steps, port, log_level, halt_event):
    """Run the Simulator in a subprocess."""
    try:
        sim = Simulator(cfg_file, max_time_steps=steps, log_level=log_level)
        sim.run(port)
    except Exception as e:
        print('Simulator error: %s' % e, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Run Appalachian mesh scenario in-process (simulator only)')
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
        # Step 1: Load terrain data if provided
        path_loss_matrix = None
        if args.terrain_csv:
            logger.info('Loading terrain path-loss matrix ...')
            node_names = [name for name, _, _, _ in nodes]
            path_loss_matrix = load_terrain_matrix(
                args.terrain_csv, args.freq_mhz, node_names)
            logger.info('  Loaded %d source nodes' % len(path_loss_matrix))

        # Step 2: Create scenario config
        logger.info('Creating scenario config ...')
        cfg_path = os.path.join(work_dir, 'appalachian.cfg')
        create_appalachian_config(
            output_file=cfg_path,
            duration=timedelta(seconds=args.duration),
            path_loss_matrix=path_loss_matrix,
            hilltop_only=args.hilltop_only,
        )

        # Step 3: Launch Simulator
        ctx = multiprocessing.get_context('forkserver')
        logger.info('Launching Simulator on port %d ...' % default_port)
        sim_proc = ctx.Process(
            target=run_simulator,
            args=(cfg_path, args.steps, default_port, log_level, None),
            name='simulator')
        sim_proc.start()

        # Step 4: Run for duration
        logger.info('Running simulator for %ds ...' % args.duration)
        logger.info('  (Press Ctrl+C to stop early)')
        logger.info('')
        logger.info('NOTE: For full AT protocol metrics, use test-simulation-scenarios.sh')
        logger.info('      which runs Docker containers with instrumented AT nodes.')

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

        # Step 5: Shutdown
        logger.info('Shutting down ...')
        sim_proc.terminate()
        sim_proc.join(timeout=5)

        logger.info('Simulator run complete.')

    finally:
        logger.info('Cleaning up %s' % work_dir)
        import shutil
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
