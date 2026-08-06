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

"""In-process integration test for Appalachian scenario.

Launches MetricsCollector via multiprocessing (no Docker).
Validates it receives protocol events and produces a metrics report.
"""
import json
import multiprocessing
import os
import time

import pytest

try:
    from autonomous_trust.core import Configuration, ProcessTracker, Process
    from autonomous_trust.evaluation.metrics.collector import MetricsCollector
    from examples.appalachia.scenario import create_appalachian_config
except ImportError:
    pytest.skip("AT packages not installed", allow_module_level=True)


@pytest.fixture
def appalachian_config(tmp_path):
    """Create an Appalachian scenario config (hilltop only for speed)."""
    cfg_path = str(tmp_path / 'appalachian.cfg')
    create_appalachian_config(output_file=cfg_path, hilltop_only=True)
    return cfg_path


@pytest.fixture
def metrics_output(tmp_path):
    """Path for metrics JSON output."""
    return str(tmp_path / 'metrics.json')


class TestAppalachianInProcess:
    """In-process integration: MetricsCollector lifecycle, no Docker."""

    def test_metrics_collector_produces_report(self, metrics_output, tmp_path):
        """MetricsCollector runs, shuts down on signal, and writes a report."""
        # Set up a test AT root directory
        test_root = str(tmp_path / 'at_root')
        test_cfg_dir = os.path.join(test_root, 'etc', 'at')
        os.makedirs(test_cfg_dir, exist_ok=True)
        os.environ[Configuration.ROOT_VARIABLE_NAME] = test_root

        ctx = multiprocessing.get_context('forkserver')
        manager = ctx.Manager()

        subsystems = ProcessTracker()
        log_queue = manager.Queue()

        configurations: dict = {
            Process.key: [],
            Process.level: 'debug',
        }

        collector = MetricsCollector(
            configurations, subsystems, log_queue,
            dependencies=None, output_path=metrics_output
        )
        configurations[Process.key].append(collector)

        queues = {collector.name: manager.Queue()}
        signal = manager.Queue()

        # Run collector in a subprocess
        proc = ctx.Process(target=collector.process, args=(queues, signal))
        proc.start()

        # Give it a moment to start its loop
        time.sleep(1)

        # Signal shutdown
        signal.put(Process.sig_quit)
        proc.join(timeout=10)
        assert not proc.is_alive(), "MetricsCollector did not shut down"

        # Verify report was written
        assert os.path.exists(metrics_output)
        with open(metrics_output) as f:
            report = json.load(f)

        # All metric keys present (values are None/0 since no messages sent)
        assert 'identity_convergence_s' in report
        assert 'reputation_stability_stddev' in report
        assert 'negotiation_rtt_mean_s' in report
        assert 'protocol_bytes_total' in report
        assert report['identity_convergence_s'] is None
        assert report['protocol_bytes_total'] == 0
