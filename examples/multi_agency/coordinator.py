"""
Civilian demo coordinator / inspector node.

Aggregates data from all participants, runs the dashboard with
demo-specific panels (trust timeline, sensor comparison, event log),
manages scenario playback, and records events for canned replay.

Usage:
    python coordinator.py [--setup] [--log-level debug]
                          [--record FILE] [--compromise-mode gradual|abrupt]
"""

from __future__ import annotations

import os
import sys
import queue
import json
import logging
import threading
from pathlib import Path
from datetime import timedelta

from autonomous_trust.core import AutonomousTrust, LogLevel, CfgIds, Process, ProcMeta
from autonomous_trust.core.config.generate import generate_identity, generate_worker_config
from autonomous_trust.core.system import queue_cadence
from autonomous_trust.core.reputation.protocol import ReputationProtocol

try:
    from autonomous_trust.inspector.peer.daq import Cohort, CohortTracker
    HAS_INSPECTOR = True
except ImportError:
    HAS_INSPECTOR = False

try:
    from autonomous_trust.services.data.client import DataRcvr
    HAS_DATA = True
except ImportError:
    HAS_DATA = False

logger = logging.getLogger(__name__)


class CivilianCoordinator(AutonomousTrust):
    """Coordinator node for the civilian disaster response demo.

    Extends AutonomousTrust with:
    - Peer cohort tracking (for dashboard)
    - Reputation monitoring (for trust timeline)
    - Data aggregation (for sensor comparison)
    - Scenario event recording (for canned playback)
    """

    def __init__(self, record_path: str | None = None,
                 compromise_mode: str = "abrupt", **kwargs):
        self.data_queue: queue.Queue = queue.Queue()
        self._record_path = record_path
        self._compromise_mode = compromise_mode
        self._reputation_cache: dict[str, float] = {}
        self._tick_count = 0

        super().__init__(silent=True, **kwargs)

        # Peer tracking
        if HAS_INSPECTOR:
            self._cohort = Cohort()
            self.add_worker(CohortTracker, cohort=self._cohort)

        # Data receiver (aggregates sensor readings from participants)
        if HAS_DATA:
            self.add_worker(DataRcvr)

    def init_tasking(self, queues):
        """Called once before the main loop starts."""
        logger.info("Civilian coordinator starting (compromise_mode=%s)",
                    self._compromise_mode)

        if self._record_path:
            logger.info("Recording events to %s", self._record_path)

    def autonomous_tasking(self, queues):
        """Called each tick — monitors reputation, feeds dashboard."""
        self._tick_count += 1

        # Query reputation every 30 seconds (60 ticks at 500ms cadence)
        if self._tick_count % 60 == 0:
            self._query_reputations(queues)

        # Push updates to dashboard every 5 seconds (10 ticks)
        if self._tick_count % 10 == 0:
            self._push_dashboard_update()

    def _query_reputations(self, queues):
        """Request reputation scores for all known peers."""
        try:
            for peer in self.peers:
                rep = self.query_reputation(peer)
                if rep is not None:
                    name = getattr(peer, 'nickname', str(peer))
                    self._reputation_cache[name] = rep
        except Exception:
            logger.debug("Reputation query failed (may be too early)")

    def _push_dashboard_update(self):
        """Push current state to the data queue for dashboard consumption."""
        state = {
            "reputations": dict(self._reputation_cache),
            "tick": self._tick_count,
        }
        try:
            self.data_queue.put_nowait(("state", state))
        except queue.Full:
            pass

    def cleanup(self):
        """Graceful shutdown."""
        logger.info("Civilian coordinator shutting down")


def main():
    setup_mode = "--setup" in sys.argv
    record_path = None
    compromise_mode = "abrupt"
    log_level = LogLevel.DEBUG

    for i, arg in enumerate(sys.argv):
        if arg == "--log-level" and i + 1 < len(sys.argv):
            log_level = LogLevel[sys.argv[i + 1].upper()]
        elif arg == "--record" and i + 1 < len(sys.argv):
            record_path = sys.argv[i + 1]
        elif arg == "--compromise-mode" and i + 1 < len(sys.argv):
            compromise_mode = sys.argv[i + 1]

    root_dir = os.environ.get("AUTONOMOUS_TRUST_ROOT",
                              str(Path(__file__).parent / "coordinator"))
    os.environ["AUTONOMOUS_TRUST_ROOT"] = root_dir
    os.makedirs(os.path.join(root_dir, "etc", "at"), exist_ok=True)
    os.makedirs(os.path.join(root_dir, "var", "at"), exist_ok=True)

    generate_identity(preserve=True)

    if setup_mode:
        if HAS_DATA:
            from autonomous_trust.services.data.client import DataConfig
            generate_worker_config(DataRcvr, DataConfig)
        if HAS_INSPECTOR:
            generate_worker_config(CohortTracker)
        print("Setup complete for coordinator")
        return

    logger.info("Starting civilian coordinator")
    coordinator = CivilianCoordinator(
        record_path=record_path,
        compromise_mode=compromise_mode,
        log_level=log_level,
    )
    coordinator.run_forever()


if __name__ == "__main__":
    main()
