"""
Multi-agency demo coordinator / inspector node.

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

from autonomous_trust.core import AutonomousTrust, Configuration, LogLevel, CfgIds, Process, ProcMeta
from autonomous_trust.core.config.generate import generate_identity, generate_worker_config
from autonomous_trust.core.system import queue_cadence, now
from autonomous_trust.core.reputation.protocol import ReputationProtocol

try:
    from autonomous_trust.inspector.peer.daq import Cohort, CohortTracker
    HAS_INSPECTOR = True
except ImportError as _exc:
    # Silent degradation here makes `_drain_peer_readings` a no-op and
    # readings never reach the coordinator. Surface the cause at
    # module-import time on stderr (logger isn't configured yet).
    print(
        f"[multi_agency.coordinator] HAS_INSPECTOR=False — "
        f"autonomous_trust.inspector.peer.daq import failed: "
        f"{type(_exc).__name__}: {_exc}",
        file=sys.stderr, flush=True,
    )
    HAS_INSPECTOR = False

try:
    from autonomous_trust.services.data.client import DataRcvr
    HAS_DATA = True
except ImportError as _exc:
    print(
        f"[multi_agency.coordinator] HAS_DATA=False — "
        f"autonomous_trust.services.data.client import failed: "
        f"{type(_exc).__name__}: {_exc}",
        file=sys.stderr, flush=True,
    )
    HAS_DATA = False

# Dashboard imports — PYTHONPATH=/app:... in the demo image (see
# deploy/Dockerfile), so the package-qualified imports work directly.
from examples.multi_agency.scenario import DisasterResponseScenario  # noqa: E402
from examples.multi_agency.dashboard.multi_agency_app import (  # noqa: E402
    build_dashboard,
)
from examples.multi_agency.dashboard import live_server  # noqa: E402

logger = logging.getLogger(__name__)


class MultiAgencyCoordinator(AutonomousTrust):
    """Coordinator node for the multi-agency disaster response demo.

    Extends AutonomousTrust with:
    - Peer cohort tracking (for dashboard)
    - Reputation monitoring (for trust timeline)
    - Data aggregation (for sensor comparison)
    - Scenario event recording (for canned playback)
    """

    def __init__(self, scenario: DisasterResponseScenario,
                 record_path: str | None = None,
                 compromise_mode: str = "abrupt",
                 dashboard_port: int = 8050,
                 **kwargs):
        self.scenario = scenario
        self.data_queue: queue.Queue = queue.Queue()
        self._record_path = record_path
        self._compromise_mode = compromise_mode
        self._dashboard_port = dashboard_port
        self._reputation_cache: dict[str, float] = {}
        self._tick_count = 0
        self._latest_state: dict = {"reputations": {}, "tick": 0, "phase": None}

        self._panels = build_dashboard(scenario)

        super().__init__(silent=True, **kwargs)

        # Peer tracking
        if HAS_INSPECTOR:
            self._cohort = Cohort(self.queue_pool)
            self.add_worker(CohortTracker, cohort=self._cohort)

        # DataRcvr.handle_data dispatches into cohort.peers, so the
        # inspector cohort must exist before we register it.
        if HAS_DATA and HAS_INSPECTOR:
            self.add_worker(DataRcvr, cohort=self._cohort)

    def init_tasking(self, queues):
        """Called once before the main loop starts."""
        logger.info("Multi-agency coordinator starting (compromise_mode=%s)",
                    self._compromise_mode)

        if self._record_path:
            logger.info("Recording events to %s", self._record_path)
        live_server.start_in_thread(
            name="examples.multi_agency.coordinator",
            title=self.scenario.name,
            panels=self._panels,
            chart_keys=["temperature_chart", "wind_chart"],
            state_provider=lambda: self._latest_state,
            port=self._dashboard_port,
        )
        logger.info("Dashboard serving on :%d", self._dashboard_port)

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
                    self._feed_timeline(name, rep)
        except Exception:
            logger.debug("Reputation query failed (may be too early)")

    def _feed_timeline(self, peer_name: str, score: float) -> None:
        try:
            t = (now() - self.tasking_start).total_seconds()
        except Exception:
            t = self._tick_count * 0.5
        live_server.feed_timeline_sample(
            self._panels, t_seconds=t, peer_name=peer_name, score=score)

    def _push_dashboard_update(self):
        """Push current state to the data queue for dashboard consumption."""
        self._latest_state = {
            "reputations": dict(self._reputation_cache),
            "tick": self._tick_count,
            "phase": (self.scenario.current_phase.name
                      if self.scenario.current_phase else None),
        }
        try:
            self.data_queue.put_nowait(("state", self._latest_state))
        except queue.Full:
            pass

    def cleanup(self):
        """Graceful shutdown."""
        logger.info("Multi-agency coordinator shutting down")


def main():
    # AT's Automaton attaches its StreamHandler only to a logger named
    # after its own class, not to root.  Without basicConfig here,
    # `logger = getLogger(__name__)` above has no handler in its chain
    # and `logger.info(...)` falls to Python's lastResort (WARNING/stderr),
    # silently dropping every diagnostic line below WARNING.  See
    # examples/dod_mission/coordinator.py:main() for the long version.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

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

    # AT derives etc/at + var/at from AUTONOMOUS_TRUST_ROOT.  generate_identity
    # requires cfg_dir as a positional arg (see mission/coordinator.py).
    root_dir = os.environ.get(Configuration.ROOT_VARIABLE_NAME,
                              str(Path(__file__).parent / "coordinator"))
    os.environ[Configuration.ROOT_VARIABLE_NAME] = root_dir
    cfg_dir = Configuration.get_cfg_dir()
    dat_dir = Configuration.get_data_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    os.makedirs(dat_dir, exist_ok=True)

    generate_identity(cfg_dir, preserve=True, defaults=True)

    if setup_mode:
        # generate_worker_config(cfg_dir, proc_name, cfg_class, defaults)
        if HAS_DATA:
            from autonomous_trust.services.data.client import DataConfig
            generate_worker_config(cfg_dir, DataRcvr.name, DataConfig, True)
        # CohortTracker has no separate InitializableConfig; AT uses defaults.
        print("Setup complete for coordinator")
        return

    logger.info("Starting multi-agency coordinator")
    scenario = DisasterResponseScenario()
    coordinator = MultiAgencyCoordinator(
        scenario=scenario,
        record_path=record_path,
        compromise_mode=compromise_mode,
        log_level=log_level,
    )
    coordinator.run_forever()


if __name__ == "__main__":
    main()
