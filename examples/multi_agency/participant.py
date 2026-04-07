"""
Civilian demo participant node.

Each sensor peer (NOAA, USGS, EPA) runs as an instance of this class.
It inherits from AutonomousTrust and registers data-source workers
based on the peer's agency and capabilities.

Usage:
    python participant.py <peer-name> [--setup] [--log-level debug]

The peer name determines which data generators are attached.
"""

from __future__ import annotations

import os
import re
import sys
import time
import random
import logging
from pathlib import Path

from autonomous_trust.core import AutonomousTrust, Configuration, LogLevel
from autonomous_trust.core.config.generate import generate_identity, generate_worker_config
from autonomous_trust.services.data.server import DataProcess, DataConfig
from autonomous_trust.services.network_statistics import NetStatsSource

try:
    from autonomous_trust.simulator.peer.peer_metadata import SimMetadataSource, SimMetadata
    HAS_SIMULATOR = True
except ImportError:
    HAS_SIMULATOR = False

logger = logging.getLogger(__name__)


class CivilianParticipant(AutonomousTrust):
    """An AT node for the civilian disaster response demo."""

    def __init__(self, peer_name: str, agency: str, **kwargs):
        self.peer_name = peer_name
        self.agency = agency
        super().__init__(silent=True, **kwargs)

        # Always add network stats
        self.add_worker(NetStatsSource)

        # Simulator metadata source (if simulator package available)
        if HAS_SIMULATOR:
            self.add_worker(SimMetadataSource)

        # Data source for sensor readings
        self.add_worker(DataProcess)

    def autonomous_tasking(self, queues):
        """Called each tick by the AT event loop."""
        pass  # Data generation handled by DataProcess worker


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <peer-name> [--setup] [--log-level LEVEL]")
        sys.exit(1)

    peer_name = sys.argv[1]
    agency = os.environ.get("AT_AGENCY", "unknown")
    setup_mode = "--setup" in sys.argv
    log_level = LogLevel.DEBUG

    for i, arg in enumerate(sys.argv):
        if arg == "--log-level" and i + 1 < len(sys.argv):
            log_level = LogLevel[sys.argv[i + 1].upper()]

    # Per-peer root directory
    root_dir = os.environ.get("AUTONOMOUS_TRUST_ROOT",
                              str(Path(__file__).parent / peer_name))
    os.environ["AUTONOMOUS_TRUST_ROOT"] = root_dir
    os.makedirs(os.path.join(root_dir, "etc", "at"), exist_ok=True)
    os.makedirs(os.path.join(root_dir, "var", "at"), exist_ok=True)

    # Generate identity (preserves existing keys)
    generate_identity(preserve=True)

    if setup_mode:
        generate_worker_config(DataProcess, DataConfig)
        if HAS_SIMULATOR:
            generate_worker_config(SimMetadataSource, SimMetadata)
        print(f"Setup complete for {peer_name}")
        return

    # Stagger startup to avoid thundering herd
    delay_sec = int(os.environ.get("AT_JOIN_DELAY_SEC", "0"))
    if delay_sec > 0:
        logger.info("Delaying startup by %ds (AT_JOIN_DELAY_SEC)", delay_sec)
        time.sleep(delay_sec)
    else:
        time.sleep(random.uniform(1, 5))

    logger.info("Starting civilian participant: %s (%s)", peer_name, agency)
    participant = CivilianParticipant(peer_name, agency, log_level=log_level)
    participant.run_forever()


if __name__ == "__main__":
    main()
