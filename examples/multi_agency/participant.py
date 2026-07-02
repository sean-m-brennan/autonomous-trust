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

"""
Multi-agency demo participant node.

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
from autonomous_trust.core.system import queue_cadence
from autonomous_trust.services.data.server import DataProcess, DataConfig
from autonomous_trust.services.network_statistics import NetStatsSource

try:
    from autonomous_trust.simulator.peer.peer_metadata import SimMetadataSource, SimMetadata
    HAS_SIMULATOR = True
except ImportError:
    HAS_SIMULATOR = False

# Sibling-module access for script invocation (`python participant.py`).
# Mirrors the dod_mission participant — lets `register_trust_ladder` be
# imported by bare name from the same directory.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

logger = logging.getLogger(__name__)


class MultiAgencyParticipant(AutonomousTrust):
    """An AT node for the multi-agency disaster response demo."""

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

    def autonomous_ability(self, queues):
        """Advertise this peer's data capability + trust-ladder caps.

        Mirrors ``DoDMissionParticipant.autonomous_ability``: register
        the abilities on ``self.capabilities``, then push the populated
        Capabilities object onto every worker queue so DataRcvr /
        idprocess in sibling subprocesses learn what this peer offers.
        Without the broadcast, the coordinator never subscribes to this
        peer's data stream and tier-weight metadata never reaches the
        reputation process.
        """
        self.capabilities.register_ability(
            DataProcess.capability_name, None)
        # `participant.py` is invoked as a script, and _HERE is on
        # sys.path (top of module) — bare-name import works.
        from trust_ladder import register_trust_ladder  # local import
        self._trust_ladder = register_trust_ladder(self.capabilities)
        logger.info(
            "autonomous_ability: peer=%s capabilities=%s — "
            "broadcasting to %d worker queue(s)",
            self.peer_name, self.capabilities.to_list(),
            len([q for q in queues if q != self.proc_name]))
        for q_name in queues:
            if q_name == self.proc_name:
                continue
            try:
                queues[q_name].put(self.capabilities,
                                   block=True, timeout=queue_cadence)
            except Exception:
                logger.warning("Failed to publish capabilities to %s",
                               q_name)

    def autonomous_tasking(self, queues):
        """Called each tick by the AT event loop."""
        pass  # Data generation handled by DataProcess worker


def main():
    # See examples/dod_mission/coordinator.py:main() — AT only handler-
    # binds its own framework logger, so this module's `logger.info(...)`
    # is otherwise dropped by Python's lastResort handler.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

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

    # Per-peer root directory.  AT derives etc/at + var/at from
    # AUTONOMOUS_TRUST_ROOT.  generate_identity needs cfg_dir explicitly.
    root_dir = os.environ.get(Configuration.ROOT_VARIABLE_NAME,
                              str(Path(__file__).parent / peer_name))
    os.environ[Configuration.ROOT_VARIABLE_NAME] = root_dir
    cfg_dir = Configuration.get_cfg_dir()
    dat_dir = Configuration.get_data_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    os.makedirs(dat_dir, exist_ok=True)

    # Generate identity (preserves existing keys)
    generate_identity(cfg_dir, preserve=True, defaults=True)

    if setup_mode:
        # generate_worker_config(cfg_dir, proc_name, cfg_class, defaults)
        generate_worker_config(cfg_dir, DataProcess.name, DataConfig, True)
        if HAS_SIMULATOR:
            generate_worker_config(cfg_dir, SimMetadataSource.name, SimMetadata, True)
        print(f"Setup complete for {peer_name}")
        return

    # Stagger startup to avoid thundering herd
    delay_sec = int(os.environ.get("AT_JOIN_DELAY_SEC", "0"))
    if delay_sec > 0:
        logger.info("Delaying startup by %ds (AT_JOIN_DELAY_SEC)", delay_sec)
        time.sleep(delay_sec)
    else:
        time.sleep(random.uniform(1, 5))

    logger.info("Starting multi-agency participant: %s (%s)", peer_name, agency)
    participant = MultiAgencyParticipant(peer_name, agency, log_level=log_level)
    participant.run_forever()


if __name__ == "__main__":
    # Default to forkserver: 'fork' (Linux default through 3.13) forks a
    # multi-threaded process and can deadlock the child. Harmless on 3.14+.
    import multiprocessing as _mp
    _mp.set_start_method('forkserver', force=True)
    main()
