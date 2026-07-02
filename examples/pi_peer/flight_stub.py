# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Drone-shaped behavior for a C ``at_demo`` microdrone (Stretch Goal 3, Path B).

The C node runs the trust fabric; this stub supplies the ISR *data* it streams.
It reuses the exact same generator bundle the Python ``participant.py`` binds for
a ``microdrone`` role — ``MicrodroneGenerators`` (target position + motion +
audio) plus the rich ``DetectionSource`` (crop_b64 / bbox / target_latlon /
heartbeat) — so a C microdrone is indistinguishable from a Python one in the
coordinator's sensor-comparison and inspector detection dashboards.

Each ``tick()`` returns a list of ``Reading.to_dict()`` dicts; the launcher
(``pi_peer_main.py``) JSON-encodes the batch and streams it to the C node's
``--ingest-readings`` AF_UNIX socket. Pose is replayed locally on the shared
``AT_DEMO_T0_EPOCH`` clock (mirroring participant._detection_pose_provider) so
FOV/visibility timing lines up with the rest of the scenario.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import Callable, Optional
from uuid import uuid4

# Dashed-package layout: import the dod_mission generators by bare name, the
# same trick participant.py uses (examples/dod_mission/{scenario,generators}).
_DOD = Path(__file__).resolve().parent.parent / "dod_mission"
sys.path.insert(0, str(_DOD))
sys.path.insert(0, str(_DOD / "generators"))

from scenario import DoDMissionScenario  # noqa: E402
from isr import MicrodroneGenerators  # noqa: E402
from detection import (  # noqa: E402
    build_detection_source, DETECTION_VIEW_CENTER_OVERRIDE,
)

logger = logging.getLogger(__name__)


def scenario_from_env() -> DoDMissionScenario:
    """Build the scenario from the same env knobs participant.py reads, so the
    stub agrees with the coordinator on the peer roster + geometry."""
    return DoDMissionScenario(
        squad_size=int(os.environ.get("AT_SQUAD_SIZE", "4")),
        swarm_size=int(os.environ.get("AT_SWARM_SIZE", "4")),
        sensor_count=int(os.environ.get("AT_SENSOR_COUNT", "3")),
        hacked_sensors=int(os.environ.get("AT_HACKED_SENSORS", "2")),
        include_mq800=os.environ.get("AT_INCLUDE_MQ800", "1") != "0",
        include_jet=os.environ.get("AT_INCLUDE_JET", "1") != "0",
        include_command=os.environ.get("AT_INCLUDE_COMMAND", "1") != "0",
    )


def _make_pose_provider(scenario: DoDMissionScenario, peer_name: str,
                        t0_epoch: float) -> Callable[[], Optional[tuple]]:
    """Replay this microdrone's deterministic scenario path to a live (lat,lon).

    Mirrors participant._detection_pose_provider: ``_update_positions`` is pure
    movement (no phase side effects); we read our own role's position. Driven by
    the shared demo clock so the forward FOV sweeps onto the objective on the
    same timeline the readings are stamped against.
    """
    def _pose():
        try:
            t = timedelta(seconds=time.time() - t0_epoch)
            scenario._update_positions(t)  # noqa: SLF001
            role = scenario.peers.get(peer_name)
            pos = getattr(role, "position", None)
            if pos is None:
                return None
            return (pos.lat, pos.lon)
        except Exception:  # a flaky pose source must never crash the stream
            logger.debug("pose provider failed for %s", peer_name, exc_info=True)
            return None
    return _pose


class FlightStub:
    """Builds a microdrone generator bundle and ticks it to Reading dicts."""

    def __init__(self, peer_name: str, scenario: Optional[DoDMissionScenario] = None,
                 t0_epoch: Optional[float] = None):
        self.peer_name = peer_name
        self.scenario = scenario or scenario_from_env()
        self.role = self.scenario.peers.get(peer_name)
        if self.role is None:
            raise ValueError(f"{peer_name!r} not in scenario {self.scenario.name!r}")
        if self.role.kind != "microdrone":
            logger.warning("flight stub built for non-microdrone role %s (%s)",
                           peer_name, self.role.kind)
        self.t0_epoch = float(t0_epoch if t0_epoch is not None
                              else (os.environ.get("AT_DEMO_T0_EPOCH") or time.time()))

        sensor_xy = (self.role.position.lat, self.role.position.lon)
        self._bundle = MicrodroneGenerators(peer_name, sensor_xy)

        # Rich detection channel (full fidelity: crop_b64 / bbox / heartbeat),
        # gated to this peer's join time, with live pose so visibility tracks
        # the drone's advance. Silently None if the catalogue isn't present.
        arrival_sec = 0.0
        jp = getattr(self.role, "join_phase", 0)
        phases = getattr(self.scenario, "_phases", None)
        if jp and phases and 0 <= jp < len(phases):
            arrival_sec = phases[jp].start.total_seconds()
        self._detection = build_detection_source(
            peer_name=peer_name,
            role="microdrone",
            roster_latlon=sensor_xy,
            view_center_override_latlon=DETECTION_VIEW_CENTER_OVERRIDE.get(peer_name),
            active_after_sec=arrival_sec,
            pose_provider=_make_pose_provider(self.scenario, peer_name, self.t0_epoch),
        )
        if self._detection is None:
            logger.warning("no detection catalogue for %s; streaming sensors only",
                           peer_name)

    def tick(self) -> list[dict]:
        """Return this tick's Readings as dicts (Reading.to_dict() shape)."""
        t = timedelta(seconds=time.time() - self.t0_epoch)
        readings = list(self._bundle.tick(t) or [])
        if self._detection is not None:
            readings.extend(self._detection.tick(t) or [])
        dicts = [r.to_dict() for r in readings]
        # Stamp every reading in this batch with the same task_id, exactly as
        # the Python producer does (dod_mission/participant.py
        # DoDDataProcess.acquire). The coordinator reads this task_id from the
        # reading metadata to submit its verdict-side TransactionScore; the C
        # node submits the paired producer-side 0.9 TS on the SAME task_id
        # (data_source_proc.c). The two halves form the bilateral Transaction
        # that lets this C microdrone earn reputation. Without the stamp the
        # coordinator hits its "NO task_id" branch and the drone never scores.
        batch_id = str(uuid4())
        for d in dicts:
            meta = d.setdefault("metadata", {})
            meta["task_id"] = batch_id
        return dicts
