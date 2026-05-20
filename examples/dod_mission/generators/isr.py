# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""ISR data generators for overhead drones and the microdrone swarm.

Overhead platforms (RQ-86, MQ-800) and the closer-in microdrone swarm
all track the same target.  When they're honest, their position
reports agree within sensor noise (a few meters in x/y).  When the
MQ-800 is compromised, its position reports are offset by tens of
meters — easily caught by the cross-source position validator in
../tasks/validation.py.

Coordinates are local-frame meters (origin = squad insertion point).
Conversion back to lat/lon for the dashboard happens at the
coordinator; staying in meters here lets us reason about absolute
position error in the same units the validator uses.

Generator inventory:
  TargetPositionX / TargetPositionY:  Target's local (x, y) in meters
  TargetBearingGenerator:             Bearing from sensor to target (deg)
  ElectronicNoiseGenerator:           RF noise floor in dB (RQ-86 sentinel
                                      for unannounced platforms entering)
  MotionIntensityGenerator:           Microdrone scalar motion-detection
                                      output (used by recon_sweep)
  AudioLevelGenerator:                Microdrone audio level (dB)

Convenience bundles:
  OverheadISRGenerators:  All target-tracking generators for an RQ-86 / MQ-800
  MicrodroneGenerators:   Sensor bundle for a microdrone
"""

from __future__ import annotations

import math
import random
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading
from autonomous_trust.evaluation.generators import (
    DataGenerator, SinusoidalGenerator, RandomWalkGenerator,
)


# Target ground-truth path (local-frame meters from squad insertion point).
# The target sits ~2 km north-by-northwest of insertion and drifts slowly
# south-southeast as the scenario progresses — a mobile vehicle the squad
# is converging on.  GROUND_START → GROUND_MID in scenario.py covers ~2 km;
# we use a similar offset here.
_TARGET_START_X = -550.0   # meters east of insertion (negative = west)
_TARGET_START_Y = +1980.0  # meters north of insertion
_TARGET_DRIFT_MPS_X = 0.4  # slow eastward drift
_TARGET_DRIFT_MPS_Y = -0.3 # slow southward drift


def _target_true_xy(t: timedelta) -> tuple[float, float]:
    """Ground-truth target (x, y) at scenario time t."""
    secs = t.total_seconds()
    x = _TARGET_START_X + _TARGET_DRIFT_MPS_X * secs
    y = _TARGET_START_Y + _TARGET_DRIFT_MPS_Y * secs
    return x, y


# --- Target position (cross-source validated) -----------------------

class TargetPositionXGenerator(DataGenerator):
    """Reports the target's local-frame x coordinate (meters).

    Each overhead platform produces its own slightly-noisy estimate.
    Honest sensors agree within ~5 m; the position validator's
    threshold is 50 m, so the MQ-800's compromise (offset 80 m+) trips
    it within one or two cadence ticks.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None,
                 cadence_sec: float = 1.0):
        super().__init__(
            peer_name=peer_name,
            data_type="target_position_x",
            unit="m",
            cadence_sec=cadence_sec,
            noise_stddev=2.0,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        x, _ = _target_true_xy(t)
        return x


class TargetPositionYGenerator(DataGenerator):
    """Reports the target's local-frame y coordinate (meters)."""

    def __init__(self, peer_name: str, seed: Optional[int] = None,
                 cadence_sec: float = 1.0):
        super().__init__(
            peer_name=peer_name,
            data_type="target_position_y",
            unit="m",
            cadence_sec=cadence_sec,
            noise_stddev=2.0,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        _, y = _target_true_xy(t)
        return y


class TargetBearingGenerator(DataGenerator):
    """Bearing from sensor position to target (degrees, 0=N, 90=E).

    Computed against the target ground truth.  Each peer's bearing
    will differ because the peers are at different positions — this
    is NOT a cross-source validation target.  Useful for triangulation
    tasks instead.
    """

    def __init__(self, peer_name: str, sensor_xy: tuple[float, float],
                 seed: Optional[int] = None, cadence_sec: float = 2.0):
        super().__init__(
            peer_name=peer_name,
            data_type="target_bearing_deg",
            unit="deg",
            cadence_sec=cadence_sec,
            noise_stddev=1.5,
            seed=seed,
        )
        self.sensor_x, self.sensor_y = sensor_xy

    def _generate_value(self, t: timedelta) -> float:
        tx, ty = _target_true_xy(t)
        dx = tx - self.sensor_x
        dy = ty - self.sensor_y
        bearing = math.degrees(math.atan2(dx, dy))
        # Normalize to 0-360
        return bearing % 360.0


# --- Electronic noise (RQ-86 sentinel) ------------------------------

class ElectronicNoiseGenerator(DataGenerator):
    """RF noise floor in dB seen by an overhead platform.

    Baseline ~35 dB.  When the MQ-800 arrives at T+4:00, the noise
    floor spikes by ~25 dB across all overhead platforms — a tell
    that something high-power is in the area.  RQ-86s report this
    correctly; the compromised MQ-800 will under-report it (it knows
    where the noise is coming from and is trying to mask).

    Used by the electronic-noise validator: divergence between
    RQ-86's reading and MQ-800's reading is itself a trust signal.
    """

    BASELINE_DB = 35.0
    MQ800_ARRIVAL_SEC = 4 * 60     # phase 4: rogue
    SPIKE_DB = 25.0
    SPIKE_RAMP_SEC = 30.0          # smooth ramp, not a step

    def __init__(self, peer_name: str, seed: Optional[int] = None,
                 cadence_sec: float = 3.0):
        super().__init__(
            peer_name=peer_name,
            data_type="electronic_noise_db",
            unit="dB",
            cadence_sec=cadence_sec,
            noise_stddev=1.5,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        secs = t.total_seconds()
        ramp_progress = (secs - self.MQ800_ARRIVAL_SEC) / self.SPIKE_RAMP_SEC
        ramp = max(0.0, min(1.0, ramp_progress))
        return self.BASELINE_DB + self.SPIKE_DB * ramp


# --- Microdrone-level sensors ---------------------------------------

class MotionIntensityGenerator(RandomWalkGenerator):
    """Scalar motion-detection magnitude from a microdrone's video.

    Ramps up as the squad nears the target — more activity in frame.
    Not cross-source validated.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None,
                 cadence_sec: float = 2.0):
        super().__init__(
            peer_name=peer_name,
            data_type="motion_intensity",
            unit="",
            mean=0.2,
            step_size=0.05,
            bounds=(0.0, 1.0),
            trend=0.0,
            cadence_sec=cadence_sec,
            noise_stddev=0.03,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        # Ramp mean from 0.2 to 0.7 over the first 4 minutes
        progress = min(t.total_seconds() / 240.0, 1.0)
        self.mean = 0.2 + 0.5 * progress
        return super()._generate_value(t)


class AudioLevelGenerator(RandomWalkGenerator):
    """Microdrone audio level (dB, A-weighted)."""

    def __init__(self, peer_name: str, seed: Optional[int] = None,
                 cadence_sec: float = 2.0):
        super().__init__(
            peer_name=peer_name,
            data_type="audio_level_db",
            unit="dB",
            mean=42.0,
            step_size=2.0,
            bounds=(30.0, 95.0),
            trend=0.0,
            cadence_sec=cadence_sec,
            noise_stddev=1.0,
            seed=seed,
        )


# --- Convenience bundles --------------------------------------------

class OverheadISRGenerators:
    """All generators an overhead platform (RQ-86 or MQ-800) runs.

    Includes target position (cross-validated), electronic noise
    (cross-validated), and bearing (used by triangulate tasks).
    The compromise wrapper in ../compromise/contradictory_isr.py wraps
    the position generators to corrupt their output after activation.
    """

    def __init__(self, peer_name: str, sensor_xy: tuple[float, float],
                 seed: Optional[int] = None):
        base = seed if seed is not None else hash(peer_name) & 0xFFFF
        self.target_x = TargetPositionXGenerator(peer_name, seed=base)
        self.target_y = TargetPositionYGenerator(peer_name, seed=base + 1)
        self.bearing = TargetBearingGenerator(peer_name, sensor_xy, seed=base + 2)
        self.electronic_noise = ElectronicNoiseGenerator(peer_name, seed=base + 3)
        self._generators = [
            self.target_x, self.target_y, self.bearing, self.electronic_noise,
        ]

    def tick(self, t: timedelta) -> list[Reading]:
        return [r for r in (g.tick(t) for g in self._generators) if r is not None]


class MicrodroneGenerators:
    """Sensor bundle for a microdrone.

    Microdrones also produce a target_position estimate (less precise
    than overhead, but they're closer in) so they participate in
    cross-source validation.  Motion and audio are local readings
    used by the recon_sweep task.
    """

    def __init__(self, peer_name: str, sensor_xy: tuple[float, float],
                 seed: Optional[int] = None):
        base = seed if seed is not None else hash(peer_name) & 0xFFFF
        # Microdrone position readings are noisier than overhead (closer
        # but less stabilization), so seed with a separate stream and
        # let the validator's threshold absorb the looser tolerance.
        self.target_x = TargetPositionXGenerator(peer_name, seed=base,
                                                 cadence_sec=2.0)
        self.target_x.noise_stddev = 4.0
        self.target_y = TargetPositionYGenerator(peer_name, seed=base + 1,
                                                 cadence_sec=2.0)
        self.target_y.noise_stddev = 4.0
        self.motion = MotionIntensityGenerator(peer_name, seed=base + 2)
        self.audio = AudioLevelGenerator(peer_name, seed=base + 3)
        self._generators = [self.target_x, self.target_y, self.motion, self.audio]

    def tick(self, t: timedelta) -> list[Reading]:
        return [r for r in (g.tick(t) for g in self._generators) if r is not None]
