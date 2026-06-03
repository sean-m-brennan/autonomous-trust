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
import os
import random
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading
from autonomous_trust.evaluation.generators import (
    DataGenerator, SinusoidalGenerator, RandomWalkGenerator,
)


# Target ground-truth path (local-frame meters from squad insertion point).
# The target sits ~1.9 km north and ~390 m west of insertion and drifts
# slowly south-southeast as the scenario progresses — a mobile vehicle the
# squad is converging on. These local coords are GROUND_MID (the target
# building, scenario.py) relative to GROUND_START, via overlay.json's
# deg-per-metre constants; keep them in sync with scenario.py:GROUND_MID and
# assets/detections/overlay.json:compound-alpha.
_TARGET_START_X = -389.5   # meters east of insertion (negative = west)
_TARGET_START_Y = +1888.7  # meters north of insertion
_TARGET_DRIFT_MPS_X = 0.4  # slow eastward drift
_TARGET_DRIFT_MPS_Y = -0.3 # slow southward drift


def _target_true_xy(t: timedelta) -> tuple[float, float]:
    """Ground-truth target (x, y) at scenario time t."""
    secs = t.total_seconds()
    x = _TARGET_START_X + _TARGET_DRIFT_MPS_X * secs
    y = _TARGET_START_Y + _TARGET_DRIFT_MPS_Y * secs
    return x, y


# --- Microdrone approach (for target-detection range gating) ---------
#
# A microdrone is a short-range sensor: it cannot range a target ~2 km out
# at the insertion LZ. It only localizes the target once the swarm (co-
# located with the squad) has closed to within MICRODRONE_CONVERGE_RANGE_M;
# until then it works the immediate forward environment (its motion/audio
# readings + the forward-FOV detection channel in generators/detection.py).
#
# We model the swarm-centroid track in the same local frame as the target,
# mirroring scenario.py's squad path anchors (kept here rather than imported
# to avoid a host/sim import cycle; the timing anchors must stay in sync with
# scenario.py:_squad_path). The objective is essentially the target area
# (GROUND_MID ~= _TARGET_START), so the drone closes on the target during
# infil, holds near it, then recedes on exfil. Per-drone hover offsets
# (<25 m) are negligible against the convergence range, so one centroid
# track serves the whole swarm.
MICRODRONE_CONVERGE_RANGE_M = 200.0   # start localizing the target at ~200 m

_APPROACH_LZ_XY = (0.0, 0.0)                          # insertion LZ
_APPROACH_OBJECTIVE_XY = (_TARGET_START_X, _TARGET_START_Y)  # objective ~ target
_APPROACH_EXFIL_XY = (-3200.0, -770.0)               # GROUND_EXFIL, local metres
_APPROACH_STAGE_END_SEC = 60.0    # T+1:00  held at the LZ through Setup
_APPROACH_INFIL_END_SEC = 180.0   # T+3:00  infiltrated to the objective
_APPROACH_HOLD_END_SEC = 420.0    # T+7:00  held at the objective; exfil begins
_APPROACH_EXFIL_DUR_SEC = 60.0    # T+8:00  reached the extraction point


def _lerp_xy(a: tuple[float, float], b: tuple[float, float],
             f: float) -> tuple[float, float]:
    return (a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f)


def _microdrone_approx_xy(t: timedelta) -> tuple[float, float]:
    """Swarm-centroid (x, y) in the local frame at scenario time t."""
    secs = t.total_seconds()
    if secs <= _APPROACH_STAGE_END_SEC:
        return _APPROACH_LZ_XY
    if secs < _APPROACH_INFIL_END_SEC:
        f = ((secs - _APPROACH_STAGE_END_SEC)
             / (_APPROACH_INFIL_END_SEC - _APPROACH_STAGE_END_SEC))
        return _lerp_xy(_APPROACH_LZ_XY, _APPROACH_OBJECTIVE_XY, f)
    if secs <= _APPROACH_HOLD_END_SEC:
        return _APPROACH_OBJECTIVE_XY
    f = min((secs - _APPROACH_HOLD_END_SEC) / _APPROACH_EXFIL_DUR_SEC, 1.0)
    return _lerp_xy(_APPROACH_OBJECTIVE_XY, _APPROACH_EXFIL_XY, f)


def _microdrone_in_target_range(t: timedelta) -> bool:
    """True once the swarm has closed to within convergence range."""
    mx, my = _microdrone_approx_xy(t)
    tx, ty = _target_true_xy(t)
    return math.hypot(tx - mx, ty - my) <= MICRODRONE_CONVERGE_RANGE_M


# --- Target position (cross-source validated) -----------------------

class TargetPositionXGenerator(DataGenerator):
    """Reports the target's local-frame x coordinate (meters).

    Each overhead platform produces its own slightly-noisy estimate.
    Honest sensors agree within ~5 m; the position validator's
    threshold is 50 m, so the MQ-800's compromise (offset 300 m/axis,
    ~424 m NE) trips it within one or two cadence ticks — far enough
    that it reads as a deliberate lie, not a statistical anomaly.
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

    Baseline ~35 dB and FLAT until the MQ-800 arrives — there is no
    high-power emitter in the AO before then.  On arrival the noise floor
    spikes by ~25 dB across all overhead platforms; that spike coinciding
    with the MQ-800's appearance is itself a tell that the new arrival is
    a hostile, high-power platform.  RQ-86s report the spike correctly;
    the compromised MQ-800 will under-report it (it knows where the noise
    is coming from and is trying to mask).

    Used by the electronic-noise validator: divergence between RQ-86's
    reading and MQ-800's reading is itself a trust signal.

    The spike onset is pinned to the MQ-800's arrival time. That arrival
    lives in scenario.py (MQ800_JOIN_SEC); to keep the tell from drifting
    away from the actual arrival, both read the same value — override via
    AT_MQ800_JOIN_SEC (seconds) and the launcher can set it once for both.
    Strictly gated: the floor stays at baseline for every t before arrival.
    """

    BASELINE_DB = 35.0
    # Default T+4:00 (phase 4, "Rogue"); MUST equal scenario.py:MQ800_JOIN_SEC.
    MQ800_ARRIVAL_SEC = float(os.environ.get("AT_MQ800_JOIN_SEC", 4 * 60))
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
        # Hard gate: dead flat at baseline until the MQ-800 arrives, so the
        # noise spike can never precede (or stand in for) its arrival.
        if secs < self.MQ800_ARRIVAL_SEC:
            return self.BASELINE_DB
        ramp = min(1.0, (secs - self.MQ800_ARRIVAL_SEC) / self.SPIKE_RAMP_SEC)
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
        # Forward-environment sensors run continuously; target-position
        # readings are range-gated in tick() (see _microdrone_in_target_range).
        self._forward_env = [self.motion, self.audio]
        self._target = [self.target_x, self.target_y]
        # Kept for callers/compromise wrappers that introspect the full set.
        self._generators = self._target + self._forward_env

    def tick(self, t: timedelta) -> list[Reading]:
        # Local forward-environment sensing always runs — a microdrone is
        # always watching its immediate surroundings (motion, audio, and the
        # forward-FOV detection channel wired in participant.py).
        out = [r for r in (g.tick(t) for g in self._forward_env)
               if r is not None]
        # Target localization only once the swarm has closed to within
        # range: a microdrone can't range a target ~2 km out at insertion,
        # so it picks the target up as the squad nears the objective (and
        # drops it again on exfil) rather than reporting it from t=0.
        if _microdrone_in_target_range(t):
            out.extend(r for r in (g.tick(t) for g in self._target)
                       if r is not None)
        return out
