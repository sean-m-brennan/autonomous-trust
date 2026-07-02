# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Ground-sensor generators for leave-behind platforms.

Each leave-behind sensor produces seismic, acoustic, and perimeter-trip
readings.  These are NOT cross-source validated against the overhead
ISR — the validators only see them within the leave-behind population.
Clean sensors agree (sparse seismic events, quiet acoustic baseline,
occasional perimeter trips); a hacked sensor's data may be honest,
since the compromise category here is identity, not content.  The
forged-identity marker in ../compromise/forged_identity.py is what the
network rejects, not the data shape.

Generators:
  SeismicGenerator:        Magnitude scale (0-3 typical, 4+ vehicles)
  AcousticGenerator:       Audio level (dB)
  PerimeterTripGenerator:  Boolean-ish trip events (0 / 1)
"""

from __future__ import annotations

import math
import random
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading
from autonomous_trust.evaluation.generators import (
    DataGenerator, RandomWalkGenerator,
)


class SeismicGenerator(DataGenerator):
    """Ground vibration magnitude (Richter-like scalar, mostly < 1).

    Baseline is micro-seismicity floor ~0.1.  As the squad and target
    converge on the area (phases 3-5) vehicle activity pushes brief
    excursions into the 1-3 range.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None,
                 cadence_sec: float = 5.0):
        super().__init__(
            peer_name=peer_name,
            data_type="seismic_magnitude",
            unit="",
            cadence_sec=cadence_sec,
            noise_stddev=0.05,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        secs = t.total_seconds()
        baseline = 0.1
        # Vehicle-activity bumps in phases 3-5
        if 180 <= secs <= 330:
            # Periodic small spikes from passing engines
            bump = 0.6 * max(0.0, math.sin(secs / 12.0))
            return baseline + bump
        return baseline


class AcousticGenerator(RandomWalkGenerator):
    """Ambient acoustic level (dB) at the sensor."""

    def __init__(self, peer_name: str, seed: Optional[int] = None,
                 cadence_sec: float = 4.0):
        super().__init__(
            peer_name=peer_name,
            data_type="acoustic_db",
            unit="dB",
            mean=38.0,
            step_size=1.5,
            bounds=(25.0, 80.0),
            trend=0.0,
            cadence_sec=cadence_sec,
            noise_stddev=0.7,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        # Approach-phase activity bump similar to seismic
        secs = t.total_seconds()
        if 180 <= secs <= 330:
            self.mean = 50.0
        else:
            self.mean = 38.0
        return super()._generate_value(t)


class PerimeterTripGenerator(DataGenerator):
    """Boolean-ish trip events (0 or 1) from a passive IR / break-beam.

    Honest leave-behind sensors trip only when something genuinely
    crosses their fence line — modeled here as a low-rate Poisson-like
    process during the convergence window.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None,
                 cadence_sec: float = 5.0):
        super().__init__(
            peer_name=peer_name,
            data_type="perimeter_trip",
            unit="",
            cadence_sec=cadence_sec,
            noise_stddev=0.0,
            seed=seed,
        )
        self._trip_rng = random.Random(seed)

    def _generate_value(self, t: timedelta) -> float:
        secs = t.total_seconds()
        # Trip probability bumps during the convergence window
        if 180 <= secs <= 360:
            p = 0.15
        else:
            p = 0.01
        return 1.0 if self._trip_rng.random() < p else 0.0


class GroundSensorGenerators:
    """Bundle of all generators for one leave-behind sensor."""

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        base = seed if seed is not None else hash(peer_name) & 0xFFFF
        self.seismic = SeismicGenerator(peer_name, seed=base)
        self.acoustic = AcousticGenerator(peer_name, seed=base + 1)
        self.perimeter = PerimeterTripGenerator(peer_name, seed=base + 2)
        self._generators = [self.seismic, self.acoustic, self.perimeter]

    def tick(self, t: timedelta) -> list[Reading]:
        return [r for r in (g.tick(t) for g in self._generators) if r is not None]
