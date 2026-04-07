"""
USGS seismic data generators for the civilian disaster response demo.

Produces background micro-seismicity typical of the southeastern US
(Cape Fear Arch region) with occasional triggered events during
hurricane approach (storm-induced microseisms).

Readings:
  - Magnitude (Richter-like scale, mostly <2.0 with rare 2-3 events)
  - Ground velocity (mm/s peak ground velocity)
  - Depth (km, shallow events typical of region)
"""

from __future__ import annotations

import math
import random
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading
from autonomous_trust.evaluation.generators import DataGenerator


class MagnitudeGenerator(DataGenerator):
    """Seismic magnitude generator.

    Background: micro-events at 0.5-1.5 magnitude, frequent.
    Storm-induced: occasional 1.5-3.0 events as hurricane approaches
    (microseisms from ocean wave coupling).
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type="magnitude",
            unit="ML",
            cadence_sec=15.0,
            noise_stddev=0.0,  # handled internally for log-normal dist
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        secs = t.total_seconds()

        # Background micro-seismicity (log-normal distribution)
        base = abs(self._rng.lognormvariate(-0.5, 0.6))
        base = min(base, 1.5)

        # Storm-induced microseisms increase after T+3:00
        if secs > 180:
            storm_factor = min((secs - 180) / 300.0, 1.0)
            if self._rng.random() < 0.15 * storm_factor:
                # Triggered event: 1.5-3.0 magnitude
                return 1.5 + self._rng.uniform(0, 1.5) * storm_factor
        return base


class GroundVelocityGenerator(DataGenerator):
    """Peak ground velocity (PGV) generator.

    Correlates loosely with magnitude.  Normal background is 0.01-0.1 mm/s.
    Noticeable events reach 1-10 mm/s.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type="ground_velocity",
            unit="mm/s",
            cadence_sec=5.0,
            noise_stddev=0.005,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        secs = t.total_seconds()
        # Background PGV
        base = 0.02 + 0.01 * math.sin(secs / 60.0)

        # Elevated PGV during storm approach (ocean microseisms)
        if secs > 180:
            storm = min((secs - 180) / 300.0, 1.0)
            base += 0.05 * storm
            # Occasional spikes
            if self._rng.random() < 0.05 * storm:
                base += self._rng.uniform(0.5, 5.0)
        return max(0.0, base)


class SeismicStationGenerators:
    """Bundle of seismic generators for a single USGS monitor."""

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        base_seed = seed or hash(peer_name) & 0xFFFF
        self.magnitude = MagnitudeGenerator(peer_name, seed=base_seed)
        self.ground_velocity = GroundVelocityGenerator(
            peer_name, seed=base_seed + 100)
        self._generators = [self.magnitude, self.ground_velocity]

    def tick(self, t: timedelta) -> list[Reading]:
        readings = []
        for gen in self._generators:
            r = gen.tick(t)
            if r is not None:
                readings.append(r)
        return readings
