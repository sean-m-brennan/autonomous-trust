"""
NOAA weather data generators for the multi-agency disaster response demo.

Produces realistic hurricane-season readings for coastal North Carolina:
  - Temperature (diurnal sinusoid + hurricane warming trend)
  - Wind speed (random walk with gust events during storm approach)
  - Barometric pressure (declining trend as hurricane approaches)
  - Precipitation (event-based, increasing with storm proximity)

Each generator is bound to a specific NOAA sensor peer.
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


class TemperatureGenerator(SinusoidalGenerator):
    """Coastal NC temperature with hurricane warming.

    Base: ~28C (82F) summer, +/- 4C diurnal swing.
    Hurricane effect: +2-3C warming trend as storm approaches (warm SST).
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type="temperature",
            unit="C",
            baseline=28.0,
            amplitude=4.0,
            period_sec=480.0,    # 8-min scenario = 1 "day" cycle
            phase_offset=0.0,
            cadence_sec=5.0,
            noise_stddev=0.3,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        base = super()._generate_value(t)
        # Warming trend: +3C over the scenario as hurricane approaches
        warming = 3.0 * (t.total_seconds() / self.period_sec)
        return base + min(warming, 3.0)


class WindSpeedGenerator(RandomWalkGenerator):
    """Coastal wind speed with hurricane gusts.

    Starts at ~15 km/h (normal coastal breeze), ramps to 80+ km/h
    as the storm approaches.  Gust events add 20-40 km/h spikes.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type="wind_speed",
            unit="km/h",
            mean=15.0,
            step_size=3.0,
            bounds=(0.0, 150.0),
            trend=0.0,
            cadence_sec=5.0,
            noise_stddev=2.0,
            seed=seed,
        )
        self._gust_rng = random.Random(seed + 1 if seed else None)

    def _generate_value(self, t: timedelta) -> float:
        # Ramp mean wind from 15 to 80 km/h over the scenario
        progress = min(t.total_seconds() / 480.0, 1.0)
        self.mean = 15.0 + 65.0 * progress
        self.step_size = 3.0 + 7.0 * progress

        base = super()._generate_value(t)

        # Random gusts (10% chance per reading after T+2:00)
        if t.total_seconds() > 120 and self._gust_rng.random() < 0.10:
            gust = self._gust_rng.uniform(20.0, 40.0)
            return base + gust

        return base


class PressureGenerator(DataGenerator):
    """Barometric pressure declining as hurricane approaches.

    Normal: ~1013 hPa.  Hurricane eye: ~960 hPa.
    Smooth exponential decline with small fluctuations.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type="pressure",
            unit="hPa",
            cadence_sec=10.0,
            noise_stddev=0.5,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        # Decline from 1013 to ~965 hPa over 8 minutes
        progress = min(t.total_seconds() / 480.0, 1.0)
        # Exponential approach to minimum
        drop = 48.0 * (1.0 - math.exp(-3.0 * progress))
        return 1013.0 - drop


class PrecipitationGenerator(DataGenerator):
    """Precipitation rate (mm/hr) — event-based with storm bands.

    Light rain starts around T+2:00, heavy rain bands from T+3:00+.
    Uses a modulated sinusoid to simulate rain bands passing through.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type="precipitation",
            unit="mm/hr",
            cadence_sec=10.0,
            noise_stddev=2.0,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        secs = t.total_seconds()
        if secs < 120:
            return 0.0  # Dry before T+2:00

        # Rain intensity ramps from 0 to ~50 mm/hr
        progress = min((secs - 120) / 360.0, 1.0)
        base_rate = 50.0 * progress

        # Rain bands (periodic intensification)
        band = 0.5 + 0.5 * math.sin(secs / 30.0)
        return max(0.0, base_rate * band)


class WeatherStationGenerators:
    """Bundle of all weather generators for a single NOAA station.

    Convenience class that creates and ticks all four generators together.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        base_seed = seed or hash(peer_name) & 0xFFFF
        self.temperature = TemperatureGenerator(peer_name, seed=base_seed)
        self.wind_speed = WindSpeedGenerator(peer_name, seed=base_seed + 100)
        self.pressure = PressureGenerator(peer_name, seed=base_seed + 200)
        self.precipitation = PrecipitationGenerator(peer_name, seed=base_seed + 300)
        self._generators = [
            self.temperature, self.wind_speed,
            self.pressure, self.precipitation,
        ]

    def tick(self, t: timedelta) -> list[Reading]:
        """Advance all generators; return list of readings produced."""
        readings = []
        for gen in self._generators:
            r = gen.tick(t)
            if r is not None:
                readings.append(r)
        return readings
