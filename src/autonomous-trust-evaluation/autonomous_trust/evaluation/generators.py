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
Base data generator classes for AutonomousTrust demo scenarios.

Generators produce synthetic sensor readings with configurable noise,
drift, and anomaly injection.  Each generator is bound to a peer and
a data type (e.g. temperature, seismic magnitude, AQI).

Demo-specific generators (weather, seismic, etc.) subclass these bases.
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading


class DataGenerator(ABC):
    """Abstract base for sensor data generators.

    Subclasses implement `_generate_value()` to produce the raw reading
    for a given time step.  The base class handles noise injection and
    cadence management.

    Args:
        peer_name:   Peer this generator is bound to
        data_type:   Reading type string
        unit:        Measurement unit
        cadence_sec: How often to produce a reading
        noise_stddev: Gaussian noise standard deviation (0 = perfect)
        seed:        Random seed for reproducibility (None = random)
    """

    def __init__(self, peer_name: str, data_type: str, unit: str,
                 cadence_sec: float = 5.0, noise_stddev: float = 0.0,
                 seed: Optional[int] = None):
        self.peer_name = peer_name
        self.data_type = data_type
        self.unit = unit
        self.cadence_sec = cadence_sec
        self.noise_stddev = noise_stddev
        self._rng = random.Random(seed)
        self._last_tick: float = -cadence_sec  # ensure first tick fires

    @abstractmethod
    def _generate_value(self, t: timedelta) -> float:
        """Produce the true (noiseless) value at scenario time t."""
        ...

    def _apply_noise(self, value: float) -> float:
        """Add Gaussian noise to a value."""
        if self.noise_stddev > 0:
            return value + self._rng.gauss(0, self.noise_stddev)
        return value

    def tick(self, t: timedelta) -> Optional[Reading]:
        """Advance the generator to time t.  Returns a Reading if the
        cadence interval has elapsed, otherwise None."""
        elapsed = t.total_seconds()
        if elapsed - self._last_tick < self.cadence_sec:
            return None
        self._last_tick = elapsed

        raw = self._generate_value(t)
        noisy = self._apply_noise(raw)

        return Reading(
            timestamp=t,
            peer_name=self.peer_name,
            data_type=self.data_type,
            value=noisy,
            unit=self.unit,
            quality=0.95 + self._rng.uniform(0, 0.05),
        )


class SinusoidalGenerator(DataGenerator):
    """Generator with a sinusoidal base signal (e.g. diurnal temperature).

    Args:
        baseline:    Center value
        amplitude:   Peak-to-peak / 2
        period_sec:  Period of the sinusoid (default: 24h for diurnal)
        phase_offset: Phase offset in radians
    """

    def __init__(self, peer_name: str, data_type: str, unit: str,
                 baseline: float = 0.0, amplitude: float = 1.0,
                 period_sec: float = 86400.0, phase_offset: float = 0.0,
                 **kwargs):
        super().__init__(peer_name, data_type, unit, **kwargs)
        self.baseline = baseline
        self.amplitude = amplitude
        self.period_sec = period_sec
        self.phase_offset = phase_offset

    def _generate_value(self, t: timedelta) -> float:
        phase = 2 * math.pi * t.total_seconds() / self.period_sec + self.phase_offset
        return self.baseline + self.amplitude * math.sin(phase)


class RandomWalkGenerator(DataGenerator):
    """Generator with random-walk dynamics (e.g. wind speed, AQI).

    The value does a bounded random walk around a mean, with optional
    trend drift.

    Args:
        mean:       Long-term mean
        step_size:  Max change per tick
        bounds:     (min, max) clamp values
        trend:      Linear drift per second (0 = stationary)
    """

    def __init__(self, peer_name: str, data_type: str, unit: str,
                 mean: float = 0.0, step_size: float = 0.5,
                 bounds: tuple[float, float] = (-1e6, 1e6),
                 trend: float = 0.0, **kwargs):
        super().__init__(peer_name, data_type, unit, **kwargs)
        self.mean = mean
        self.step_size = step_size
        self.bounds = bounds
        self.trend = trend
        self._current = mean

    def _generate_value(self, t: timedelta) -> float:
        step = self._rng.uniform(-self.step_size, self.step_size)
        # Mean-reverting drift
        revert = 0.01 * (self.mean - self._current)
        # Linear trend
        trend_val = self.trend * t.total_seconds()

        self._current += step + revert
        self._current = max(self.bounds[0], min(self.bounds[1], self._current))
        return self._current + trend_val
