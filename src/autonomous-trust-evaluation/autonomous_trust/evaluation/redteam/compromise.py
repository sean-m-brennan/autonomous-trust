"""
Compromise behavior modules for AutonomousTrust demo scenarios.

These wrap a data generator and inject malicious behavior:
  - GradualDrift:  Slowly shift readings away from truth
  - AbruptDeviation: Instantly flip to fabricated values
  - Intermittent: Alternate between honest and dishonest readings

Each takes an honest generator and returns modified readings after
a configurable activation time.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading
from autonomous_trust.evaluation.generators import DataGenerator


class CompromiseBehavior(ABC):
    """Wraps a DataGenerator and injects malicious behavior after activation.

    Args:
        honest_generator: The underlying honest generator
        activate_at:      Scenario time when compromise begins
    """

    def __init__(self, honest_generator: DataGenerator,
                 activate_at: timedelta):
        self.honest = honest_generator
        self.activate_at = activate_at
        self._active = False

    @property
    def peer_name(self) -> str:
        return self.honest.peer_name

    @property
    def data_type(self) -> str:
        return self.honest.data_type

    def is_active(self, t: timedelta) -> bool:
        return t >= self.activate_at

    @abstractmethod
    def _corrupt_value(self, honest_value: float, t: timedelta) -> float:
        """Transform an honest value into a corrupt one."""
        ...

    def tick(self, t: timedelta) -> Optional[Reading]:
        """Produce a reading — honest before activation, corrupt after."""
        reading = self.honest.tick(t)
        if reading is None:
            return None

        if not self.is_active(t):
            return reading

        self._active = True
        corrupt = self._corrupt_value(reading.value, t)
        return Reading(
            timestamp=reading.timestamp,
            peer_name=reading.peer_name,
            data_type=reading.data_type,
            value=corrupt,
            unit=reading.unit,
            quality=reading.quality,  # lies about quality too
            metadata={**reading.metadata, "_compromised": True},
        )


class GradualDrift(CompromiseBehavior):
    """Slowly drift readings away from truth over time.

    Good for realistic compromise scenarios where detection takes time.
    The drift rate controls how fast the reading diverges.

    Args:
        drift_rate:  Units of drift per minute after activation
        max_drift:   Cap on total drift (absolute value)
        direction:   1.0 for upward drift, -1.0 for downward
    """

    def __init__(self, honest_generator: DataGenerator,
                 activate_at: timedelta,
                 drift_rate: float = 0.5,
                 max_drift: float = 20.0,
                 direction: float = 1.0):
        super().__init__(honest_generator, activate_at)
        self.drift_rate = drift_rate
        self.max_drift = max_drift
        self.direction = 1.0 if direction >= 0 else -1.0

    def _corrupt_value(self, honest_value: float, t: timedelta) -> float:
        elapsed_min = (t - self.activate_at).total_seconds() / 60.0
        drift = min(self.drift_rate * elapsed_min, self.max_drift)
        return honest_value + drift * self.direction


class AbruptDeviation(CompromiseBehavior):
    """Instantly switch to fabricated values at activation.

    More dramatic for demos — easy for audience to see the divergence.

    Args:
        fabricated_value: Fixed value to report (or None for offset mode)
        offset:           If fabricated_value is None, offset from honest value
    """

    def __init__(self, honest_generator: DataGenerator,
                 activate_at: timedelta,
                 fabricated_value: Optional[float] = None,
                 offset: float = 15.0):
        super().__init__(honest_generator, activate_at)
        self.fabricated_value = fabricated_value
        self.offset = offset

    def _corrupt_value(self, honest_value: float, t: timedelta) -> float:
        if self.fabricated_value is not None:
            return self.fabricated_value
        return honest_value + self.offset


class Intermittent(CompromiseBehavior):
    """Alternate between honest and corrupt readings.

    Harder to detect — mimics a sensor with an intermittent fault.

    Args:
        corrupt_fraction: Fraction of readings that are corrupt (0.0-1.0)
        offset:           How far corrupt readings deviate
    """

    def __init__(self, honest_generator: DataGenerator,
                 activate_at: timedelta,
                 corrupt_fraction: float = 0.3,
                 offset: float = 10.0):
        super().__init__(honest_generator, activate_at)
        self.corrupt_fraction = corrupt_fraction
        self.offset = offset
        self._tick_count = 0

    def _corrupt_value(self, honest_value: float, t: timedelta) -> float:
        self._tick_count += 1
        # Use a deterministic pattern based on tick count
        phase = math.sin(self._tick_count * 0.7)  # pseudo-random-ish
        if phase > (1.0 - 2 * self.corrupt_fraction):
            return honest_value + self.offset
        return honest_value
