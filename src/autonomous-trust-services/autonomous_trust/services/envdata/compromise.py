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

"""Compromise wrapper for environmental-data generators.

Takes any source callable `(timedelta) -> Reading | None` and returns a
new callable that produces identical output until `onset_sec`, then
applies mode-specific falsification. The wrapper doesn't know or care
whether the underlying source is a real sensor, a `DataGenerator`, a
file replayer, etc -- it transforms Readings.

Modes (all tested against the scenario):
    temperature_drift      -- gradual +N deg F drift over a ramp window
    wind_spikes            -- random multiplicative spikes on a tick
    pressure_flatline      -- freeze at first-seen value after onset
    precipitation_invert   -- reflect around a midpoint

A helper `compromise_from_env()` constructs a CompromiseConfig from the
AT_COMPROMISED/AT_COMPROMISE_ONSET_SEC/AT_COMPROMISE_MODES env vars that
the demo compose/k8s generator sets on rogue peers.
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Optional

from ..data.reading import Reading


# Mode identifiers -- string constants used in configs and env vars.
COMPROMISE_MODE_TEMP_DRIFT        = "temperature_drift"
COMPROMISE_MODE_WIND_SPIKES       = "wind_spikes"
COMPROMISE_MODE_PRESSURE_FLATLINE = "pressure_flatline"
COMPROMISE_MODE_PRECIP_INVERT     = "precipitation_invert"


# Source callable type (matches envdata.base.AcquireFn without import).
SourceFn = Callable[[timedelta], Optional[Reading]]


# Data-type -> mode mapping so a single CompromiseConfig can cover all
# four weather streams from one rogue peer without per-stream wiring.
_TYPE_TO_MODE = {
    "temperature":          COMPROMISE_MODE_TEMP_DRIFT,
    "wind_speed":           COMPROMISE_MODE_WIND_SPIKES,
    "barometric_pressure":  COMPROMISE_MODE_PRESSURE_FLATLINE,
    "precipitation":        COMPROMISE_MODE_PRECIP_INVERT,
}


@dataclass
class CompromiseConfig:
    """Parameters governing the rogue behavior.

    Attributes:
        onset_sec:       Scenario seconds after which compromise begins.
        modes:           Enabled mode identifiers (see constants above).
        temp_drift_deg:  Final temperature bias applied after full ramp (F).
        temp_drift_rate_sec: Ramp-in window (linear 0 -> full bias).
        wind_spike_rate_per_sec: Probability per tick of a wind spike.
        wind_spike_mult: Multiplier applied on a spike.
        invert_midpoint: Reflection point for precipitation inversion (in/hr).
        seed:            Wrapper RNG seed for reproducible spikes.
    """
    onset_sec: float
    modes: list[str] = field(default_factory=list)
    temp_drift_deg: float = 5.0
    temp_drift_rate_sec: float = 60.0
    wind_spike_rate_per_sec: float = 0.08
    wind_spike_mult: float = 2.5
    invert_midpoint: float = 0.10
    seed: Optional[int] = None

    def has(self, mode: str) -> bool:
        return mode in self.modes


class CompromisedGenerator:
    """Wraps a source callable; produces falsified Readings after onset.

    Intentionally duck-typed rather than a DataGenerator subclass: the
    services layer does not depend on evaluation/generators.py.

    Example:
        wrapper = CompromisedGenerator(honest_gen.tick, config)
        service.set_source(wrapper)  # service sees a tick-like callable
    """

    _MODE_TABLE = _TYPE_TO_MODE

    def __init__(self, inner: SourceFn, config: CompromiseConfig):
        self._inner = inner
        self._config = config
        self._rng = random.Random(config.seed)
        self._frozen_pressure: Optional[float] = None

    # --- per-mode transformations ---

    def _apply_temperature_drift(self, t_sec: float, value: float) -> float:
        dt = max(0.0, t_sec - self._config.onset_sec)
        ramp = min(1.0, dt / max(self._config.temp_drift_rate_sec, 1e-3))
        return value + ramp * self._config.temp_drift_deg

    def _apply_wind_spikes(self, value: float) -> float:
        if self._rng.random() < self._config.wind_spike_rate_per_sec:
            return value * self._config.wind_spike_mult
        return value

    def _apply_pressure_flatline(self, value: float) -> float:
        if self._frozen_pressure is None:
            self._frozen_pressure = value
        return self._frozen_pressure

    def _apply_precipitation_invert(self, value: float) -> float:
        mid = self._config.invert_midpoint
        return max(0.0, 2 * mid - value)

    # --- callable interface (mirrors DataGenerator.tick) ---

    def __call__(self, t: timedelta) -> Optional[Reading]:
        return self.tick(t)

    def tick(self, t: timedelta) -> Optional[Reading]:
        reading = self._inner(t)
        if reading is None:
            return None

        t_sec = t.total_seconds()
        if t_sec < self._config.onset_sec:
            return reading

        mode = self._MODE_TABLE.get(reading.data_type)
        if mode is None or not self._config.has(mode):
            return reading

        value = reading.value
        if mode == COMPROMISE_MODE_TEMP_DRIFT:
            value = self._apply_temperature_drift(t_sec, value)
        elif mode == COMPROMISE_MODE_WIND_SPIKES:
            value = self._apply_wind_spikes(value)
        elif mode == COMPROMISE_MODE_PRESSURE_FLATLINE:
            value = self._apply_pressure_flatline(value)
        elif mode == COMPROMISE_MODE_PRECIP_INVERT:
            value = self._apply_precipitation_invert(value)

        md = dict(reading.metadata)
        md["compromised"] = True
        md["compromise_mode"] = mode
        return Reading(
            timestamp=reading.timestamp,
            peer_name=reading.peer_name,
            data_type=reading.data_type,
            value=value,
            unit=reading.unit,
            # Quality stays honest: ZTA/metadata cannot reveal the attack;
            # AT must catch this via corroboration against other peers.
            quality=reading.quality,
            metadata=md,
        )


# ----------------------------------------------------------------------
# Env-var plumbing (compose generator sets AT_COMPROMISED etc. on rogue peers)
# ----------------------------------------------------------------------

def compromise_from_env(env: Optional[dict[str, str]] = None
                        ) -> Optional[CompromiseConfig]:
    """Return a CompromiseConfig if AT_COMPROMISED=1 in the environment,
    else None. Parses AT_COMPROMISE_ONSET_SEC and AT_COMPROMISE_MODES."""
    env = env if env is not None else os.environ

    if env.get("AT_COMPROMISED", "") not in ("1", "true", "True"):
        return None

    try:
        onset = float(env.get("AT_COMPROMISE_ONSET_SEC", "240"))
    except ValueError:
        onset = 240.0
    modes_raw = env.get("AT_COMPROMISE_MODES", "")
    modes = [m.strip() for m in modes_raw.split(",") if m.strip()]

    return CompromiseConfig(onset_sec=onset, modes=modes)
