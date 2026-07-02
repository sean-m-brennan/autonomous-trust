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

"""Data generators specific to the disaster-response scenario.

Five weather types (NOAA), two seismic types (USGS), one air-quality
type (EPA), and one situation-report type (FEMA). Each is a thin
configuration of the base DataGenerator classes in
`autonomous_trust.evaluation.generators`.

Compromise wrappers let a scenario turn an honest generator into a
falsifying one at a configured onset time. The wrapper does not replace
the generator -- it decorates the tick() output so up to the onset
readings look identical to an honest station's.

Compromise modes (all implemented below):
    temperature_drift      -- gradual +5F bias accumulated after onset
    wind_spikes            -- random Poisson-spaced multiplicative spikes
    pressure_flatline      -- output freezes at last honest value
    precipitation_invert   -- value is reflected around a midpoint

Divergence is subtle enough that a single reading looks plausible but
corroboration against other NOAA stations detects the shift within a
minute of onset.
"""

from __future__ import annotations

import math
from datetime import timedelta
from typing import Optional, Union

from autonomous_trust.services.data import Reading
from autonomous_trust.services.envdata.compromise import (
    CompromiseConfig,
    CompromisedGenerator,
)

from ..generators import (
    DataGenerator,
    RandomWalkGenerator,
    SinusoidalGenerator,
)

# Anything build_generators_for_scenario returns -- either an honest
# DataGenerator or a CompromisedGenerator wrapping one.
TickLike = Union[DataGenerator, CompromisedGenerator]


# ----------------------------------------------------------------------
# Data type names (kept consistent with scenario capabilities)
# ----------------------------------------------------------------------

TYPE_TEMPERATURE     = "temperature"       # deg F
TYPE_WIND_SPEED      = "wind_speed"        # mph
TYPE_PRESSURE        = "barometric_pressure"  # inHg
TYPE_PRECIPITATION   = "precipitation"     # in/hr
TYPE_GROUND_MOTION   = "ground_motion"     # mm/s (peak ground velocity)
TYPE_MAGNITUDE       = "seismic_magnitude"  # Richter-scale local M_L
TYPE_AQI             = "air_quality_index"  # 0-500 AQI integer
TYPE_SITREP          = "situation_report"  # text blob


# ----------------------------------------------------------------------
# NOAA weather generators
# ----------------------------------------------------------------------

class TemperatureGenerator(SinusoidalGenerator):
    """Diurnal temperature cycle in deg F.

    Baseline ~55F, amplitude ~15F, period compressed to scenario time
    so a viewer can see a full day cycle inside the 8-minute demo.
    """

    def __init__(self, peer_name: str, baseline_f: float = 55.0,
                 amplitude_f: float = 15.0,
                 diurnal_period_sec: float = 480.0,
                 cadence_sec: float = 1.0,
                 noise_stddev: float = 0.3,
                 seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type=TYPE_TEMPERATURE,
            unit="F",
            baseline=baseline_f,
            amplitude=amplitude_f,
            period_sec=diurnal_period_sec,
            cadence_sec=cadence_sec,
            noise_stddev=noise_stddev,
            seed=seed,
        )


class WindSpeedGenerator(RandomWalkGenerator):
    """Wind speed in mph: random walk on [0, 45]."""

    def __init__(self, peer_name: str, mean_mph: float = 8.0,
                 step_mph: float = 1.5, max_mph: float = 45.0,
                 cadence_sec: float = 1.0,
                 noise_stddev: float = 0.2,
                 seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type=TYPE_WIND_SPEED,
            unit="mph",
            mean=mean_mph,
            step_size=step_mph,
            bounds=(0.0, max_mph),
            cadence_sec=cadence_sec,
            noise_stddev=noise_stddev,
            seed=seed,
        )


class PressureGenerator(RandomWalkGenerator):
    """Barometric pressure in inHg, slow random walk around 30.0."""

    def __init__(self, peer_name: str, mean_inhg: float = 30.00,
                 step_inhg: float = 0.02, cadence_sec: float = 1.0,
                 noise_stddev: float = 0.005,
                 seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type=TYPE_PRESSURE,
            unit="inHg",
            mean=mean_inhg,
            step_size=step_inhg,
            bounds=(28.50, 31.00),
            cadence_sec=cadence_sec,
            noise_stddev=noise_stddev,
            seed=seed,
        )


class PrecipitationGenerator(DataGenerator):
    """Precipitation in in/hr. Bursty -- mostly dry with rain episodes.

    Follows a two-state Markov process: DRY (rate=0) and WET (positive
    rate drawn from an exponential). Transitions are time-scaled so
    the demo sees a few wet/dry flips over 8 minutes.
    """

    def __init__(self, peer_name: str, cadence_sec: float = 1.0,
                 dry_to_wet_per_sec: float = 1.0 / 120.0,
                 wet_to_dry_per_sec: float = 1.0 / 60.0,
                 wet_rate_mean_inhr: float = 0.15,
                 noise_stddev: float = 0.01,
                 seed: Optional[int] = None):
        super().__init__(peer_name, TYPE_PRECIPITATION, "in/hr",
                         cadence_sec=cadence_sec,
                         noise_stddev=noise_stddev,
                         seed=seed)
        self._p_dry_wet = dry_to_wet_per_sec
        self._p_wet_dry = wet_to_dry_per_sec
        self._wet_rate = wet_rate_mean_inhr
        self._state_wet = False
        self._state_value = 0.0
        self._last_eval_t = 0.0

    def _generate_value(self, t: timedelta) -> float:
        now = t.total_seconds()
        dt = max(0.0, now - self._last_eval_t)
        self._last_eval_t = now

        # State transition (per-second probability, small-dt approximation).
        if self._state_wet:
            if self._rng.random() < self._p_wet_dry * dt:
                self._state_wet = False
                self._state_value = 0.0
        else:
            if self._rng.random() < self._p_dry_wet * dt:
                self._state_wet = True
                self._state_value = self._rng.expovariate(1.0 / self._wet_rate)

        return max(0.0, self._state_value)


# ----------------------------------------------------------------------
# USGS seismic generators
# ----------------------------------------------------------------------

class GroundMotionGenerator(DataGenerator):
    """Peak ground velocity in mm/s. Quiescent with occasional transients.

    Below the detection threshold 99% of the time; periodic mini-events
    (local seismicity) produce transients. Demo is weather-driven so
    USGS mostly stays quiet, but produces occasional blips so USGS peers
    remain visibly active in the UI.
    """

    def __init__(self, peer_name: str, cadence_sec: float = 1.0,
                 baseline_mm_s: float = 0.02,
                 transient_rate_per_sec: float = 1.0 / 30.0,
                 transient_peak_mm_s: float = 1.5,
                 transient_decay_sec: float = 2.0,
                 noise_stddev: float = 0.003,
                 seed: Optional[int] = None):
        super().__init__(peer_name, TYPE_GROUND_MOTION, "mm/s",
                         cadence_sec=cadence_sec,
                         noise_stddev=noise_stddev,
                         seed=seed)
        self._baseline = baseline_mm_s
        self._transient_rate = transient_rate_per_sec
        self._transient_peak = transient_peak_mm_s
        self._decay_sec = transient_decay_sec
        self._transient_start: Optional[float] = None
        self._transient_peak_val: float = 0.0

    def _generate_value(self, t: timedelta) -> float:
        now = t.total_seconds()

        # Start a new transient with small per-second probability.
        if self._transient_start is None:
            if self._rng.random() < self._transient_rate * self.cadence_sec:
                self._transient_start = now
                self._transient_peak_val = self._rng.uniform(
                    0.3 * self._transient_peak, self._transient_peak
                )

        value = self._baseline
        if self._transient_start is not None:
            elapsed = now - self._transient_start
            value += self._transient_peak_val * math.exp(-elapsed / self._decay_sec)
            if elapsed > 6 * self._decay_sec:
                self._transient_start = None

        return value


class MagnitudeGenerator(DataGenerator):
    """Richter-scale magnitude estimates -- periodic, sparse.

    Produces a reading only when a transient is active in the companion
    ground-motion stream. For scenario convenience this generator fires
    its own low-rate magnitudes that a fusion node can compare against
    ground-motion peaks for internal consistency.
    """

    def __init__(self, peer_name: str, cadence_sec: float = 5.0,
                 event_rate_per_sec: float = 1.0 / 60.0,
                 magnitude_bounds: tuple[float, float] = (1.5, 3.2),
                 noise_stddev: float = 0.05,
                 seed: Optional[int] = None):
        super().__init__(peer_name, TYPE_MAGNITUDE, "M_L",
                         cadence_sec=cadence_sec,
                         noise_stddev=noise_stddev,
                         seed=seed)
        self._event_rate = event_rate_per_sec
        self._bounds = magnitude_bounds
        self._active_mag: Optional[float] = None

    def _generate_value(self, t: timedelta) -> float:
        # Fire a new magnitude reading occasionally; otherwise return NaN
        # (callers should filter on quality or value==0 for "no event").
        if self._rng.random() < self._event_rate * self.cadence_sec:
            lo, hi = self._bounds
            self._active_mag = self._rng.uniform(lo, hi)
        if self._active_mag is None:
            return 0.0
        mag = self._active_mag
        # Reset so we don't re-report the same magnitude every tick.
        self._active_mag = None
        return mag


# ----------------------------------------------------------------------
# EPA air-quality generator
# ----------------------------------------------------------------------

class AirQualityGenerator(RandomWalkGenerator):
    """AQI random walk, 0-500 (integer in Reading.metadata["aqi_int"])."""

    def __init__(self, peer_name: str, mean_aqi: float = 45.0,
                 step_aqi: float = 2.5, cadence_sec: float = 1.0,
                 noise_stddev: float = 0.5,
                 seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type=TYPE_AQI,
            unit="AQI",
            mean=mean_aqi,
            step_size=step_aqi,
            bounds=(0.0, 500.0),
            cadence_sec=cadence_sec,
            noise_stddev=noise_stddev,
            seed=seed,
        )


# ----------------------------------------------------------------------
# FEMA situation-report generator
# ----------------------------------------------------------------------

_SITREP_TEMPLATES = [
    "Perimeter secure. Staging area {sa} supplied for {h}h.",
    "Evac routes {r1} and {r2} clear. {n} shelters operational.",
    "Request resupply: {comm} kits, {med} med-kits via {r1}.",
    "Comms with {peer} nominal. Mesh link quality {q:.2f}.",
    "Weather degradation reported from {peer}; holding {unit} in place.",
    "Sensor network integrity check: {ok}/{tot} peers corroborating.",
]


class SituationReportGenerator(DataGenerator):
    """Periodic text situation reports. Reading.value holds a stable
    numeric hash; the text is in Reading.metadata["text"]."""

    def __init__(self, peer_name: str, cadence_sec: float = 20.0,
                 seed: Optional[int] = None):
        super().__init__(peer_name, TYPE_SITREP, "text",
                         cadence_sec=cadence_sec,
                         noise_stddev=0.0,
                         seed=seed)

    def _generate_value(self, t: timedelta) -> float:
        # Unused; tick() is overridden.
        return 0.0

    def tick(self, t: timedelta) -> Optional[Reading]:
        elapsed = t.total_seconds()
        if elapsed - self._last_tick < self.cadence_sec:
            return None
        self._last_tick = elapsed

        tpl = self._rng.choice(_SITREP_TEMPLATES)
        text = tpl.format(
            sa=self._rng.choice(["Alpha", "Bravo", "Charlie"]),
            h=self._rng.randint(4, 24),
            r1=self._rng.choice(["I-5", "US-101", "SR-8", "SR-12"]),
            r2=self._rng.choice(["I-5", "US-101", "SR-8", "SR-12"]),
            n=self._rng.randint(2, 9),
            comm=self._rng.randint(20, 80),
            med=self._rng.randint(10, 40),
            peer=self._rng.choice(["noaa-1", "noaa-2", "usgs-1", "usgs-2"]),
            q=self._rng.uniform(0.60, 0.99),
            unit=self._rng.choice(["R10-FS1", "R10-FS2"]),
            ok=self._rng.randint(6, 9),
            tot=9,
        )

        return Reading(
            timestamp=t,
            peer_name=self.peer_name,
            data_type=self.data_type,
            value=float(hash(text) & 0xFFFF) / 0xFFFF,
            unit=self.unit,
            quality=0.98,
            metadata={"text": text},
        )


# ----------------------------------------------------------------------
# Roster helper: build generators for every peer in the scenario
# ----------------------------------------------------------------------

def build_generators_for_scenario(scenario) -> dict[str, list[TickLike]]:
    """Return {peer_name: [tick-producer, ...]} for a DisasterResponseScenario.

    Each producer exposes `.tick(timedelta) -> Reading | None` -- either
    a DataGenerator or a CompromisedGenerator wrapping one.
    """
    out: dict[str, list[TickLike]] = {}

    # Deterministic per-peer seeds so playback is reproducible.
    def _seed(name: str, tag: str) -> int:
        return (hash((name, tag)) & 0x7FFFFFFF) or 1

    for name, role in scenario.peers.items():
        gens: list[TickLike] = []

        if role.kind == "weather-sensor":
            # Per-peer baseline offset so honest stations differ slightly.
            offset = ((hash(name) & 0xFF) - 128) / 200.0  # ~-0.6 .. +0.6 F
            honest: list[DataGenerator] = [
                TemperatureGenerator(name, baseline_f=55.0 + offset,
                                     seed=_seed(name, "temp")),
                WindSpeedGenerator(name, seed=_seed(name, "wind")),
                PressureGenerator(name, seed=_seed(name, "pressure")),
                PrecipitationGenerator(name, seed=_seed(name, "precip")),
            ]
            if role.metadata.get("compromised"):
                cfg = CompromiseConfig(
                    onset_sec=float(role.metadata.get("compromise_onset_sec",
                                                      240.0)),
                    modes=list(role.metadata.get("compromise_modes", [])),
                    seed=_seed(name, "compromise"),
                )
                # envdata.CompromisedGenerator wraps a callable, not a
                # DataGenerator. We pass `.tick` to keep the inner
                # generator's state coherent while rewriting readings.
                gens.extend(CompromisedGenerator(g.tick, cfg) for g in honest)
            else:
                gens.extend(honest)

        elif role.kind == "seismic-monitor":
            gens.append(GroundMotionGenerator(name, seed=_seed(name, "gm")))
            gens.append(MagnitudeGenerator(name, seed=_seed(name, "mag")))

        elif role.kind == "air-quality-monitor":
            gens.append(AirQualityGenerator(name, seed=_seed(name, "aqi")))

        elif role.kind in ("field-station", "fusion-node"):
            gens.append(SituationReportGenerator(name, seed=_seed(name, "sitrep")))

        out[name] = gens

    return out
