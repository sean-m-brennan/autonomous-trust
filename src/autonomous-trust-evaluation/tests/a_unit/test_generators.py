# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

import math
from datetime import timedelta

import pytest

from autonomous_trust.evaluation.generators import (
    SinusoidalGenerator,
    RandomWalkGenerator,
)


class TestSinusoidalGenerator:
    def test_baseline_at_zero_phase(self):
        gen = SinusoidalGenerator(
            'peer-1', 'temperature', 'C',
            baseline=20.0, amplitude=5.0, period_sec=100.0,
            cadence_sec=1.0, noise_stddev=0.0, seed=42,
        )
        reading = gen.tick(timedelta(seconds=0))
        assert reading is not None
        assert reading.value == pytest.approx(20.0, abs=1e-9)

    def test_peak_at_quarter_period(self):
        gen = SinusoidalGenerator(
            'peer-1', 'temperature', 'C',
            baseline=20.0, amplitude=5.0, period_sec=100.0,
            cadence_sec=1.0, noise_stddev=0.0, seed=42,
        )
        gen.tick(timedelta(seconds=0))  # consume first tick
        reading = gen.tick(timedelta(seconds=25))  # quarter period
        assert reading is not None
        assert reading.value == pytest.approx(25.0, abs=1e-9)

    def test_trough_at_three_quarter_period(self):
        gen = SinusoidalGenerator(
            'peer-1', 'temperature', 'C',
            baseline=20.0, amplitude=5.0, period_sec=100.0,
            cadence_sec=1.0, noise_stddev=0.0, seed=42,
        )
        gen.tick(timedelta(seconds=0))
        reading = gen.tick(timedelta(seconds=75))
        assert reading is not None
        assert reading.value == pytest.approx(15.0, abs=1e-9)

    def test_phase_offset(self):
        gen = SinusoidalGenerator(
            'peer-1', 'temperature', 'C',
            baseline=0.0, amplitude=1.0, period_sec=100.0,
            phase_offset=math.pi / 2,
            cadence_sec=1.0, noise_stddev=0.0, seed=42,
        )
        reading = gen.tick(timedelta(seconds=0))
        assert reading is not None
        # sin(pi/2) = 1.0
        assert reading.value == pytest.approx(1.0, abs=1e-9)

    def test_cadence_suppresses_early_tick(self):
        gen = SinusoidalGenerator(
            'peer-1', 'temperature', 'C',
            baseline=20.0, amplitude=5.0,
            cadence_sec=10.0, noise_stddev=0.0, seed=42,
        )
        r1 = gen.tick(timedelta(seconds=0))
        assert r1 is not None
        r2 = gen.tick(timedelta(seconds=5))
        assert r2 is None  # too early
        r3 = gen.tick(timedelta(seconds=10))
        assert r3 is not None

    def test_noise_changes_value(self):
        gen = SinusoidalGenerator(
            'peer-1', 'temperature', 'C',
            baseline=20.0, amplitude=0.0,
            cadence_sec=1.0, noise_stddev=2.0, seed=42,
        )
        reading = gen.tick(timedelta(seconds=0))
        assert reading is not None
        # With noise, value should differ from baseline
        # (seed=42 won't give exactly 0 noise)
        assert reading.value != 20.0

    def test_reading_metadata(self):
        gen = SinusoidalGenerator(
            'peer-1', 'temperature', 'C',
            baseline=20.0, amplitude=5.0,
            cadence_sec=1.0, noise_stddev=0.0, seed=42,
        )
        reading = gen.tick(timedelta(seconds=0))
        assert reading.peer_name == 'peer-1'
        assert reading.data_type == 'temperature'
        assert reading.unit == 'C'
        assert 0.95 <= reading.quality <= 1.0

    def test_reproducible_with_seed(self):
        def make():
            gen = SinusoidalGenerator(
                'peer-1', 'temperature', 'C',
                baseline=20.0, amplitude=5.0,
                cadence_sec=1.0, noise_stddev=1.0, seed=123,
            )
            return gen.tick(timedelta(seconds=0)).value
        assert make() == make()


class TestRandomWalkGenerator:
    def test_starts_at_mean(self):
        gen = RandomWalkGenerator(
            'peer-2', 'wind', 'm/s',
            mean=10.0, step_size=0.5,
            cadence_sec=1.0, noise_stddev=0.0, seed=42,
        )
        reading = gen.tick(timedelta(seconds=0))
        assert reading is not None
        # First value is mean + one step + revert (revert=0 at start)
        # Should be close to mean
        assert abs(reading.value - 10.0) <= 0.5

    def test_bounded(self):
        gen = RandomWalkGenerator(
            'peer-2', 'wind', 'm/s',
            mean=10.0, step_size=100.0,
            bounds=(5.0, 15.0),
            cadence_sec=1.0, noise_stddev=0.0, seed=42,
        )
        for i in range(50):
            reading = gen.tick(timedelta(seconds=i))
            if reading is not None:
                assert 5.0 <= reading.value <= 15.0 + abs(gen.trend * i)

    def test_trend_drift(self):
        gen = RandomWalkGenerator(
            'peer-2', 'wind', 'm/s',
            mean=0.0, step_size=0.0,  # no random walk
            trend=1.0,  # 1 unit/sec
            bounds=(-1e6, 1e6),
            cadence_sec=1.0, noise_stddev=0.0, seed=42,
        )
        r0 = gen.tick(timedelta(seconds=0))
        r10 = gen.tick(timedelta(seconds=10))
        assert r0 is not None and r10 is not None
        # At t=10, trend adds 10.0
        assert r10.value == pytest.approx(10.0, abs=0.2)

    def test_mean_reversion(self):
        gen = RandomWalkGenerator(
            'peer-2', 'aqi', 'ug/m3',
            mean=50.0, step_size=0.01,
            bounds=(0.0, 100.0),
            cadence_sec=1.0, noise_stddev=0.0, seed=42,
        )
        # Run many ticks - value should stay near mean
        values = []
        for i in range(200):
            r = gen.tick(timedelta(seconds=i))
            if r is not None:
                values.append(r.value)
        avg = sum(values) / len(values)
        assert abs(avg - 50.0) < 5.0

    def test_cadence(self):
        gen = RandomWalkGenerator(
            'peer-2', 'wind', 'm/s',
            mean=10.0, step_size=0.5,
            cadence_sec=5.0, seed=42,
        )
        assert gen.tick(timedelta(seconds=0)) is not None
        assert gen.tick(timedelta(seconds=3)) is None
        assert gen.tick(timedelta(seconds=5)) is not None
