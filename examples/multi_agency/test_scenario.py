#!/usr/bin/env python3
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
Verification tests for the multi-agency disaster response demo.

Exercises the scenario engine, data generators, compromise detection,
and playback recording/replay without requiring the full AT stack.
Run directly:  python -m examples.multi_agency.test_scenario
"""

import json
import os
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

# Ensure repo root is on path
_repo = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_repo))
from autonomous_trust.evaluation.scenarios.scenario import PeerState, PhaseEvent
from autonomous_trust.evaluation.generators import SinusoidalGenerator, RandomWalkGenerator
from autonomous_trust.evaluation.redteam.compromise import GradualDrift, AbruptDeviation
from autonomous_trust.evaluation.playback import EventRecorder, PlaybackEngine

from examples.multi_agency.scenario import DisasterResponseScenario
from examples.multi_agency.generators.weather import WeatherStationGenerators
from examples.multi_agency.generators.seismic import SeismicStationGenerators
from examples.multi_agency.generators.airquality import AirQualityGenerators
from examples.multi_agency.compromise.falsified_sensor import create_compromised_temperature
from examples.multi_agency.tasks.validation import CrossSourceValidator
from examples.multi_agency.tasks.data_sharing import ALL_TASKS


passed = 0
failed = 0

def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")


def test_scenario_definition():
    """Scenario has correct structure."""
    s = DisasterResponseScenario()
    check("9 peers defined", len(s.peers) == 9)
    check("9 phases defined", len(s.phases) == 9)
    check("duration > 7 minutes", s.duration.total_seconds() > 420)
    check("noaa-sensor-3 is compromised",
          s.peers["noaa-sensor-3"].metadata.get("compromised") is True)
    check("epa-monitor-1 joins in phase 7 (EPA Onboard)",
          s.peers["epa-monitor-1"].join_phase == 7)
    check("scenario exports as dict",
          "peers" in s.export_scenario_def())


def test_scenario_advancement():
    """Scenario fires events in correct order."""
    s = DisasterResponseScenario()
    events_fired = []
    s.on_event(lambda e: events_fired.append(e))

    # T+0: initial peers join (8 peers with join_phase=0; EPA joins later)
    s.advance_to(timedelta(seconds=1))
    join_events = [e for e in events_fired if e.event_type == PhaseEvent.PEER_JOIN]
    check("8 peers join at T+0", len(join_events) == 8)

    # T+4:00: compromise starts
    s.advance_to(timedelta(minutes=4, seconds=1))
    compromise = [e for e in events_fired if e.event_type == PhaseEvent.COMPROMISE_START]
    check("compromise event fires at T+4:00", len(compromise) == 1)
    check("compromise targets noaa-sensor-3",
          compromise[0].peer_name == "noaa-sensor-3")
    check("peer state is COMPROMISED",
          s.peer_states["noaa-sensor-3"] == PeerState.COMPROMISED)

    # T+5:00: exclusion
    s.advance_to(timedelta(minutes=5, seconds=1))
    exclusions = [e for e in events_fired if e.event_type == PhaseEvent.PEER_EXCLUDE]
    check("exclusion event fires at T+5:00", len(exclusions) == 1)
    check("excluded peer state",
          s.peer_states["noaa-sensor-3"] == PeerState.EXCLUDED)

    # T+6:00: EPA joins
    s.advance_to(timedelta(minutes=6, seconds=1))
    late_joins = [e for e in events_fired
                  if e.event_type == PhaseEvent.PEER_JOIN and e.peer_name == "epa-monitor-1"]
    check("EPA joins at T+6:00", len(late_joins) == 1)
    check("EPA peer state is ACTIVE",
          s.peer_states["epa-monitor-1"] == PeerState.ACTIVE)


def test_weather_generators():
    """Weather generators produce reasonable values."""
    gen = WeatherStationGenerators("noaa-sensor-1", seed=42)
    readings = []
    for sec in range(0, 300, 5):
        readings.extend(gen.tick(timedelta(seconds=sec)))

    types_seen = {r.data_type for r in readings}
    check("weather produces 4 data types",
          types_seen == {"temperature", "wind_speed", "pressure", "precipitation"})

    temps = [r.value for r in readings if r.data_type == "temperature"]
    check("temperature in reasonable range",
          all(15 < t < 45 for t in temps))

    pressures = [r.value for r in readings if r.data_type == "pressure"]
    check("pressure is declining",
          pressures[-1] < pressures[0])


def test_seismic_generators():
    """Seismic generators produce values."""
    gen = SeismicStationGenerators("usgs-monitor-1", seed=42)
    readings = []
    for sec in range(0, 300, 5):
        readings.extend(gen.tick(timedelta(seconds=sec)))

    types_seen = {r.data_type for r in readings}
    check("seismic produces magnitude + ground_velocity",
          {"magnitude", "ground_velocity"}.issubset(types_seen))


def test_airquality_generators():
    """Air quality generators produce values."""
    gen = AirQualityGenerators("epa-monitor-1", seed=42)
    readings = []
    for sec in range(0, 120, 5):
        readings.extend(gen.tick(timedelta(seconds=sec)))

    types_seen = {r.data_type for r in readings}
    check("AQ produces aqi + pm25 + ozone",
          {"aqi", "pm25", "ozone"}.issubset(types_seen))


def test_compromise_gradual():
    """Gradual drift produces increasing deviation over time."""
    # Create two generators with same seed — one honest, one compromised
    honest = create_compromised_temperature(mode="gradual", seed=42)
    honest.activate_at = timedelta(hours=99)  # never activates

    comp = create_compromised_temperature(mode="gradual", seed=42)

    # Compare readings at T+4:30 (30s after activation) and T+5:30 (90s after)
    honest_vals = {}
    comp_vals = {}
    for sec in range(0, 360, 5):
        t = timedelta(seconds=sec)
        h = honest.tick(t)
        c = comp.tick(t)
        if h:
            honest_vals[sec] = h.value
        if c:
            comp_vals[sec] = c.value

    # At T+4:30 (270s), drift = 0.5 * 0.5min = 0.25C
    # At T+5:30 (330s), drift = 0.5 * 1.5min = 0.75C
    check("gradual: readings at T+270 exist",
          270 in comp_vals and 270 in honest_vals)
    check("gradual: readings at T+330 exist",
          330 in comp_vals and 330 in honest_vals)

    if 270 in comp_vals and 330 in comp_vals:
        drift_270 = comp_vals[270] - honest_vals[270]
        drift_330 = comp_vals[330] - honest_vals[330]
        check("gradual: drift at T+5:30 > drift at T+4:30",
              drift_330 > drift_270)


def test_compromise_abrupt():
    """Abrupt deviation produces immediate large offset."""
    comp = create_compromised_temperature(mode="abrupt", seed=42)

    pre_reading = comp.tick(timedelta(seconds=235))
    post_reading = comp.tick(timedelta(seconds=245))

    check("abrupt: pre and post readings exist",
          pre_reading is not None and post_reading is not None)
    if pre_reading and post_reading:
        check("abrupt: post reading offset by ~15C",
              abs(post_reading.value - pre_reading.value) > 10)


def test_cross_source_validation():
    """Validator detects compromised sensor."""
    validator = CrossSourceValidator("temperature", threshold=5.0, min_sources=3)

    # Three honest sensors reading ~28C
    honest_1 = SinusoidalGenerator("s1", "temperature", "C", baseline=28, amplitude=1,
                                    period_sec=480, cadence_sec=5, seed=1)
    honest_2 = SinusoidalGenerator("s2", "temperature", "C", baseline=28, amplitude=1,
                                    period_sec=480, cadence_sec=5, seed=2)
    # Compromised sensor reading ~43C (offset +15)
    bad = SinusoidalGenerator("s3", "temperature", "C", baseline=43, amplitude=1,
                               period_sec=480, cadence_sec=5, seed=3)

    anomalies = []
    for sec in range(0, 60, 5):
        t = timedelta(seconds=sec)
        for gen in [honest_1, honest_2, bad]:
            r = gen.tick(t)
            if r:
                result = validator.submit(r)
                if result and result.is_anomalous:
                    anomalies.append(result)

    check("validator detects anomaly", len(anomalies) > 0)
    if anomalies:
        check("anomaly is from s3", anomalies[0].peer_name == "s3")
        check("deviation > threshold", anomalies[0].deviation > 5.0)


def test_playback_roundtrip():
    """Record and replay an event stream."""
    s = DisasterResponseScenario()

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        tmppath = f.name

    try:
        # Record
        with EventRecorder(tmppath) as recorder:
            s.on_event(recorder.record_event)
            s.advance_to(timedelta(minutes=5, seconds=1))

        # Verify file was written
        with open(tmppath) as f:
            lines = f.readlines()
        check("playback file has events", len(lines) > 5)

        # Replay
        engine = PlaybackEngine(tmppath)
        check("playback engine loaded frames",
              engine.frame_count > 5)
        check("playback duration > 0",
              engine.duration > 0)

        # Seek
        engine.seek(240.0)
        check("seek works", engine.current_time >= 240.0)

    finally:
        os.unlink(tmppath)


def test_task_definitions():
    """Task definitions are well-formed."""
    check("3 standard tasks defined", len(ALL_TASKS) == 3)
    for task in ALL_TASKS:
        d = task.to_dict()
        check(f"task {task.task_type} serializes",
              "task_type" in d and "required_capabilities" in d)


def main():
    print("=== Multi-Agency Demo Verification ===\n")

    test_scenario_definition()
    test_scenario_advancement()
    test_weather_generators()
    test_seismic_generators()
    test_airquality_generators()
    test_compromise_gradual()
    test_compromise_abrupt()
    test_cross_source_validation()
    test_playback_roundtrip()
    test_task_definitions()

    print(f"\n=== {passed + failed} checks, {failed} failures ===")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
