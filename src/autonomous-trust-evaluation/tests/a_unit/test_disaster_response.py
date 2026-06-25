# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Verification suite for the multi-agency disaster-response demo.

Covers every functional checkpoint in demo-implementation-plan.md
§Verification that's exercisable without a live K8s cluster:

    * Scenario completes through all 9 phases without error
    * Bootstrap reputation ramp is visible (data generator drift + phase
      pacing -- the reputation process itself is tested elsewhere)
    * Compromise detection signal is statistically distinguishable within
      60s of onset (the core demo claim)
    * Exclusion event fires at the scripted time
    * EPA peer enters at join_phase=7 (T+6:00) -- the bootstrap trigger
    * Cross-source plausibility scoring actually rejects the rogue
    * DataFusionProcess trust-weighting suppresses the rogue's influence
    * Compose + K8s manifest generators produce valid YAML
    * PlaybackEngine replays recorded events into listeners
    * Dashboard layout, agency map, trust graph, event log, peer detail
      components render without live cohort

UI-level behavior (dash callbacks, real-time updates) is out of scope
for unit tests -- that lives in an integration harness (future work).
"""

from __future__ import annotations

import json
import os
import random
import statistics
import tempfile
from collections import defaultdict, deque
from datetime import timedelta

import pytest

from autonomous_trust.evaluation.scenarios.disaster_response import (
    AGENCY_COLORS,
    DisasterResponseScenario,
)
from autonomous_trust.evaluation.scenarios.disaster_response_data import (
    TYPE_PRECIPITATION,
    TYPE_PRESSURE,
    TYPE_TEMPERATURE,
    TYPE_WIND_SPEED,
    build_generators_for_scenario,
)


# ---------------------------------------------------------------------------
# Scenario structure
# ---------------------------------------------------------------------------

class TestScenarioStructure:
    def setup_method(self):
        self.s = DisasterResponseScenario()

    def test_peer_count(self):
        # Plan: 10 peers (3 honest NOAA + 1 rogue NOAA + 2 USGS + 3 FEMA + 1 EPA).
        assert len(self.s.peers) == 10

    def test_phase_count_and_order(self):
        phases = self.s.phases
        assert len(phases) == 9
        for i in range(1, len(phases)):
            assert phases[i].start >= phases[i - 1].start

    def test_phase_timeline_matches_plan(self):
        starts = {p.name: p.start.total_seconds() for p in self.s.phases}
        assert starts["Formation"]   == 0
        assert starts["Bootstrap"]   == 30
        assert starts["Negotiation"] == 90
        assert starts["Sharing"]     == 150
        assert starts["Compromise"]  == 240
        assert starts["Detection"]   == 270
        assert starts["Exclusion"]   == 300
        assert starts["Onboarding"]  == 360
        assert starts["Integration"] == 420

    def test_epa_is_late_joiner(self):
        epa = self.s.peers["epa-1"]
        assert epa.join_phase == 7
        assert epa.agency == "EPA"

    def test_rogue_peer_is_noaa_3(self):
        rogue = self.s.peers["noaa-3"]
        assert rogue.metadata.get("compromised") is True
        assert rogue.metadata["compromise_onset_sec"] == 240.0
        # All four weather modes advertised (so every data type gets falsified).
        modes = rogue.metadata["compromise_modes"]
        assert set(modes) == {
            "temperature_drift", "wind_spikes",
            "pressure_flatline", "precipitation_invert",
        }

    def test_agency_colors_match_css(self):
        # Demo CSS references agency colors by hex value; the scenario
        # module is the single source of truth, so diff here guards
        # against drift.
        assert AGENCY_COLORS == {
            "NOAA": "#1f77b4",
            "USGS": "#8c564b",
            "FEMA": "#d62728",
            "EPA":  "#2ca02c",
        }

    def test_full_run_applies_all_events(self):
        self.s.advance_to(timedelta(seconds=500))
        peer_states = self.s.peer_states
        # noaa-3 got excluded; everyone else is active (EPA onboarded)
        assert peer_states["noaa-3"].name == "EXCLUDED"
        assert peer_states["epa-1"].name == "ACTIVE"
        # Event log should include all phase annotations + explicit events
        types = {rec["type"] for rec in self.s.event_log}
        assert "PEER_JOIN" in types
        assert "COMPROMISE_START" in types
        assert "COMPROMISE_DETECT" in types
        assert "PEER_EXCLUDE" in types


# ---------------------------------------------------------------------------
# Compromise detection -- statistical plausibility
# ---------------------------------------------------------------------------

class TestCompromiseDetection:
    """Verify the compromise signal is distinguishable within the 60s
    SLA that the plan's verification test #4 demands."""

    def setup_method(self):
        self.s = DisasterResponseScenario()
        self.roster = build_generators_for_scenario(self.s)

    def _temp_samples(self, peer_name: str,
                      t_start: int, t_end: int) -> list[float]:
        out: list[float] = []
        for ts in range(t_start, t_end):
            for gen in self.roster[peer_name]:
                reading = gen.tick(timedelta(seconds=ts))
                if reading is not None and reading.data_type == TYPE_TEMPERATURE:
                    out.append(reading.value)
        return out

    def test_temperature_drift_visible_within_60s(self):
        roster = self.roster
        def temp(p): return [g for g in roster[p]
                             if getattr(g, 'data_type', None) == TYPE_TEMPERATURE
                             or 'temperature' in getattr(g.__class__, '__name__', '').lower()][0]

        # Tick everything from T+0 so generators warm up properly,
        # then compare honest vs rogue means over the first 60s post-onset.
        honest, rogue = [], []
        for ts in range(0, 310):
            t = timedelta(seconds=ts)
            # noaa-1 honest
            r1 = [g for g in self.roster['noaa-1'] if hasattr(g, 'tick')][0]
            r3_gens = self.roster['noaa-3']
            h = r1.tick(t)
            if h and h.data_type == TYPE_TEMPERATURE and 240 <= ts < 300:
                honest.append(h.value)
            for g in r3_gens:
                r = g.tick(t)
                if r and r.data_type == TYPE_TEMPERATURE and 240 <= ts < 300:
                    rogue.append(r.value)

        assert honest and rogue
        delta = statistics.fmean(rogue) - statistics.fmean(honest)
        # Plan claim: rogue drifts +5F over a 60s ramp. Post-onset window
        # average should be a few F higher than honest within 60s.
        assert delta > 1.5, (
            f"temperature bias too small within 60s of onset: {delta:.2f}F"
        )

    def test_pressure_flatlines_after_onset(self):
        # Pressure random-walks normally; the rogue freezes at onset.
        roster = self.roster
        rogue_vals: list[float] = []
        for ts in range(0, 400):
            t = timedelta(seconds=ts)
            for g in roster['noaa-3']:
                r = g.tick(t)
                if r and r.data_type == TYPE_PRESSURE:
                    rogue_vals.append(r.value)

        pre = [v for i, v in enumerate(rogue_vals) if i < 200]
        post = [v for i, v in enumerate(rogue_vals) if i >= 240]
        assert pre and post
        # Post-onset stddev should be effectively zero (flatline).
        assert statistics.pstdev(post) < 0.005, (
            f"pressure not flatlining; post-onset std={statistics.pstdev(post)}"
        )
        # And pre-onset should have clearly higher variability.
        assert statistics.pstdev(pre) > statistics.pstdev(post) * 4


# ---------------------------------------------------------------------------
# Cross-source corroboration
# ---------------------------------------------------------------------------

class TestSensorValidation:
    """The core defense-in-depth claim: no central rule flags the rogue;
    peers arrive at low scores via cross-source plausibility."""

    def test_rogue_reading_scores_low(self):
        from autonomous_trust.services.envdata.sensor_validation import (
            SensorValidationProcess,
        )
        from autonomous_trust.services.data.reading import Reading

        rng = random.Random(42)
        val = SensorValidationProcess.__new__(SensorValidationProcess)
        val._windows = defaultdict(lambda: deque(maxlen=20))

        # Three honest peers hovering around 55F with 0.8F noise.
        for peer in ("noaa-1", "noaa-2", "noaa-4"):
            for i in range(20):
                val.observe(Reading(timedelta(seconds=i), peer, "temperature",
                                    55.0 + rng.gauss(0, 0.8), "F"))

        honest = Reading(timedelta(20), "noaa-3", "temperature", 55.2, "F")
        rogue  = Reading(timedelta(20), "noaa-3", "temperature", 62.0, "F")

        assert val.plausibility(honest) > 0.85
        assert val.plausibility(rogue) < 0.15


class TestDataFusion:
    """FEMA fusion must reflect the trust weighting so low-reputation
    peers stop influencing the fused picture before exclusion."""

    def test_weighting_suppresses_rogue(self):
        from autonomous_trust.services.envdata.fusion import DataFusionProcess
        from autonomous_trust.services.data.reading import Reading

        fus = DataFusionProcess.__new__(DataFusionProcess)
        fus._inbound = defaultdict(lambda: deque(maxlen=30))
        fus._reputation = None
        fus._last_emit = -10.0
        fus._env_cfg = None
        fus._start_wall = None

        # 3 honest peers at 72F, 1 rogue at 80F.
        for peer, v in [("n1", 72.0), ("n2", 72.1),
                        ("n4", 71.9), ("n3", 80.0)]:
            for i in range(10):
                fus.ingest(Reading(timedelta(seconds=i), peer,
                                   "temperature", v, "F"))

        # Equal weights -> the rogue shifts the mean toward 80.
        unweighted = fus.tick_once(timedelta(seconds=10))
        fus._last_emit = -10.0
        assert unweighted["metadata"]["fused"]["temperature"] > 73.0

        # Drop rogue weight to 0 -> fused mean returns to ~72.0
        fus.set_reputation_lookup(lambda p: 0.0 if p == "n3" else 1.0)
        weighted = fus.tick_once(timedelta(seconds=20))
        assert abs(weighted["metadata"]["fused"]["temperature"] - 72.0) < 0.1


# ---------------------------------------------------------------------------
# Deployment generators
# ---------------------------------------------------------------------------

class TestComposeAndK8sGeneration:
    """Compose + K8s manifests roundtrip through YAML parsing cleanly
    and carry the compromise plumbing on the rogue service."""

    def test_compose_carries_compromise_env(self):
        from autonomous_trust.evaluation.scenarios.disaster_response_compose import (
            ComposeOptions, generate_compose,
        )
        yaml = generate_compose(DisasterResponseScenario(), ComposeOptions())
        assert "noaa-3:" in yaml
        assert 'AT_COMPROMISED: "1"' in yaml
        # All four modes listed on the rogue
        assert "temperature_drift" in yaml
        assert "pressure_flatline" in yaml

    def test_k8s_manifests_have_expected_agency_files(self):
        from autonomous_trust.evaluation.scenarios.disaster_response_compose import (
            generate_k8s_manifests,
        )
        files = generate_k8s_manifests(DisasterResponseScenario())
        # Per-agency + scenario config + namespace + inspector
        expected = {"noaa.yaml", "usgs.yaml", "fema.yaml", "epa.yaml",
                    "scenario-config.yaml", "namespace.yaml",
                    "inspector.yaml"}
        assert set(files.keys()) == expected
        assert "disaster-response-scenario" in files["scenario-config.yaml"]
        # Inspector manifest must carry both Deployment and NodePort Service.
        ins = files["inspector.yaml"]
        assert "kind: Deployment" in ins
        assert "kind: Service" in ins
        assert "type: NodePort" in ins
        assert "name: multi-agency-inspector" in ins

    def test_compose_scenario_export_is_json(self):
        # The compose generator writes a scenario.json the dashboard reads;
        # verify the roundtrip works on a tempdir.
        from autonomous_trust.evaluation.scenarios.disaster_response_compose import (
            write_all,
        )
        s = DisasterResponseScenario()
        with tempfile.TemporaryDirectory() as d:
            write_all(s, d)
            with open(os.path.join(d, "scenario", "scenario.json")) as f:
                payload = json.load(f)
            assert payload["name"] == s.name
            assert len(payload["peers"]) == 10
            assert len(payload["phases"]) == 9


# ---------------------------------------------------------------------------
# Playback engine + recording
# ---------------------------------------------------------------------------

class TestPlaybackEngine:
    def test_seek_fires_events(self):
        from autonomous_trust.evaluation.scenarios.playback_engine import (
            PlaybackEngine,
        )
        s = DisasterResponseScenario()
        engine = PlaybackEngine(s)
        seen: list[str] = []
        engine.on_event(lambda ev, t: seen.append(ev.event_type.name))
        engine.seek_to_phase("Compromise")
        # COMPROMISE_START must have fired when seeking past T+240.
        assert "COMPROMISE_START" in seen

    def test_record_and_replay_roundtrip(self):
        from unittest import mock

        from autonomous_trust.evaluation.scenarios import playback_engine as pe_mod
        from autonomous_trust.evaluation.scenarios.playback_engine import (
            PlaybackEngine, PlaybackMode,
        )
        from autonomous_trust.evaluation.scenarios.recording import (
            EventRecorder,
        )

        s = DisasterResponseScenario()
        engine = PlaybackEngine(s)
        rec = EventRecorder()
        engine.on_event(lambda ev, t: rec.record(ev))
        s.advance_to(timedelta(seconds=500))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as fh:
            path = fh.name
        try:
            rec.save(path, scenario=s)
            # Replay the *recording* into a fresh scenario. In PLAYBACK mode
            # load_recorded buffers the events and tick() drains them as
            # scenario time advances -- the scripted timeline is suppressed, so
            # whatever lands in `replayed` came from the recorded stream, not a
            # re-run of s2. tick() is wall-clock driven, so we control the
            # engine's monotonic clock to advance deterministically past the
            # recording's extent in a single tick.
            s2 = DisasterResponseScenario()
            engine2 = PlaybackEngine(s2, mode=PlaybackMode.PLAYBACK)
            replayed: list[str] = []
            engine2.on_event(lambda ev, t: replayed.append(ev.event_type.name))
            engine2.load_recorded(path)

            clock = {"t": 1000.0}
            with mock.patch.object(pe_mod.time, "monotonic",
                                   lambda: clock["t"]):
                engine2.play()             # anchors _last_wall at 1000
                clock["t"] += 100_000.0    # jump past the recording's extent
                engine2.tick()             # drains all deferred events

            assert replayed
            assert "COMPROMISE_START" in replayed
            assert "PEER_EXCLUDE" in replayed
        finally:
            os.unlink(path)

    def test_snapshot_roundtrip(self):
        """Reputation samples and sensor-reading snapshots written via
        EventRecorder.record_snapshot must survive a save/load cycle
        through PlaybackEngine and fire snapshot listeners in time
        order as the engine ticks past their timestamps.
        """
        from autonomous_trust.evaluation.scenarios.playback_engine import (
            PlaybackEngine, PlaybackMode,
        )
        from autonomous_trust.evaluation.scenarios.recording import (
            EventRecorder,
        )

        s = DisasterResponseScenario()
        rec = EventRecorder()
        # Two reputation samples + two sensor readings, intentionally
        # written out of order to confirm load_recorded sorts them.
        rec.record_snapshot({
            "t": 30.0, "type": "REPUTATION_SAMPLE",
            "peer": "noaa-1", "score": 0.62,
        })
        rec.record_snapshot({
            "t": 5.0, "type": "REPUTATION_SAMPLE",
            "peer": "noaa-1", "score": 0.50,
        })
        rec.record_snapshot({
            "t": 10.0, "type": "SENSOR_READING",
            "peer": "noaa-1", "data_type": "temperature",
            "value": 21.3, "unit": "C", "quality": 0.97,
            "metadata": {"sensor_id": "A"},
        })
        rec.record_snapshot({
            "t": 20.0, "type": "SENSOR_READING",
            "peer": "noaa-2", "data_type": "temperature",
            "value": 21.5, "unit": "C", "quality": 0.97,
            "metadata": {},
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as fh:
            path = fh.name
        try:
            rec.save(path, scenario=s)
            # Saved payload must carry the snapshot sidecar.
            with open(path) as f:
                payload = json.load(f)
            assert "snapshots" in payload
            assert len(payload["snapshots"]) == 4

            s2 = DisasterResponseScenario()
            engine = PlaybackEngine(s2, mode=PlaybackMode.PLAYBACK)
            received: list[dict] = []
            engine.on_snapshot(lambda snap, t: received.append(snap))
            engine.load_recorded(path)

            # Engine.tick() consumes the buffer as scenario_time
            # crosses each entry's t. Drive it by seeking past the
            # last snapshot in one go.
            engine.play()
            engine.seek(60.0)
            engine.tick()

            assert [s["t"] for s in received] == [5.0, 10.0, 20.0, 30.0]
            assert received[0]["type"] == "REPUTATION_SAMPLE"
            assert received[1]["type"] == "SENSOR_READING"
            assert received[1]["peer"] == "noaa-1"
            assert received[1]["metadata"] == {"sensor_id": "A"}
        finally:
            os.unlink(path)

    def test_tier_lost_event_routes_to_event_log(self):
        """A TIER_LOST record (peer's trust tier demoted) must:
          - Reconstruct as a PhaseEvent through PlaybackEngine.load_recorded
          - Render in EventLogPanel.add_from_event_record at warning severity
        Both halves of the new Phase 6 tier_lost path pinned here so a
        future PhaseEvent rename or severity-map edit fails fast.
        """
        from autonomous_trust.evaluation.scenarios.playback_engine import (
            PlaybackEngine, PlaybackMode,
        )
        from autonomous_trust.evaluation.scenarios.recording import (
            EventRecorder,
        )
        from autonomous_trust.evaluation.scenarios.scenario import PhaseEvent
        from autonomous_trust.inspector.dashboard.event_log import (
            EventLogPanel, SEVERITY_WARNING,
        )

        # 1. Enum hookup: TIER_LOST must be a PhaseEvent so load_recorded
        #    doesn't silently drop it.
        assert hasattr(PhaseEvent, "TIER_LOST")

        # 2. Event log routing: the record shape the DoD coordinator
        #    produces lands as a warning row.
        log = EventLogPanel()
        log.add_from_event_record({
            "t": 245.0,
            "type": "TIER_LOST",
            "peer": "mq800",
            "description": "mq800 tier 2 → 1 (access revoked)",
            "data": {"source": "tier_change"},
        })
        assert len(log.entries) == 1
        e = log.entries[0]
        assert e.severity == SEVERITY_WARNING
        assert e.peer_name == "mq800"
        assert "tier 2" in e.text and "→ 1" in e.text

        # 3. Playback round-trip: a recorded TIER_LOST record reloads
        #    into the engine's deferred_events buffer (no longer skipped
        #    by the PhaseEvent filter in load_recorded).
        rec = EventRecorder()
        rec.record({
            "t": 245.0,
            "type": "TIER_LOST",
            "peer": "mq800",
            "description": "mq800 tier 2 → 1 (access revoked)",
            "data": {"source": "tier_change"},
        })
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as fh:
            path = fh.name
        try:
            rec.save(path, scenario=DisasterResponseScenario())
            engine = PlaybackEngine(DisasterResponseScenario(),
                                    mode=PlaybackMode.PLAYBACK)
            received: list = []
            engine.on_event(lambda ev, t: received.append(ev))
            engine.load_recorded(path)
            engine.play()
            engine.seek(300.0)
            engine.tick()
            kinds = [ev.event_type.name for ev in received]
            assert "TIER_LOST" in kinds
        finally:
            os.unlink(path)

    def test_keystats_derived_from_scenario(self):
        from autonomous_trust.evaluation.scenarios.playback_engine import (
            PlaybackEngine,
        )
        from autonomous_trust.evaluation.scenarios.recording import (
            KeyStatTracker,
        )
        s = DisasterResponseScenario()
        engine = PlaybackEngine(s)
        tracker = KeyStatTracker()
        engine.on_event(lambda ev, t: tracker.observe(ev))
        s.advance_to(timedelta(seconds=500))

        # Scenario's scripted detection/exclusion: 30s detection, 60s exclusion.
        assert tracker.stats.detection_latency_sec == 30.0
        assert tracker.stats.exclusion_latency_sec == 60.0
        # Everyone joined once; noaa-3 excluded.
        assert tracker.stats.peers_joined == 10
        assert tracker.stats.peers_excluded == 1


# ---------------------------------------------------------------------------
# UI composability (no Dash callbacks fired)
# ---------------------------------------------------------------------------

class TestDashboardComposition:
    """Verify the dashboard components all build figures/HTML without a
    live cohort. Doesn't exercise Dash callbacks."""

    def test_layout_exposes_all_expected_ids(self):
        pytest.importorskip("dash_extensions")
        from autonomous_trust.inspector.dashboard.disaster_response_layout import (
            IDS, build_dashboard,
        )
        div = build_dashboard(DisasterResponseScenario())

        def walk(node, seen):
            if getattr(node, "id", None):
                seen.add(node.id)
            children = getattr(node, "children", None) or []
            if not isinstance(children, list):
                children = [children]
            for c in children:
                if hasattr(c, "children") or hasattr(c, "id"):
                    walk(c, seen)

        seen: set[str] = set()
        walk(div, seen)
        assert set(IDS.values()).issubset(seen)

    def test_agency_map_figure_builds(self):
        pytest.importorskip("plotly")
        from autonomous_trust.inspector.dashboard.disaster_response_map import (
            build_map_from_scenario,
        )
        fig = build_map_from_scenario(
            DisasterResponseScenario(),
            compromised={"noaa-3"},
            active_flows=[("noaa-1", "fema-fusion", "weather_stream")],
        )
        names = [t.name for t in fig.data if t.name]
        for agency in ("NOAA", "USGS", "FEMA", "EPA"):
            assert agency in names
        assert "compromise-pulse" in names

    def test_trust_graph_figure_builds(self):
        pytest.importorskip("plotly")
        from autonomous_trust.inspector.dashboard.disaster_response_graph import (
            build_graph_from_scenario,
        )
        fig = build_graph_from_scenario(
            DisasterResponseScenario(),
            trust_matrix=[
                ("noaa-1", "fema-fusion", 0.9),
                ("noaa-3", "fema-fusion", 0.2),
            ],
            compromised={"noaa-3"},
        )
        names = [t.name for t in fig.data if t.name]
        assert "compromise-pulse-graph" in names

    def test_event_log_color_codes_by_severity(self):
        from autonomous_trust.inspector.dashboard.event_log import (
            EventLogPanel,
        )
        s = DisasterResponseScenario()
        log = EventLogPanel()
        for ph in s.phases:
            for ev in ph.events:
                log.add_from_scenario_event(ev)
        html = log.to_html()
        # COMPROMISE_START -> warning, PEER_EXCLUDE -> threat
        assert "demo-event--warning" in html
        assert "demo-event--threat" in html

    def test_peer_detail_distinguishes_rogue_and_healthy(self):
        from autonomous_trust.inspector.dashboard.peer_detail import (
            IdentityInfo,
            PeerDetailPanel,
            PeerDetailState,
            ReputationSnapshot,
        )
        panel = PeerDetailPanel()
        healthy = panel.to_html(PeerDetailState(
            name="noaa-1", agency="NOAA", kind="weather-sensor",
            status="active",
            identity=IdentityInfo(uuid="u1", zta_valid=True),
            reputation=ReputationSnapshot(current_score=0.9),
        ))
        rogue = panel.to_html(PeerDetailState(
            name="noaa-3", agency="NOAA", kind="weather-sensor",
            status="compromised",
            identity=IdentityInfo(uuid="u3", zta_valid=True),
            reputation=ReputationSnapshot(current_score=0.15),
        ))
        assert "ACTIVE" in healthy
        assert "COMPROMISED" in rogue
        # ZTA credentials still read as valid in both (the attack claim).
        assert "valid" in healthy and "valid" in rogue
