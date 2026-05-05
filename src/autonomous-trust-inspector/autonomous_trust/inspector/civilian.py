# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Civilian-demo runtime (Stages 1 + 2a + 2b + 2c).

Wires a Dash app to a PlaybackEngine driving DisasterResponseScenario.

Stage 1 wired: topbar clock / phase / status.
Stage 2a wired: playback controls, event log, narration overlay.
Stage 2b wired: agency map, trust timeline, peer detail drawer.
Stage 2c wired: trust network graph, data streams panel.
Stage 3 deferred: bridging real AT peer messages into the scenario.

Two modes:
    live        real wall clock; scripted scenario.advance_to events.
    playback    recorded JSON event log buffered + replayed over time
                via PlaybackEngine.load_recorded.
"""

from __future__ import annotations

import logging
import math
import queue as _queue
from datetime import datetime, timedelta
from typing import Optional

from autonomous_trust.evaluation.scenarios.disaster_response import (
    DisasterResponseScenario,
)
from autonomous_trust.services.data import Reading
from autonomous_trust.evaluation.scenarios.disaster_response_narration import (
    build_narration_script,
)
from autonomous_trust.evaluation.scenarios.playback_engine import (
    PlaybackEngine, PlaybackMode, ALLOWED_SPEEDS,
)
from autonomous_trust.evaluation.scenarios.scenario import PeerState

from dash import callback_context as ctx
from dash_extensions.enrich import (
    html, dcc, Input, Output, State, ALL, no_update,
)

from .dash_components.core import DashControl
from .dashboard.disaster_response_layout import (
    IDS, build_dashboard, classify_status, format_clock, format_phase,
)
from .dashboard.data_streams import DataStreamsPanel
from .dashboard.disaster_response_graph import build_graph_from_scenario
from .dashboard.disaster_response_map import build_map_from_scenario
from .dashboard.narration import NarrationOverlay, STYLE_COLORS
from .dashboard.peer_detail import (
    PeerDetailPanel, PeerDetailState, IdentityInfo, ReputationSnapshot,
)
from .dashboard.trust_timeline import TrustTimeline, ReputationSample


_TICK_INTERVAL_ID = "demo-tick"
_TICK_MS = 500

# Playback-control element IDs (local to this module).
_PB_PLAYPAUSE = "demo-pb-playpause"
_PB_SPEED = "demo-pb-speed"       # pattern-matched
_PB_PHASE = "demo-pb-phase"       # pattern-matched
_PB_PROGRESS_FILL = "demo-pb-progress-fill"
_PB_TIME_LABEL = "demo-pb-time"

# Stage-2b element IDs.
_MAP_GRAPH = "demo-map-graph"
_TIMELINE_GRAPH = "demo-timeline-graph"
_DETAIL_IFRAME = "demo-detail-iframe"
_SELECTED_PEER = "demo-selected-peer"   # dcc.Store payload key = "name"
_TICK_SAMPLE_SEC = 2.0  # how often the timeline samples reputation

# Stage-2c element IDs.
_GRAPH_GRAPH = "demo-trust-graph"
_STREAMS_IFRAME = "demo-streams-iframe"
_STREAMS_TICK_SEC = 1.0  # synthesize one reading per stream at 1 Hz

logger = logging.getLogger(__name__)


class CivilianDemo:
    """Dash server + PlaybackEngine wiring for the civilian demo."""

    def __init__(self, port: int, playback_file: Optional[str] = None,
                 host: str = "0.0.0.0", bridge_queue=None):
        self._port = port
        self._host = host
        self._playback_file = playback_file
        # Stage 3a: if set, drained each tick; live-mode only.
        self._bridge_queue = bridge_queue
        self._bridge_seen: set[str] = set()

        self._scenario = DisasterResponseScenario()
        mode = (PlaybackMode.PLAYBACK
                if playback_file else PlaybackMode.LIVE)
        self._engine = PlaybackEngine(self._scenario, mode=mode)

        if playback_file:
            self._engine.load_recorded(playback_file)

        self._narration = NarrationOverlay(script=build_narration_script())

        # Per-peer reputation history, appended each tick; drives the
        # trust-timeline panel. Live bridge events (Stage 3b.2) update
        # _rep_samples directly via _drain_bridge; peers that have
        # received at least one live observation are tracked in
        # _live_rep_peers so _sample_reputation skips them and falls
        # back to peer_state synthesis only for peers we haven't yet
        # observed (e.g. late joiners not yet in the AT group).
        self._rep_samples: dict[str, list[ReputationSample]] = {}
        self._last_sample_t: float = -_TICK_SAMPLE_SEC
        self._live_rep_peers: set[str] = set()
        # Stage 3b.3(a): bilateral observation matrix. Keys are
        # canonical (a, b) tuples (sorted) so a's view of b and b's view
        # of a collapse into one undirected edge weight. Value is the
        # latest pair-blended trust (currently min — skepticism wins).
        self._live_trust_matrix: dict[tuple[str, str], float] = {}
        self._live_trust_seen_dir: dict[tuple[str, str], float] = {}

        self._peer_detail_panel = PeerDetailPanel()
        self._streams_panel = DataStreamsPanel(
            peer_colors=_agency_palette(self._scenario))
        self._last_streams_t: float = -_STREAMS_TICK_SEC
        # Track which peers have been marked inactive in the streams
        # panel so we only mark once (mark_inactive is idempotent, but
        # avoiding the scan each tick is cheap).
        self._streams_inactive: set[str] = set()
        # Stage 3b.4: peers whose readings have arrived from real
        # EnvData* services via the bridge. _update_streams falls back
        # to synthesis only for peers we haven't yet observed.
        self._live_stream_peers: set[str] = set()

        self._dash = DashControl(
            name="autonomous_trust.inspector.civilian",
            title=self._scenario.name,
            host=host,
            port=port,
        )
        self._dash.app.layout = self._build_layout()
        self._register_callbacks()

    # --- layout ---------------------------------------------------------

    def _build_layout(self) -> html.Div:
        dashboard = build_dashboard(scenario=self._scenario)
        # Inject interactive children into the placeholder bodies that
        # build_dashboard() left empty.
        self._replace_child_by_id(
            dashboard, IDS["panel_playback"],
            self._playback_controls_children())
        self._replace_child_by_id(
            dashboard, IDS["panel_map"],
            dcc.Graph(id=_MAP_GRAPH,
                      config={"displayModeBar": False},
                      responsive=True,
                      style={"height": "100%", "width": "100%"}))
        self._replace_child_by_id(
            dashboard, IDS["panel_timeline"],
            dcc.Graph(id=_TIMELINE_GRAPH,
                      config={"displayModeBar": False},
                      responsive=True,
                      style={"height": "100%", "width": "100%"}))
        self._replace_child_by_id(
            dashboard, IDS["panel_detail"],
            html.Iframe(id=_DETAIL_IFRAME, srcDoc="",
                        style={"width": "100%", "height": "100%",
                               "border": "0", "background": "transparent"}))
        self._replace_child_by_id(
            dashboard, IDS["panel_graph"],
            dcc.Graph(id=_GRAPH_GRAPH,
                      config={"displayModeBar": False},
                      responsive=True,
                      style={"height": "100%", "width": "100%"}))
        self._replace_child_by_id(
            dashboard, IDS["panel_streams"],
            html.Iframe(id=_STREAMS_IFRAME, srcDoc="",
                        style={"width": "100%", "height": "100%",
                               "border": "0", "background": "transparent"}))
        return html.Div(children=[
            dcc.Interval(id=_TICK_INTERVAL_ID,
                         interval=_TICK_MS, n_intervals=0),
            dcc.Store(id=_SELECTED_PEER, data={"name": None}),
            dashboard,
        ])

    @staticmethod
    def _replace_child_by_id(root, target_id: str, new_children):
        """Recursively find `target_id` in a Dash component tree and set
        its `children` to `new_children`. Layout is built once so this
        is cheap."""
        stack = [root]
        while stack:
            node = stack.pop()
            if getattr(node, "id", None) == target_id:
                node.children = new_children
                return True
            kids = getattr(node, "children", None)
            if kids is None:
                continue
            if isinstance(kids, (list, tuple)):
                stack.extend(kids)
            else:
                stack.append(kids)
        return False

    def _playback_controls_children(self) -> html.Div:
        scenario = self._scenario
        duration = scenario.duration.total_seconds()
        phases = scenario.phases
        return html.Div(className="demo-pb", children=[
            html.Div(className="demo-pb__row", children=[
                html.Button("▶", id=_PB_PLAYPAUSE,
                            n_clicks=0, className="demo-pb__btn"),
                html.Div(className="demo-pb__speeds", children=[
                    html.Button(
                        f"{s:g}x",
                        id={"type": _PB_SPEED, "speed": s},
                        n_clicks=0,
                        className="demo-pb__speed",
                    )
                    for s in ALLOWED_SPEEDS
                ]),
                html.Div("T+00:00", id=_PB_TIME_LABEL,
                         className="demo-pb__time"),
                html.Div(f"/ {_format_mmss(duration)}",
                         className="demo-pb__duration"),
            ]),
            html.Div(className="demo-pb__progress", children=[
                html.Div(id=_PB_PROGRESS_FILL,
                         className="demo-pb__progress-fill",
                         style={"width": "0%"}),
            ]),
            html.Div(className="demo-pb__phases", children=[
                html.Button(
                    phase.name,
                    id={"type": _PB_PHASE,
                        "t": phase.start.total_seconds()},
                    n_clicks=0,
                    className="demo-pb__phase",
                )
                for phase in phases
            ]),
        ])

    # --- callbacks ------------------------------------------------------

    def _register_callbacks(self):
        engine = self._engine
        scenario = self._scenario
        narration = self._narration
        demo = self   # for callbacks that need mutable instance state

        @self._dash.callback(
            Output(IDS["topbar_clock"], "children"),
            Output(IDS["topbar_phase"], "children"),
            Output(IDS["topbar_status"], "children"),
            Output(IDS["topbar_status"], "className"),
            Output(IDS["panel_log"], "children"),
            Output(IDS["narration_overlay"], "children"),
            Output(IDS["narration_overlay"], "style"),
            Output(_PB_PLAYPAUSE, "children"),
            Output(_PB_TIME_LABEL, "children"),
            Output(_PB_PROGRESS_FILL, "style"),
            Output(_MAP_GRAPH, "figure"),
            Output(_TIMELINE_GRAPH, "figure"),
            Output(_DETAIL_IFRAME, "srcDoc"),
            Output(_GRAPH_GRAPH, "figure"),
            Output(_STREAMS_IFRAME, "srcDoc"),
            Input(_TICK_INTERVAL_ID, "n_intervals"),
            Input(_SELECTED_PEER, "data"),
        )
        def _on_tick(_n, selected):
            engine.tick()
            tel = engine.telemetry()
            demo._drain_bridge(tel.scenario_time)
            states = scenario.peer_states
            any_onboarding = any(
                s == PeerState.PENDING for s in states.values())
            any_detected = any(
                s in (PeerState.DETECTED, PeerState.EXCLUDED)
                for s in states.values())
            any_excluded = any(
                s == PeerState.EXCLUDED for s in states.values())
            label, css = classify_status(
                has_compromise_detected=any_detected,
                has_rogue_excluded=any_excluded,
                any_peer_onboarding=any_onboarding,
            )

            clock = format_clock(tel.scenario_time)
            phase_str = format_phase(tel.current_phase_idx,
                                     len(scenario.phases),
                                     tel.current_phase_name)
            log_children = _build_event_log(scenario.event_log)

            narration.advance_to(tel.scenario_time)
            nchildren, nstyle = _build_narration(narration.current_block)

            play_icon = "❚❚" if tel.playing else "▶"
            time_label = _format_mmss(tel.scenario_time)
            duration = tel.scenario_duration or 1.0
            pct = max(0.0, min(100.0,
                               100.0 * tel.scenario_time / duration))
            progress_style = {"width": f"{pct:.1f}%"}

            # Stage-2b panels.
            compromised = {n for n, s in states.items()
                           if s in (PeerState.COMPROMISED,
                                    PeerState.DETECTED)}
            excluded = {n for n, s in states.items()
                        if s == PeerState.EXCLUDED}
            # Late joiners (join_phase>0) default to opacity 0 in the
            # builders; we flip them to visible once they've transitioned
            # out of PENDING.
            peer_opacity = {n: 1.0 for n, s in states.items()
                            if s != PeerState.PENDING}
            map_fig = build_map_from_scenario(
                scenario,
                compromised=compromised,
                excluded=excluded,
                peer_opacity=peer_opacity,
            )
            # uirevision preserves pan/zoom across frames; the figure's
            # own autosize=True handles container fit via dcc.Graph.
            map_fig.update_layout(uirevision="demo-map")

            demo._sample_reputation(tel.scenario_time)
            timeline_fig = demo._build_timeline_figure()
            timeline_fig.update_layout(uirevision="demo-timeline")

            peer_name = (selected or {}).get("name") if selected else None
            detail_html = demo._build_peer_detail_html(peer_name)

            # Stage-2c: trust graph + data streams.
            # Stage 3b.3: live observations cap (and thus discount) any
            # edge touching a peer the bridge has scored — see
            # _build_trust_matrix.
            trust_matrix = demo._build_trust_matrix(scenario, states)
            stream_counts = _synth_stream_counts(scenario, states)
            graph_fig = build_graph_from_scenario(
                scenario,
                trust_matrix=trust_matrix,
                stream_counts=stream_counts,
                compromised=compromised,
                excluded=excluded,
                peer_opacity=peer_opacity,
            )
            graph_fig.update_layout(uirevision="demo-graph")
            demo._update_streams(tel.scenario_time, states)
            streams_html = demo._streams_panel.to_html(height="100%")

            return (clock, phase_str, label, css,
                    log_children, nchildren, nstyle,
                    play_icon, time_label, progress_style,
                    map_fig, timeline_fig, detail_html,
                    graph_fig, streams_html)

        @self._dash.callback(
            Output(_SELECTED_PEER, "data"),
            Input(_MAP_GRAPH, "clickData"),
            Input(_GRAPH_GRAPH, "clickData"),
            State(_SELECTED_PEER, "data"),
            prevent_initial_call=True,
        )
        def _on_peer_click(map_click, graph_click, current):
            # Dispatch by which input triggered; fall back to whichever
            # has a payload (initial fires on layout load).
            trig = ctx.triggered_id
            if trig == _MAP_GRAPH:
                click_data = map_click
            elif trig == _GRAPH_GRAPH:
                click_data = graph_click
            else:
                click_data = map_click or graph_click
            name = _peer_name_from_click(click_data)
            if name is None:
                return no_update
            if current and current.get("name") == name:
                return {"name": None}   # toggle-deselect
            return {"name": name}

        @self._dash.callback(
            Output(_PB_PLAYPAUSE, "n_clicks"),  # dummy sink
            Input(_PB_PLAYPAUSE, "n_clicks"),
            prevent_initial_call=True,
        )
        def _on_playpause(_n):
            engine.toggle()
            return no_update

        @self._dash.callback(
            Output({"type": _PB_SPEED, "speed": ALL}, "n_clicks"),
            Input({"type": _PB_SPEED, "speed": ALL}, "n_clicks"),
            State({"type": _PB_SPEED, "speed": ALL}, "id"),
            prevent_initial_call=True,
        )
        def _on_speed(_clicks, ids):
            # ctx.triggered_id tells us which one; ids has the speed value.
            tid = ctx.triggered_id
            if isinstance(tid, dict) and "speed" in tid:
                engine.set_speed(float(tid["speed"]))
            return [no_update] * len(ids)

        @self._dash.callback(
            Output({"type": _PB_PHASE, "t": ALL}, "n_clicks"),
            Input({"type": _PB_PHASE, "t": ALL}, "n_clicks"),
            State({"type": _PB_PHASE, "t": ALL}, "id"),
            prevent_initial_call=True,
        )
        def _on_phase_jump(_clicks, ids):
            tid = ctx.triggered_id
            if isinstance(tid, dict) and "t" in tid:
                engine.seek(float(tid["t"]))
                if not engine.playing:
                    engine.play()
            return [no_update] * len(ids)

    # --- Stage 2b data derivation ---------------------------------------

    def _sample_reputation(self, scenario_time: float):
        """Append a reputation sample for each peer based on current
        peer_state. Called every tick but only records a new data point
        every _TICK_SAMPLE_SEC seconds (keeps the timeline lean).

        Peers that have received at least one live reputation observation
        from the bridge are skipped — _drain_bridge writes their samples
        directly. The synthesis path remains for peers we haven't seen
        yet (late joiners, peers behind a partition)."""
        if scenario_time - self._last_sample_t < _TICK_SAMPLE_SEC:
            return
        self._last_sample_t = scenario_time
        for name, state in self._scenario.peer_states.items():
            if name in self._live_rep_peers:
                continue
            self._rep_samples.setdefault(name, []).append(
                ReputationSample(
                    t=scenario_time,
                    peer_name=name,
                    score=_peer_state_to_score(state),
                ))

    def _build_timeline_figure(self):
        peer_colors = _agency_palette(self._scenario)
        tl = TrustTimeline(peer_colors=peer_colors)
        for name, samples in self._rep_samples.items():
            for s in samples:
                tl.add_sample(s)
        for phase in self._scenario.phases:
            tl.add_phase_marker(phase.start.total_seconds(), phase.name)
        return tl.figure(height=None)  # let Dash size it to the panel

    def _build_trust_matrix(self, scenario,
                            states) -> list[tuple[str, str, float]]:
        """Build the pairwise trust matrix for the network graph.

        Three layers, in priority order:

        1. **Bilateral live (`_live_trust_matrix`)** — Stage 3b.3(a).
           Each peer's view of every other peer, gathered via remote
           rep_req. The edge weight is min(observer→subject,
           subject→observer) when both directions have arrived
           (skepticism-wins between the two directional views).
        2. **Inspector-observation cap (`_live_rep_peers`)** —
           Stage 3b.3(b). For pairs without bilateral data yet, edges
           are still capped at the latest single-direction observation
           the inspector has of either endpoint. This keeps the
           inspector's view visible until the bilateral round-trip
           lands.
        3. **Synth fallback (`_synth_trust_matrix`)** — Stage 2c.
           peer_state-derived; remains the baseline for pairs the
           bridge has not seen yet.
        """
        synth = _synth_trust_matrix(scenario, states)
        # Index synth so we can replace specific edges.
        synth_idx: dict[tuple[str, str], float] = {
            tuple(sorted((a, b))): score for a, b, score in synth
        }
        # Layer 1: bilateral live overrides the synth weight for those
        # pairs.
        for key, score in self._live_trust_matrix.items():
            if key in synth_idx:
                synth_idx[key] = score
        # Layer 2: cap remaining synth edges by single-direction
        # observation. Skip edges already replaced in layer 1.
        if self._live_rep_peers:
            latest: dict[str, float] = {}
            for name in self._live_rep_peers:
                samples = self._rep_samples.get(name)
                if samples:
                    latest[name] = samples[-1].score
            for key in list(synth_idx):
                if key in self._live_trust_matrix:
                    continue
                a, b = key
                weight = synth_idx[key]
                if a in latest:
                    weight = min(weight, latest[a])
                if b in latest:
                    weight = min(weight, latest[b])
                synth_idx[key] = weight
        return [(a, b, w) for (a, b), w in synth_idx.items()]

    def _build_peer_detail_html(self, peer_name: Optional[str]) -> str:
        if peer_name is None or peer_name not in self._scenario.peers:
            return self._peer_detail_panel.to_html(None)
        role = self._scenario.peers[peer_name]
        state = self._scenario.peer_states.get(peer_name, PeerState.PENDING)
        pos = role.position
        lat = (getattr(pos, "lat", None)
               or getattr(pos, "x", 0.0) or 0.0)
        lon = (getattr(pos, "lon", None)
               or getattr(pos, "y", 0.0) or 0.0)
        latest = None
        if peer_name in self._rep_samples and self._rep_samples[peer_name]:
            latest = self._rep_samples[peer_name][-1].score
        detail = PeerDetailState(
            name=peer_name,
            agency=role.agency,
            kind=role.kind,
            status=_peer_state_to_status(state),
            lat=float(lat),
            lon=float(lon),
            identity=IdentityInfo(zta_valid=(state != PeerState.EXCLUDED)),
            reputation=ReputationSnapshot(
                current_score=latest if latest is not None
                else _peer_state_to_score(state),
            ),
            capabilities=list(role.capabilities or []),
        )
        return self._peer_detail_panel.to_html(detail)

    def _drain_bridge(self, scenario_time: float) -> None:
        """Pull bridge observations into the scenario's event log as
        ANNOTATION events so they appear in the Event Log panel."""
        if self._bridge_queue is None:
            return
        wall = datetime.utcnow().isoformat()
        while True:
            try:
                ev = self._bridge_queue.get_nowait()
            except _queue.Empty:
                break
            except Exception:
                break
            if not ev:
                continue
            tag = ev[0]
            if tag == "peer_seen" and len(ev) >= 2:
                name = str(ev[1])
                if name in self._bridge_seen:
                    continue
                self._bridge_seen.add(name)
                desc = f"[live] peer observed: {name}"
            elif tag == "reputation" and len(ev) >= 3:
                name = str(ev[1])
                score = float(ev[2])
                desc = f"[live] {name} reputation = {score:.2f}"
                # Stage 3b.2: live observations drive the timeline panel
                # directly. Marking name as live in _live_rep_peers tells
                # _sample_reputation to stop synthesizing for it.
                self._rep_samples.setdefault(name, []).append(
                    ReputationSample(
                        t=scenario_time,
                        peer_name=name,
                        score=score,
                    ))
                self._live_rep_peers.add(name)
            elif tag == "rep_pair" and len(ev) >= 4:
                # Stage 3b.3(a) bilateral: observer's view of subject.
                # Cache directional, then combine into the undirected
                # edge weight via min (skepticism-wins).
                observer = str(ev[1])
                subject = str(ev[2])
                score = float(ev[3])
                if observer == subject:
                    continue
                self._live_trust_seen_dir[(observer, subject)] = score
                key = tuple(sorted((observer, subject)))
                opposite = self._live_trust_seen_dir.get(
                    (key[1], key[0]) if key[0] == observer
                    else (observer, subject))
                if opposite is None:
                    self._live_trust_matrix[key] = score
                else:
                    self._live_trust_matrix[key] = min(score, opposite)
                desc = (f"[live] {observer} ↔ {subject} trust "
                        f"= {score:.2f}")
                name = subject
            elif tag == "ping" and len(ev) >= 3:
                name = str(ev[1])
                rtt = float(ev[2])
                desc = f"[live] {name} rtt = {rtt:.0f}ms"
            elif tag == "reading" and len(ev) >= 3:
                # Stage 3b.4: forward an envdata reading into the streams
                # panel and mark the peer as live so _update_streams
                # stops synthesizing for it.
                name = str(ev[1])
                rd = ev[2] if isinstance(ev[2], dict) else {}
                reading = _reading_from_dict(name, rd)
                if reading is None:
                    continue
                self._streams_panel.update(reading)
                self._live_stream_peers.add(name)
                # Skip event-log emission for streams (they fire ~1 Hz
                # per peer per data type — would drown the log). Other
                # tags are far less frequent.
                continue
            self._scenario._event_log.append({     # noqa: SLF001
                "t": scenario_time,
                "type": "ANNOTATION",
                "peer": name,
                "description": desc,
                "data": {"source": "bridge", "tag": tag},
                "wall_time": wall,
            })

    def _update_streams(self, scenario_time: float,
                        peer_states: dict) -> None:
        """Push synthetic readings into the streams panel at 1 Hz, and
        mark excluded peers' streams as inactive as soon as they flip."""
        # Mark newly-excluded peers. Idempotent in the panel, but we
        # guard with a local set so we skip work once handled.
        for name, state in peer_states.items():
            if (state == PeerState.EXCLUDED
                    and name not in self._streams_inactive):
                self._streams_panel.mark_inactive(name)
                self._streams_inactive.add(name)

        if scenario_time - self._last_streams_t < _STREAMS_TICK_SEC:
            return
        self._last_streams_t = scenario_time
        ts = timedelta(seconds=scenario_time)
        for name, role in self._scenario.peers.items():
            state = peer_states.get(name, PeerState.PENDING)
            if state in (PeerState.PENDING, PeerState.EXCLUDED):
                continue
            # Stage 3b.4: when the bridge has delivered any real reading
            # from this peer, stop overlaying synthesized data on top of
            # it. This mirrors how _live_rep_peers gates _sample_reputation.
            if name in self._live_stream_peers:
                continue
            quality = _peer_state_to_quality(state)
            for reading in _readings_for_role(name, role, ts, quality,
                                              scenario_time):
                self._streams_panel.update(reading)

    # --- run ------------------------------------------------------------

    def run(self):
        logger.info("Civilian demo serving on http://%s:%d/ (%s mode)",
                    self._host, self._port, self._engine.mode)
        self._dash.run(self._host, self._port)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _format_mmss(seconds: float) -> str:
    if seconds is None or seconds < 0:
        seconds = 0
    m = int(seconds) // 60
    s = int(seconds) % 60
    return f"T+{m:02d}:{s:02d}"


_EVENT_SEVERITY_CLASS = {
    "COMPROMISE_START":  "demo-event demo-event--threat",
    "COMPROMISE_DETECT": "demo-event demo-event--warning",
    "PEER_EXCLUDE":      "demo-event demo-event--success",
    "PEER_JOIN":         "demo-event demo-event--info",
    "PEER_DEPART":       "demo-event demo-event--warning",
    "ANNOTATION":        "demo-event demo-event--annot",
}


def _build_event_log(event_log: list[dict]) -> list:
    """Render scenario.event_log (newest first) as a list of html.Divs."""
    if not event_log:
        return [html.Div("No events yet",
                         className="demo-placeholder")]
    items = []
    for rec in reversed(event_log[-200:]):  # cap at 200 newest
        t = float(rec.get("t", 0))
        etype = rec.get("type", "")
        text = rec.get("description") or etype
        cls = _EVENT_SEVERITY_CLASS.get(etype, "demo-event")
        items.append(html.Div(className=cls, children=[
            html.Span(_format_mmss(t), className="demo-event__time"),
            html.Span(text, className="demo-event__text"),
        ]))
    return items


def _build_narration(block) -> tuple[list, dict]:
    """Return (children, style) for the narration overlay.

    Hidden when `block` is None.
    """
    if block is None:
        return ([], {"display": "none"})
    colors = STYLE_COLORS.get(block.style, STYLE_COLORS["default"])
    style = {
        "display": "block",
        "position": "fixed",
        "bottom": "40px",
        "left": "50%",
        "transform": "translateX(-50%)",
        "maxWidth": "700px",
        "width": "90%",
        "background": colors["bg"],
        "border": f"1px solid {colors['border']}",
        "borderRadius": "10px",
        "padding": "16px 24px",
        "zIndex": 1000,
        "backdropFilter": "blur(8px)",
        "textAlign": "center",
    }
    children = [html.Div(block.text,
                         style={"fontSize": "16px",
                                "color": colors["text"],
                                "fontWeight": 500,
                                "lineHeight": "1.4"})]
    if block.subtext:
        children.append(html.Div(block.subtext,
                                 style={"fontSize": "13px",
                                        "color": colors["text"],
                                        "opacity": 0.8,
                                        "marginTop": "6px"}))
    return (children, style)


# --- Stage 2b helpers --------------------------------------------------

def _peer_state_to_score(state: PeerState) -> float:
    """Synthesize a 0-1 reputation from a scenario PeerState. Replace
    with live AT reputation data in Stage 3."""
    if state == PeerState.PENDING:
        return 0.0
    if state == PeerState.ACTIVE:
        return 1.0
    if state == PeerState.COMPROMISED:
        return 0.55   # noisy but not yet detected
    if state == PeerState.DETECTED:
        return 0.25   # below exclusion threshold (0.5)
    if state == PeerState.EXCLUDED:
        return 0.0
    return 0.5


def _peer_state_to_status(state: PeerState) -> str:
    if state == PeerState.PENDING:
        return "onboarding"
    if state in (PeerState.COMPROMISED, PeerState.DETECTED):
        return "compromised"
    if state == PeerState.EXCLUDED:
        return "excluded"
    return "active"


_AGENCY_COLORS = {
    "NOAA": "#1f77b4",
    "USGS": "#8c564b",
    "FEMA": "#d62728",
    "EPA":  "#2ca02c",
}


def _agency_palette(scenario) -> dict[str, str]:
    """Peer → color by agency, consistent with the map."""
    return {
        name: _AGENCY_COLORS.get(role.agency, "#888")
        for name, role in scenario.peers.items()
    }


def _peer_name_from_click(click_data) -> Optional[str]:
    """Extract the peer name from a Plotly clickData payload. Map and
    trust-graph traces both put the peer name in each point's `text`
    field."""
    if not click_data or "points" not in click_data:
        return None
    pts = click_data["points"]
    if not pts:
        return None
    return pts[0].get("text") or None


# --- Stage 2c helpers --------------------------------------------------

def _peer_state_to_quality(state: PeerState) -> float:
    if state == PeerState.ACTIVE:
        return 0.96
    if state == PeerState.COMPROMISED:
        return 0.60   # before detection: drift visible in quality only
    if state == PeerState.DETECTED:
        return 0.30
    return 1.0        # PENDING/EXCLUDED caller filters before reaching here


def _synth_trust_matrix(scenario, states) -> list[tuple[str, str, float]]:
    """Synthesize pairwise trust scores from peer_states. Stage 3 replaces
    this with real bilateral reputation from the AT reputation protocol."""
    names = list(scenario.peers.keys())
    matrix: list[tuple[str, str, float]] = []
    for i, a in enumerate(names):
        sa = states.get(a, PeerState.PENDING)
        if sa == PeerState.PENDING:
            continue
        for b in names[i + 1:]:
            sb = states.get(b, PeerState.PENDING)
            if sb == PeerState.PENDING:
                continue
            # Either side excluded -> very low.
            if PeerState.EXCLUDED in (sa, sb):
                matrix.append((a, b, 0.05))
                continue
            # Either side detected -> low.
            if PeerState.DETECTED in (sa, sb):
                matrix.append((a, b, 0.25))
                continue
            # Either side compromised (but not yet detected): mid.
            if PeerState.COMPROMISED in (sa, sb):
                matrix.append((a, b, 0.55))
                continue
            # Both active: strong trust.
            matrix.append((a, b, 0.9))
    return matrix


def _synth_stream_counts(scenario, states) -> dict[str, int]:
    """Each active peer counts one stream per streaming capability it has."""
    stream_caps = {"weather_stream", "seismic_stream",
                   "airquality_stream", "situation_report", "data_fusion"}
    counts: dict[str, int] = {}
    for name, role in scenario.peers.items():
        state = states.get(name, PeerState.PENDING)
        if state in (PeerState.PENDING, PeerState.EXCLUDED):
            counts[name] = 0
            continue
        caps = list(role.capabilities or [])
        counts[name] = sum(1 for c in caps if c in stream_caps)
    return counts


# Per-capability reading spec: (data_type, unit, base_value, amplitude)
_STREAM_SPECS: dict[str, tuple[str, str, float, float]] = {
    "weather_stream":     ("temperature", "C",        15.0, 4.0),
    "seismic_stream":     ("magnitude",   "Mw",        2.0, 0.6),
    "airquality_stream":  ("pm25",        "ug/m3",    30.0, 10.0),
    "situation_report":   ("incidents",   "count",     4.0, 2.0),
    "data_fusion":        ("fused_conf",  "score",     0.85, 0.05),
}


def _reading_from_dict(peer_name: str, d: dict) -> Optional[Reading]:
    """Inverse of Reading.to_dict() — used by the Stage 3b.4 bridge path
    to rehydrate envdata readings serialized over the wire.

    Returns None when required fields are missing; callers drop the
    event silently in that case (the streams panel is best-effort).
    """
    try:
        t = float(d.get("t", 0.0))
        dtype = str(d.get("type", ""))
        value = float(d.get("value", 0.0))
        unit = str(d.get("unit", ""))
        quality = float(d.get("quality", 1.0))
        # to_dict omits peer when peer_name is empty in some paths;
        # prefer the bridge's tagged name (carries the scenario nickname).
        peer = peer_name or str(d.get("peer", "?"))
    except (TypeError, ValueError):
        return None
    if not dtype:
        return None
    return Reading(
        timestamp=timedelta(seconds=t),
        peer_name=peer,
        data_type=dtype,
        value=value,
        unit=unit,
        quality=quality,
        metadata=dict(d.get("metadata") or {}),
    )


def _readings_for_role(name: str, role, ts: timedelta,
                       quality: float, t_sec: float) -> list[Reading]:
    """Build one synthetic Reading per streaming capability of this peer.

    Values oscillate around a base with a per-peer phase offset so the
    panel isn't visibly in lockstep. Compromised peers get degraded
    quality (already applied by caller) and a bigger drift component."""
    out: list[Reading] = []
    phase = hash(name) % 360  # stable offset per peer
    drift = 0.0 if quality > 0.8 else 1.5 * (1.0 - quality)
    for cap in (role.capabilities or []):
        spec = _STREAM_SPECS.get(cap)
        if spec is None:
            continue
        dtype, unit, base, amp = spec
        value = base + amp * math.sin(
            (t_sec + phase) * 2 * math.pi / 60.0) + drift
        out.append(Reading(
            timestamp=ts, peer_name=name,
            data_type=dtype, value=value, unit=unit,
            quality=quality,
        ))
    return out
