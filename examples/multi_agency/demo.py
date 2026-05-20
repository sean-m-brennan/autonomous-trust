# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Multi-agency-demo runtime.

Wires a Dash app to a PlaybackEngine driving DisasterResponseScenario.

Stage 1: topbar clock / phase / status.
Stage 2a: playback controls (play/pause, speed, phase jumps, progress,
          reset, spacebar shortcut), event log, narration overlay.
Stage 2b: agency map, trust timeline, peer detail drawer.
Stage 2c: trust network graph, data streams panel, sensor comparison
          chart embedded in the peer-detail drawer.
Stage 3 (live bridge): peer_seen, reputation, rep_pair, and reading
          observations from real AT peers are drained from
          `bridge_queue` each tick into the scenario event log,
          trust matrix, reputation samples, and streams panel.

Two modes:
    live        real wall clock; scripted scenario.advance_to events
                augmented by live bridge observations.
    playback    recorded JSON event log buffered + replayed over time
                via PlaybackEngine.load_recorded.
"""

from __future__ import annotations

import logging
import math
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading
from autonomous_trust.evaluation.scenarios.disaster_response_narration import (
    build_narration_script,
)
from autonomous_trust.evaluation.scenarios.playback_engine import ALLOWED_SPEEDS
from autonomous_trust.evaluation.scenarios.playback_iface import PlaybackInterface
from autonomous_trust.evaluation.scenarios.recording import KeyStatTracker
from autonomous_trust.evaluation.scenarios.scenario import PeerState

from dash import callback_context as ctx
from dash_extensions import Keyboard
from dash_extensions.enrich import (
    html, dcc, Input, Output, State, ALL, no_update,
)

from autonomous_trust.inspector.dash_components.core import DashControl
from autonomous_trust.inspector.dashboard.disaster_response_layout import (
    IDS, build_dashboard, format_clock, format_phase,
)
from autonomous_trust.inspector.dashboard.data_streams import DataStreamsPanel
from autonomous_trust.inspector.dashboard.disaster_response_graph import (
    build_graph_from_scenario,
)
from autonomous_trust.inspector.dashboard.disaster_response_map import (
    build_map_from_scenario,
)
from autonomous_trust.inspector.dashboard.event_log import EventLogPanel
from autonomous_trust.inspector.dashboard.narration import (
    NarrationOverlay, STYLE_COLORS,
)
from autonomous_trust.inspector.dashboard.peer_detail import (
    PeerDetailPanel, PeerDetailState, IdentityInfo, ReputationSnapshot,
    StreamSummary,
)
from autonomous_trust.inspector.dashboard.sensor_chart import (
    SensorComparisonChart,
)
from autonomous_trust.inspector.dashboard.trust_timeline import (
    TrustTimeline, ReputationSample,
)

import plotly.graph_objects as go
from collections import deque


_TICK_INTERVAL_ID = "demo-tick"
_TICK_MS = 500

# Playback-control element IDs (local to this module).
_PB_PLAYPAUSE = "demo-pb-playpause"
_PB_SPEED = "demo-pb-speed"       # pattern-matched
_PB_PHASE = "demo-pb-phase"       # pattern-matched
_PB_PROGRESS_FILL = "demo-pb-progress-fill"
_PB_TIME_LABEL = "demo-pb-time"
_PB_RESET = "demo-pb-reset"
_PB_KEYBOARD = "demo-pb-keyboard"  # dash_extensions.Keyboard (space → play/pause)

# Stage-2b element IDs.
_MAP_GRAPH = "demo-map-graph"
_TIMELINE_GRAPH = "demo-timeline-graph"
_DETAIL_IFRAME = "demo-detail-iframe"
_SELECTED_PEER = "demo-selected-peer"   # dcc.Store payload key = "name"
_TICK_SAMPLE_SEC = 2.0  # how often the timeline samples reputation

# Stage-2c element IDs.
_GRAPH_GRAPH = "demo-trust-graph"
_STREAMS_PANEL = "demo-streams-panel"
_STREAMS_TICK_SEC = 1.0  # synthesize one reading per stream at 1 Hz

# 3h sensor-comparison chart, embedded inside panel_detail. The chart
# lives in a sibling html.Details (Sensor Readings) below the iframe so
# it can be collapsed by the user; the iframe srcDoc cannot host Dash
# components directly.
_SENSOR_GRAPH = "demo-sensor-graph"
_SENSOR_DETAILS = "demo-sensor-details"
_SENSOR_HISTORY_MAX = 240  # ~4 minutes at 1 Hz; covers the 120s display window
# kind -> (primary stream data_type, unit) for the comparison chart.
# Keys match disaster_response peer roles; data types match _STREAM_SPECS.
_KIND_PRIMARY_DTYPE: dict[str, tuple[str, str]] = {
    "weather-sensor":      ("temperature", "C"),
    "seismic-monitor":     ("magnitude",   "Mw"),
    "air-quality-monitor": ("pm25",        "ug/m3"),
}

logger = logging.getLogger(__name__)


class MultiAgencyDemo:
    """Dash server for the multi-agency demo.

    Owns the dashboard layout + Dash callbacks + UI-derived state.
    The scenario clock, scripted events, live-bridge plumbing, and the
    optional event recorder all live in the ``PlaybackInterface``
    instance handed in. Other in-process scenarios can plug into the
    same machinery by supplying their own ``PlaybackInterface`` (or
    any ``ScenarioInterface``).
    """

    def __init__(self, iface: PlaybackInterface, port: int,
                 host: str = "0.0.0.0"):
        self._iface = iface
        self._port = port
        self._host = host

        self._narration = NarrationOverlay(script=build_narration_script())

        # Key-stat callouts. Listens to scenario events via the
        # interface so detection/exclusion latencies tick up live.
        # EPA onboarding sec is filled in via observe_reputation when
        # the rep score crosses the threshold — see
        # _maybe_observe_epa_onboard. The lambda reads
        # ``self._keystat_tracker`` at call time, so reset can swap
        # in a fresh tracker without re-registering.
        self._keystat_tracker = KeyStatTracker(
            compromised_peer="noaa-3", epa_peer="epa-1")
        iface.on_engine_event(
            lambda ev, t: self._keystat_tracker.observe(ev))

        # Per-peer reputation history, appended each tick; drives the
        # trust-timeline panel. Live bridge events update _rep_samples
        # via _on_bridge_event; peers that have received at least one
        # live observation are tracked in _live_rep_peers so
        # _sample_reputation skips them and falls back to peer_state
        # synthesis only for peers we haven't yet observed.
        self._rep_samples: dict[str, list[ReputationSample]] = {}
        self._last_sample_t: float = -_TICK_SAMPLE_SEC
        self._live_rep_peers: set[str] = set()
        # Bilateral observation matrix. Keys are canonical (a, b)
        # tuples (sorted) so a's view of b and b's view of a collapse
        # into one undirected edge weight. Value is the latest
        # pair-blended trust (currently min — skepticism wins).
        self._live_trust_matrix: dict[tuple[str, str], float] = {}
        self._live_trust_seen_dir: dict[tuple[str, str], float] = {}

        self._peer_detail_panel = PeerDetailPanel()
        # Last peer rendered into the detail iframe. The iframe
        # srcDoc is replaced on each render, which resets every
        # <details> tab to its default_open state — so we only
        # re-render when the selected peer actually changes (pull on
        # click). Sentinel value ("<unset>") differs from any real
        # peer name and from None, so the very first tick always
        # renders the empty placeholder.
        self._peer_detail_last_peer: object = "<unset>"
        self._event_log_panel = EventLogPanel(capacity=200)
        self._streams_panel = DataStreamsPanel(
            peer_colors=_agency_palette(iface.scenario))

        # Per-(data_type, peer) ring of recent Reading samples,
        # populated from both synth (_update_streams) and live (bridge).
        # Drives the SensorComparisonChart embedded in the peer-detail
        # drawer when a sensor peer is selected.
        self._sensor_history: dict[str, dict[str, deque]] = {}
        self._last_streams_t: float = -_STREAMS_TICK_SEC
        # Track which peers have been marked inactive in the streams
        # panel so we only mark once (mark_inactive is idempotent, but
        # avoiding the scan each tick is cheap).
        self._streams_inactive: set[str] = set()
        # Peers whose readings have arrived from real EnvData* services
        # via the bridge. _update_streams falls back to synthesis only
        # for peers we haven't yet observed.
        self._live_stream_peers: set[str] = set()

        # Identity facts captured from the bridge's first peer_seen
        # event for each peer. Tuple: (uuid_str, fingerprint_hex,
        # joined_at_seconds). Populated only in live mode; playback
        # peers fall back to '--' in the Peer Detail panel.
        self._peer_identity: dict[str, tuple[str, str, float]] = {}

        # Subscribe to the interface's event streams.
        iface.register_bridge_event_handler(self._on_bridge_event)
        iface.register_event_log_handler(
            self._event_log_panel.add_from_event_record)
        iface.register_reset_handler(self._on_reset)

        self._dash = DashControl(
            name="examples.multi_agency.demo",
            title=iface.scenario.name,
            host=host,
            port=port,
        )
        self._dash.app.layout = self._build_layout()
        self._register_callbacks()

    # --- layout ---------------------------------------------------------

    def _build_layout(self) -> html.Div:
        dashboard = build_dashboard(scenario=self._iface.scenario)
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
            html.Div(
                # Side-by-side: identity/reputation iframe on the left
                # (1/3), Sensor Readings chart on the right (2/3). The
                # iframe's body scrolls internally; the chart fills its
                # column. flex 1:2 splits the row exactly in those
                # proportions.
                style={"display": "flex", "flexDirection": "row",
                       "height": "100%", "gap": "6px"},
                children=[
                    html.Iframe(
                        id=_DETAIL_IFRAME, srcDoc="",
                        style={"flex": "1 1 0",
                               "minWidth": "0",
                               "height": "100%",
                               "border": "0",
                               "background": "transparent"}),
                    # Sensor comparison chart, wrapped in a real
                    # html.Details so its open/closed state is owned
                    # by Dash. The wrapper's own display:none hides
                    # the whole column for non-sensor peers; the
                    # remaining iframe stretches because flex:1 on it
                    # absorbs the freed space (the row's flex parent
                    # treats display:none siblings as absent).
                    html.Details(
                        id=_SENSOR_DETAILS,
                        open=True,
                        children=[
                            html.Summary(
                                "Sensor Readings",
                                style={
                                    "padding": "8px 12px",
                                    "cursor": "pointer",
                                    "color": "#94a3b8",
                                    "textTransform": "uppercase",
                                    "letterSpacing": "0.06em",
                                    "fontSize": "11px",
                                    "flex": "0 0 auto",
                                }),
                            dcc.Graph(
                                id=_SENSOR_GRAPH,
                                figure=go.Figure(),
                                config={"displayModeBar": False},
                                responsive=True,
                                style={"flex": "1 1 auto",
                                       "minHeight": "0",
                                       "width": "100%"}),
                        ],
                        style={"display": "none",
                               "flex": "2 1 0",
                               "minWidth": "0",
                               "flexDirection": "column",
                               "border": "1px solid #1f2a44",
                               "borderRadius": "6px",
                               "background": "#121a2e",
                               "overflow": "hidden"}),
                ],
            ))
        self._replace_child_by_id(
            dashboard, IDS["panel_graph"],
            dcc.Graph(id=_GRAPH_GRAPH,
                      config={"displayModeBar": False},
                      responsive=True,
                      style={"height": "100%", "width": "100%"}))
        # Native scrolling Div instead of an iframe srcDoc: Dash patches
        # this node's `children` in place each tick, so the wrapping
        # scrollable container keeps its identity and the user's scroll
        # position survives the refresh. (Iframe srcDoc replacement
        # tears down the whole document and forces a scroll-to-top.)
        self._replace_child_by_id(
            dashboard, IDS["panel_streams"],
            html.Div(id=_STREAMS_PANEL,
                     style={"width": "100%", "height": "100%",
                            "overflowY": "auto",
                            "background": "#1E1E2E",
                            "padding": "8px",
                            "borderRadius": "6px",
                            "fontSize": "11px",
                            "fontFamily": "monospace"}))
        return html.Div(children=[
            dcc.Interval(id=_TICK_INTERVAL_ID,
                         interval=_TICK_MS, n_intervals=0),
            dcc.Store(id=_SELECTED_PEER, data={"name": None}),
            # Document-level keyboard listener for the spacebar
            # play/pause shortcut. captureKeys filters at the JS layer
            # so the callback only fires for ' ' (Space).
            Keyboard(id=_PB_KEYBOARD, captureKeys=[" "]),
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
        scenario = self._iface.scenario
        duration = scenario.duration.total_seconds()
        phases = scenario.phases
        return html.Div(className="demo-pb", children=[
            html.Div(className="demo-pb__row", children=[
                html.Button("▶", id=_PB_PLAYPAUSE,
                            n_clicks=0, className="demo-pb__btn",
                            title="Play / Pause (space)"),
                html.Button("⟲", id=_PB_RESET,
                            n_clicks=0, className="demo-pb__btn",
                            title="Reset to T+0"),
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
        iface = self._iface
        scenario = iface.scenario
        narration = self._narration
        demo = self   # for callbacks that need mutable instance state

        @self._dash.callback(
            Output(IDS["topbar_clock"], "children"),
            Output(IDS["topbar_phase"], "children"),
            Output(IDS["topbar_keystats"], "children"),
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
            Output(_STREAMS_PANEL, "children"),
            Output(_SENSOR_GRAPH, "figure"),
            Output(_SENSOR_DETAILS, "style"),
            Input(_TICK_INTERVAL_ID, "n_intervals"),
            Input(_SELECTED_PEER, "data"),
        )
        def _on_tick(_n, selected):
            iface.tick()
            tel = iface.telemetry()
            states = scenario.peer_states

            clock = format_clock(tel.scenario_time)
            phase_str = format_phase(tel.current_phase_idx,
                                     len(scenario.phases),
                                     tel.current_phase_name)
            demo._maybe_observe_epa_onboard(tel.scenario_time)
            keystats_children = _render_keystat_chips(
                demo._keystat_tracker.stats.callouts())
            log_children = demo._event_log_panel.to_dash_children()

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
            # Only rebuild the peer-detail iframe when the selection
            # changes. The iframe's srcDoc replaces the whole document
            # on every assignment, which resets every <details> tab to
            # its default_open state — so a 500ms tick would constantly
            # snap the tabs back closed. Live data inside the iframe
            # is therefore a snapshot at click time; the sensor chart
            # below the iframe and the global Trust Dynamics / Data
            # Streams panels are the live-updating views.
            if peer_name != demo._peer_detail_last_peer:
                detail_html = demo._build_peer_detail_html(peer_name)
                demo._peer_detail_last_peer = peer_name
            else:
                detail_html = no_update
            sensor_fig, sensor_style = demo._build_sensor_chart(peer_name)

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
            streams_children = demo._streams_panel.to_dash_children()

            return (clock, phase_str, keystats_children,
                    log_children, nchildren, nstyle,
                    play_icon, time_label, progress_style,
                    map_fig, timeline_fig, detail_html,
                    graph_fig, streams_children,
                    sensor_fig, sensor_style)

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
            iface.toggle()
            return no_update

        @self._dash.callback(
            Output(_PB_KEYBOARD, "n_keydowns"),  # dummy sink
            Input(_PB_KEYBOARD, "n_keydowns"),
            State(_PB_KEYBOARD, "keydown"),
            prevent_initial_call=True,
        )
        def _on_keydown(_n, keydown):
            # captureKeys=[" "] ensures we only fire on Space, but
            # double-check the payload defensively (older
            # dash_extensions versions don't filter as advertised).
            if keydown and keydown.get("key") == " ":
                iface.toggle()
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
                iface.set_speed(float(tid["speed"]))
            return [no_update] * len(ids)

        @self._dash.callback(
            Output({"type": _PB_PHASE, "t": ALL}, "n_clicks"),
            Input({"type": _PB_PHASE, "t": ALL}, "n_clicks"),
            State({"type": _PB_PHASE, "t": ALL}, "id"),
            prevent_initial_call=True,
        )
        def _on_phase_jump(_clicks, ids):
            # Pause-and-explain: clicking a phase marker seeks to its
            # start and pauses, so the narration overlay (driven from
            # scenario time on the next tick) lingers on that phase's
            # callout. The presenter resumes with space or the play
            # button. This is the inverse of the previous "skip-and-
            # resume" behavior and matches the demo plan §6 spec.
            tid = ctx.triggered_id
            if isinstance(tid, dict) and "t" in tid:
                iface.seek(float(tid["t"]))
                iface.pause()
            return [no_update] * len(ids)

        @self._dash.callback(
            Output(_PB_RESET, "n_clicks"),  # dummy sink
            Input(_PB_RESET, "n_clicks"),
            prevent_initial_call=True,
        )
        def _on_reset(_n):
            demo._iface.reset()
            return no_update

    # --- Stage 2b data derivation ---------------------------------------

    def _sample_reputation(self, scenario_time: float):
        """Append a reputation sample for each peer based on current
        peer_state. Called every tick but only records a new data point
        every _TICK_SAMPLE_SEC seconds (keeps the timeline lean).

        Peers that have received at least one live reputation observation
        from the bridge are skipped — _on_bridge_event writes their
        samples directly. The synthesis path remains for peers we haven't seen
        yet (late joiners, peers behind a partition)."""
        if scenario_time - self._last_sample_t < _TICK_SAMPLE_SEC:
            return
        self._last_sample_t = scenario_time
        for name, state in self._iface.scenario.peer_states.items():
            if name in self._live_rep_peers:
                continue
            self._rep_samples.setdefault(name, []).append(
                ReputationSample(
                    t=scenario_time,
                    peer_name=name,
                    score=_peer_state_to_score(state),
                ))

    def _build_timeline_figure(self):
        peer_colors = _agency_palette(self._iface.scenario)
        tl = TrustTimeline(peer_colors=peer_colors)
        for name, samples in self._rep_samples.items():
            for s in samples:
                tl.add_sample(s)
        for phase in self._iface.scenario.phases:
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
        # Layer 1: bilateral live overrides synth — and is included
        # even when synth has no corresponding edge. This is the path
        # that surfaces real AT-mesh observations on the trust graph
        # before the scripted scenario has transitioned peers out of
        # PENDING (e.g. live mode early in the run, or paused before
        # play).
        for key, score in self._live_trust_matrix.items():
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
        if peer_name is None or peer_name not in self._iface.scenario.peers:
            return self._peer_detail_panel.to_html(None)
        role = self._iface.scenario.peers[peer_name]
        state = self._iface.scenario.peer_states.get(peer_name, PeerState.PENDING)
        pos = role.position
        lat = (getattr(pos, "lat", None)
               or getattr(pos, "x", 0.0) or 0.0)
        lon = (getattr(pos, "lon", None)
               or getattr(pos, "y", 0.0) or 0.0)
        latest = None
        if peer_name in self._rep_samples and self._rep_samples[peer_name]:
            latest = self._rep_samples[peer_name][-1].score
        uuid_str, fingerprint, joined_at = self._peer_identity.get(
            peer_name, ("", "", 0.0))
        detail = PeerDetailState(
            name=peer_name,
            agency=role.agency,
            kind=role.kind,
            status=_peer_state_to_status(state),
            lat=float(lat),
            lon=float(lon),
            identity=IdentityInfo(
                uuid=uuid_str,
                zta_valid=(state != PeerState.EXCLUDED),
                joined_at=joined_at,
                key_fingerprint=fingerprint,
            ),
            reputation=ReputationSnapshot(
                current_score=latest if latest is not None
                else _peer_state_to_score(state),
            ),
            capabilities=list(role.capabilities or []),
            producing=self._build_producing_streams(peer_name),
        )
        return self._peer_detail_panel.to_html(detail)

    def _build_producing_streams(self, peer_name: str) -> list:
        """Build StreamSummary objects for the selected peer.

        Reads the per-(data_type, peer) ring buffers in _sensor_history
        — populated from both bridge `reading` events and synth
        readings — and produces one StreamSummary per data_type the
        peer has emitted. Pull-style: only the selected peer's data
        is processed.
        """
        out = []
        for dtype, per_peer in self._sensor_history.items():
            ring = per_peer.get(peer_name)
            if not ring:
                continue
            recent = list(ring)
            values = [float(r.value) for r in recent[-32:]]
            latest = recent[-1]
            unit = latest.unit or ""
            quality = float(latest.quality) if latest.quality is not None else 1.0
            cadence = 1.0
            if len(recent) >= 2:
                first_t = recent[0].timestamp.total_seconds()
                last_t = latest.timestamp.total_seconds()
                if last_t > first_t:
                    cadence = (last_t - first_t) / max(1, len(recent) - 1)
            out.append(StreamSummary(
                data_type=dtype,
                unit=unit,
                cadence_sec=cadence,
                recent_values=values,
                direction="producing",
                quality=quality,
            ))
        out.sort(key=lambda s: s.data_type)
        return out

    def _on_bridge_event(self, ev: tuple) -> None:
        """Handle one drained bridge tuple (fired by ``PlaybackInterface``).

        Updates the UI-derived state (timeline samples, trust matrix,
        sensor history, streams panel). The interface itself is
        responsible for annotating the scenario event log; we only
        consume the raw tuple.
        """
        if not ev:
            return
        tag = ev[0]
        scenario_time = self._iface.current_time
        if tag == "peer_seen" and len(ev) >= 2:
            name = str(ev[1])
            uuid_str = str(ev[2]) if len(ev) >= 3 else ""
            fingerprint = str(ev[3]) if len(ev) >= 4 else ""
            # First sighting wins; later peer_seen re-fires shouldn't
            # overwrite the join time (the bridge dedupes via
            # self._seen, but be defensive).
            if name not in self._peer_identity:
                self._peer_identity[name] = (uuid_str, fingerprint,
                                             scenario_time)
                # If this is the currently-selected peer, force a
                # one-shot re-render of the detail iframe so the new
                # UUID/fingerprint show up without requiring a re-click.
                if self._peer_detail_last_peer == name:
                    self._peer_detail_last_peer = "<unset>"
        elif tag == "reputation" and len(ev) >= 3:
            name = str(ev[1])
            score = float(ev[2])
            self._rep_samples.setdefault(name, []).append(
                ReputationSample(
                    t=scenario_time,
                    peer_name=name,
                    score=score,
                ))
            self._live_rep_peers.add(name)
            # Iframe srcDoc is rebuilt only when the selected peer
            # changes (see comment near the tick callback). Without
            # this nudge, the Reputation tab shows the score that was
            # current at click time, which drifts from the live value
            # surfaced in the Event Log. Forcing a re-render on each
            # bridge update for the selected peer keeps the two views
            # in sync; the cost is that any <details> tab the user
            # had open in the iframe resets — acceptable since the
            # bridge's 0.05 debounce keeps reputation events sparse.
            if self._peer_detail_last_peer == name:
                self._peer_detail_last_peer = "<unset>"
        elif tag == "rep_pair" and len(ev) >= 4:
            # Bilateral: observer's view of subject. Cache directional,
            # then combine into the undirected edge weight via min
            # (skepticism-wins).
            observer = str(ev[1])
            subject = str(ev[2])
            score = float(ev[3])
            if observer == subject:
                return
            self._live_trust_seen_dir[(observer, subject)] = score
            key = tuple(sorted((observer, subject)))
            opposite = self._live_trust_seen_dir.get(
                (key[1], key[0]) if key[0] == observer
                else (observer, subject))
            if opposite is None:
                self._live_trust_matrix[key] = score
            else:
                self._live_trust_matrix[key] = min(score, opposite)
        elif tag == "reading" and len(ev) >= 3:
            # envdata reading: forward to the streams panel and mark
            # the peer as live so _update_streams stops synthesizing.
            name = str(ev[1])
            rd = ev[2] if isinstance(ev[2], dict) else {}
            reading = _reading_from_dict(name, rd)
            if reading is None:
                return
            self._streams_panel.update(reading)
            self._record_reading(reading)
            self._live_stream_peers.add(name)

    def _on_reset(self) -> None:
        """Clear UI-derived state. Fired by ``PlaybackInterface.reset()``
        after the engine has been rewound and bridge bookkeeping cleared.

        ``KeyStatTracker`` is event-driven: replacing the instance is
        the cleanest way to clear its accumulated state; the lambda
        registered via ``iface.on_engine_event`` reads
        ``self._keystat_tracker`` at call time so it picks up the new
        instance automatically.
        """
        self._keystat_tracker = KeyStatTracker(
            compromised_peer=self._keystat_tracker._compromised,  # noqa: SLF001
            epa_peer=self._keystat_tracker._epa)                  # noqa: SLF001
        self._event_log_panel.clear()
        self._rep_samples.clear()
        self._last_sample_t = -_TICK_SAMPLE_SEC
        self._sensor_history.clear()
        self._live_rep_peers.clear()
        self._live_trust_matrix.clear()
        self._live_trust_seen_dir.clear()
        self._live_stream_peers.clear()
        self._peer_identity.clear()
        # Streams panel has no clear() of its own; rebuilding is the
        # cheapest way to drop accumulated stream state and inactive
        # markers.
        self._streams_panel = DataStreamsPanel(
            peer_colors=_agency_palette(self._iface.scenario))
        self._streams_inactive.clear()
        self._last_streams_t = -_STREAMS_TICK_SEC
        self._narration.advance_to(0.0)
        # Force a re-render of the peer detail iframe on the next tick
        # so the user sees the post-reset state if a peer was selected.
        self._peer_detail_last_peer = "<unset>"

    def _record_reading(self, reading: Reading) -> None:
        """Append a reading to the per-(data_type, peer) ring used by
        the sensor comparison chart. Stores the full Reading so the
        chart's `add_reading` API can pull `timestamp` and `value`
        without extra unpacking."""
        if not reading or not reading.data_type or not reading.peer_name:
            return
        per_type = self._sensor_history.setdefault(reading.data_type, {})
        ring = per_type.get(reading.peer_name)
        if ring is None:
            ring = deque(maxlen=_SENSOR_HISTORY_MAX)
            per_type[reading.peer_name] = ring
        ring.append(reading)

    def _build_sensor_chart(self, peer_name: Optional[str]
                            ) -> tuple[go.Figure, dict]:
        """Build the sensor comparison figure (and its container style)
        for the panel-detail drawer.

        The returned style applies to the html.Details wrapper, not the
        Graph itself: the wrapper hides the entire "Sensor Readings"
        disclosure for non-sensor peers and shows it (preserving the
        user's open/closed state) for sensors with readings.
        """
        # Hidden: wrapper collapses; the iframe sibling absorbs the
        # full row width. Visible: wrapper is a 2/3-width flex column
        # (summary + chart); minWidth:0 lets the chart shrink instead
        # of overflowing the row.
        hidden_style = {"display": "none", "flex": "2 1 0",
                        "minWidth": "0",
                        "flexDirection": "column",
                        "border": "1px solid #1f2a44",
                        "borderRadius": "6px",
                        "background": "#121a2e",
                        "overflow": "hidden"}
        visible_style = {"display": "flex", "flex": "2 1 0",
                         "minWidth": "0",
                         "flexDirection": "column",
                         "border": "1px solid #1f2a44",
                         "borderRadius": "6px",
                         "background": "#121a2e",
                         "overflow": "hidden"}
        if peer_name is None or peer_name not in self._iface.scenario.peers:
            return (go.Figure(), hidden_style)
        role = self._iface.scenario.peers[peer_name]
        spec = _KIND_PRIMARY_DTYPE.get(role.kind)
        if spec is None:
            return (go.Figure(), hidden_style)
        dtype, unit = spec
        per_peer = self._sensor_history.get(dtype) or {}
        # Need at least the selected peer's own readings to be useful.
        if peer_name not in per_peer or not per_peer[peer_name]:
            return (go.Figure(), hidden_style)

        chart = SensorComparisonChart(
            data_type=dtype,
            unit=unit,
            peer_colors=_agency_palette(self._iface.scenario),
            window_sec=120.0,
            title=f"{dtype.replace('_', ' ').title()} — {peer_name} vs corroborators",
            highlight_peer=peer_name,
        )
        # Limit overlay to peers of the same kind (e.g. compare NOAA-3
        # against the other NOAA weather sensors). Cross-agency peers
        # producing the same data_type are still useful corroborators
        # but get noisy quickly; matching by kind keeps the chart clean.
        for other_name, ring in per_peer.items():
            other_role = self._iface.scenario.peers.get(other_name)
            if other_role is None or other_role.kind != role.kind:
                continue
            for reading in ring:
                chart.add_reading(reading)

        # Mark anomalous traces using the COMPROMISE_DETECT timestamp
        # from the scenario log so the shading lines up with what the
        # event log shows.
        detect_t = _detection_time(self._iface.scenario, peer_name)
        if detect_t is not None:
            chart.mark_anomalous(peer_name, t=detect_t)

        fig = chart.figure(width=None, height=None)
        # Strip the chart's hard-coded width/height so dcc.Graph's
        # responsive=true sizes the figure to the panel column (now
        # 2/3 of panel_detail height). Margins tightened so the title
        # and legend don't crowd the plot at smaller heights.
        fig.update_layout(width=None, height=None, autosize=True,
                          margin=dict(l=40, r=12, t=30, b=40))
        return (fig, visible_style)

    def _maybe_observe_epa_onboard(self, scenario_time: float) -> None:
        """Forward the most recent EPA reputation reading (live or synth)
        into KeyStatTracker.observe_reputation so it can fix the
        epa_onboard_sec timestamp the first time the score crosses
        the threshold. KeyStatTracker is idempotent past the first
        crossing, so this is cheap to call every tick."""
        epa = self._keystat_tracker._epa  # noqa: SLF001
        samples = self._rep_samples.get(epa)
        if not samples:
            return
        latest = samples[-1]
        self._keystat_tracker.observe_reputation(
            peer=epa, score=float(latest.score), t_seconds=scenario_time)

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
        for name, role in self._iface.scenario.peers.items():
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
                self._record_reading(reading)

    # --- run ------------------------------------------------------------

    def run(self):
        logger.info("Multi-agency demo serving on http://%s:%d/ (%s mode)",
                    self._host, self._port, self._iface.mode)
        self._iface.start()
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


def _render_keystat_chips(callouts: list[tuple[str, str]]) -> list:
    """Convert KeyStats.callouts() → a list of html.Div chips.

    Empty list when the scenario has no callouts yet (fresh start).
    Each chip is a flex row with a small label + monospace value;
    styling lives in demo.css under .demo-keystat-chip*."""
    if not callouts:
        return []
    chips = []
    for label, value in callouts:
        chips.append(html.Div(
            className="demo-keystat-chip",
            children=[
                html.Span(label, className="demo-keystat-chip__label"),
                html.Span(value, className="demo-keystat-chip__value"),
            ],
        ))
    return chips


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

def _detection_time(scenario, peer_name: str) -> Optional[float]:
    """Return scenario-seconds at which COMPROMISE_DETECT fired for
    `peer_name`, or None if it hasn't fired yet."""
    for rec in scenario._event_log:           # noqa: SLF001
        if (rec.get("type") == "COMPROMISE_DETECT"
                and rec.get("peer") == peer_name):
            return float(rec.get("t", 0.0))
    return None


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
