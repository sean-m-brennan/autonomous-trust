# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Stage-1 civilian-demo runtime.

Stands up the Dash-based disaster-response dashboard driven by a
`PlaybackEngine`. Panels remain as 'loading' placeholders — only the
top-bar clock / phase / status are wired so the skeleton is visibly
advancing. Panel wiring is Stage 2.

Two modes:
    live        real wall-clock; scenario.advance_to fires scripted events.
    playback    load a recorded JSON event log and replay it on init.
"""

from __future__ import annotations

import logging
from typing import Optional

from autonomous_trust.evaluation.scenarios.disaster_response import (
    DisasterResponseScenario,
)
from autonomous_trust.evaluation.scenarios.playback_engine import (
    PlaybackEngine, PlaybackMode,
)
from autonomous_trust.evaluation.scenarios.scenario import PeerState

from dash_extensions.enrich import html, dcc, Input, Output

from .dash_components.core import DashControl
from .dashboard.disaster_response_layout import (
    IDS, build_dashboard, classify_status, format_clock, format_phase,
)


_TICK_INTERVAL_ID = "demo-tick"
_TICK_MS = 500  # UI frame rate — the engine handles wall time internally.

logger = logging.getLogger(__name__)


class CivilianDemo:
    """Dash server + PlaybackEngine wiring for the civilian demo.

    Stage 1: topbar-only callback. Panel bodies stay at their layout
    placeholders until the Stage-2 wiring lands.
    """

    def __init__(self, port: int, playback_file: Optional[str] = None,
                 host: str = "0.0.0.0"):
        self._port = port
        self._host = host
        self._playback_file = playback_file

        self._scenario = DisasterResponseScenario()
        mode = (PlaybackMode.PLAYBACK
                if playback_file else PlaybackMode.LIVE)
        self._engine = PlaybackEngine(self._scenario, mode=mode)

        if playback_file:
            self._engine.load_recorded(playback_file)

        self._dash = DashControl(
            name="autonomous_trust.inspector.civilian",
            title=self._scenario.name,
            host=host,
            port=port,
        )
        self._dash.app.layout = self._build_layout()
        self._register_callbacks()

    def _build_layout(self) -> html.Div:
        return html.Div(children=[
            dcc.Interval(id=_TICK_INTERVAL_ID,
                         interval=_TICK_MS, n_intervals=0),
            build_dashboard(scenario=self._scenario),
        ])

    def _register_callbacks(self):
        engine = self._engine
        scenario = self._scenario

        @self._dash.callback(
            Output(IDS["topbar_clock"], "children"),
            Output(IDS["topbar_phase"], "children"),
            Output(IDS["topbar_status"], "children"),
            Output(IDS["topbar_status"], "className"),
            Input(_TICK_INTERVAL_ID, "n_intervals"),
        )
        def _on_tick(_n):
            if not engine.playing:
                # Auto-start on first tick; user can pause later via
                # Stage-2 playback controls.
                engine.play()
            engine.tick()
            tel = engine.telemetry()
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
            return (
                format_clock(tel.scenario_time),
                format_phase(tel.current_phase_idx,
                             len(scenario.phases),
                             tel.current_phase_name),
                label,
                css,
            )

    def run(self):
        logger.info("Civilian demo serving on http://%s:%d/ (%s mode)",
                    self._host, self._port, self._engine.mode)
        self._dash.run(self._host, self._port)
