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
Full-screen presentation layout for the multi-agency demo.

Arranges all dashboard components into a single-page dark-themed layout
optimized for projection / screen sharing.  The layout is:

    +-----------------------------------------------+
    | Title bar              [NOAA] [USGS] [FEMA]   |
    +-------------------+---------------------------+
    |                   |  Trust Dynamics Timeline   |
    |   Agency Map      +---------------------------+
    |   (Mapbox)        |  Temperature Comparison   |
    |                   +---------------------------+
    +-------------------+  Event Log | Data Streams |
    |   Playback Controls                           |
    +-----------------------------------------------+
    |   [Narration Overlay]                         |
    +-----------------------------------------------+

This module generates the layout as nested HTML/CSS.  When integrated
with the inspector's Dash app, each section becomes a Dash component
(dcc.Graph, html.Div, etc.).  For standalone development, it renders
a static HTML preview.
"""

from __future__ import annotations

from typing import Optional

from autonomous_trust.inspector.dashboard.narration import NarrationOverlay
from autonomous_trust.inspector.dashboard.playback_controls import PlaybackControls, PlaybackState
from examples.multi_agency.dashboard.narration_script import MULTI_AGENCY_NARRATION
from examples.multi_agency.scenario import (
    DisasterResponseScenario,
    NOAA_BLUE, USGS_GREEN, FEMA_ORANGE, EPA_PURPLE,
)


AGENCY_LEGEND = [
    ("NOAA", NOAA_BLUE),
    ("USGS", USGS_GREEN),
    ("FEMA", FEMA_ORANGE),
    ("EPA",  EPA_PURPLE),
]


class PresentationLayout:
    """Generates the full-screen presentation layout.

    Usage:
        layout = PresentationLayout(scenario)
        # In the tick loop, update components then:
        html = layout.render(
            map_html="<div>map placeholder</div>",
            timeline_fig=timeline.figure(),
            temp_fig=temp_chart.figure(),
            event_html=event_log.to_html(),
            streams_html=streams.to_html(),
            detail_html=detail.render(selected_peer),
            playback_state=PlaybackState(...),
            t_seconds=current_time,
        )
    """

    def __init__(self, scenario: DisasterResponseScenario):
        self._scenario = scenario
        self._narration = NarrationOverlay(script=MULTI_AGENCY_NARRATION)
        self._playback = PlaybackControls(
            phases=[(p.name, p.start.total_seconds()) for p in scenario.phases],
            duration=scenario.duration.total_seconds(),
        )
        self._presentation_mode = True

    def toggle_presentation_mode(self):
        self._presentation_mode = not self._presentation_mode
        self._narration.toggle_visibility()

    def render(
        self,
        map_html: str = "",
        timeline_html: str = "",
        temp_chart_html: str = "",
        event_html: str = "",
        streams_html: str = "",
        detail_html: str = "",
        playback_state: Optional[PlaybackState] = None,
        t_seconds: float = 0.0,
    ) -> str:
        """Render the complete presentation layout as HTML."""
        # Update playback controls
        if playback_state:
            self._playback.update(playback_state)

        # Update narration
        self._narration.advance_to(t_seconds)
        narration_html = self._narration.to_html() if self._presentation_mode else ""

        return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AutonomousTrust — Disaster Response Demo</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        background: #0F172A;
        color: #E2E8F0;
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
        overflow: hidden;
        height: 100vh;
    }}
    .layout {{
        display: grid;
        grid-template-rows: 48px 1fr auto;
        height: 100vh;
    }}
    .title-bar {{
        display: flex;
        align-items: center;
        padding: 0 16px;
        background: #1E293B;
        border-bottom: 1px solid #334155;
    }}
    .title-bar h1 {{
        font-size: 16px;
        font-weight: 600;
        color: #F1F5F9;
        flex: 1;
    }}
    .legend {{
        display: flex;
        gap: 12px;
    }}
    .legend-item {{
        display: flex;
        align-items: center;
        gap: 4px;
        font-size: 11px;
        color: #94A3B8;
    }}
    .legend-dot {{
        width: 8px;
        height: 8px;
        border-radius: 50%;
    }}
    .main-grid {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        grid-template-rows: 1fr 1fr;
        gap: 8px;
        padding: 8px;
        overflow: hidden;
    }}
    .panel {{
        background: #1E1E2E;
        border-radius: 8px;
        padding: 8px;
        overflow: hidden;
    }}
    .panel-title {{
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #64748B;
        margin-bottom: 4px;
    }}
    .map-panel {{
        grid-row: 1 / 3;
    }}
    .bottom-row {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
    }}
    .controls-bar {{
        padding: 8px 16px;
        border-top: 1px solid #334155;
    }}
</style>
</head>
<body>
<div class="layout">
    <!-- Title Bar -->
    <div class="title-bar">
        <h1>AutonomousTrust — Multi-Agency Disaster Response</h1>
        <div class="legend">
            {''.join(f'<div class="legend-item"><div class="legend-dot" style="background:{c}"></div>{name}</div>' for name, c in AGENCY_LEGEND)}
        </div>
    </div>

    <!-- Main Content Grid -->
    <div class="main-grid">
        <!-- Left: Map -->
        <div class="panel map-panel">
            <div class="panel-title">Agency Map — Coastal North Carolina</div>
            {map_html or '<div style="height:100%;display:flex;align-items:center;justify-content:center;color:#475569">Map loading...</div>'}
        </div>

        <!-- Top Right: Trust Timeline -->
        <div class="panel">
            <div class="panel-title">Trust Dynamics</div>
            {timeline_html or '<div style="color:#475569">Waiting for data...</div>'}
        </div>

        <!-- Bottom Right: Temperature + Event Log / Streams -->
        <div class="panel">
            <div class="panel-title">Sensor Comparison</div>
            {temp_chart_html or '<div style="color:#475569">Waiting for readings...</div>'}
            <div class="bottom-row" style="margin-top:8px">
                <div>
                    <div class="panel-title">Event Log</div>
                    {event_html}
                </div>
                <div>
                    <div class="panel-title">Data Streams</div>
                    {streams_html}
                </div>
            </div>
        </div>
    </div>

    <!-- Playback Controls -->
    <div class="controls-bar">
        {self._playback.to_html()}
    </div>
</div>

<!-- Narration Overlay -->
{narration_html}

{detail_html}
</body>
</html>
"""

    def render_static_preview(self) -> str:
        """Render a static preview with placeholder content for development."""
        return self.render(
            map_html='<div style="height:100%;background:#162235;display:flex;'
                     'align-items:center;justify-content:center;color:#475569;'
                     'font-size:14px">Mapbox satellite view — Wilmington, NC</div>',
            timeline_html='<div style="height:300px;background:#162235;display:flex;'
                          'align-items:center;justify-content:center;color:#475569">'
                          'Trust timeline chart</div>',
            temp_chart_html='<div style="height:200px;background:#162235;display:flex;'
                            'align-items:center;justify-content:center;color:#475569">'
                            'Temperature comparison chart</div>',
            event_html='<div style="height:150px;background:#162235;color:#475569;'
                       'padding:8px;font-size:11px">[T+0:00] Formation begins...</div>',
            streams_html='<div style="height:150px;background:#162235;color:#475569;'
                         'padding:8px;font-size:11px">Active streams: 0</div>',
            playback_state=PlaybackState(
                playing=False, speed=1.0, current_t=0.0,
                duration=480.0, current_phase="Formation", mode="live",
            ),
            t_seconds=0.0,
        )
