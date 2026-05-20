# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Full-screen presentation layout for the DoD squad demo.

Counterpart to examples/multi_agency/dashboard/presentation.py.  Renders
the dashboard as a single-page dark-themed HTML document — useful for:

  * standalone preview / screenshot generation without a running Dash
    server (`PresentationLayout.render_static_preview()`)
  * the inspector's full-screen mode (the `render(...)` method takes
    pre-rendered HTML for each panel and assembles the page)

The actual live dashboard at http://localhost:8050 uses
`autonomous_trust.inspector.dashboard.disaster_response_layout.build_dashboard()`
to produce a Dash component tree with stable IDs; the callback layer
fills in each panel.  This module is the static / presentation-mode
analogue.

Layout (matches the schematic in dod-demo-implementation-plan.md §Phase 4):

  +-------------------------------------------------------------------+
  |  AUTONOMOUS TRUST  |  Mission Clock: T+04:32  |  Phase: ROGUE     |
  +-------------------------------------------------------------------+
  |                          |                     |                   |
  |   TACTICAL MAP           |   TRUST NETWORK     |   EVENT LOG       |
  |                          |                     |                   |
  +--------------------------+---------------------+-------------------+
  |   TRUST DYNAMICS                  |   ACTIVE TASKS                |
  +-----------------------------------+-------------------------------+
  |   PEER DETAIL (drawer)                                             |
  +-------------------------------------------------------------------+
  |   PLAYBACK CONTROLS                                                |
  +-------------------------------------------------------------------+
  |   [Narration Overlay]                                              |
  +-------------------------------------------------------------------+

Each interior cell receives pre-rendered HTML at runtime; the static
preview substitutes placeholders that approximate the panel content so
the page can be inspected by eye before live data is wired in.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from autonomous_trust.inspector.dashboard.narration import NarrationOverlay
from autonomous_trust.inspector.dashboard.playback_controls import (
    PlaybackControls, PlaybackState,
)

# Sibling imports
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
from scenario import DoDMissionScenario  # noqa: E402
from dashboard.narration_script import DOD_NARRATION  # noqa: E402
from dashboard.dod_app import ROLE_LEGEND  # noqa: E402


def _format_clock(t_seconds: float) -> str:
    minutes, seconds = divmod(int(t_seconds), 60)
    return f"T+{minutes:02d}:{seconds:02d}"


class PresentationLayout:
    """Renders the DoD demo presentation page.

    Holds the narration + playback components and assembles the full
    HTML page from the live or placeholder panel HTML the caller
    supplies.

    Usage:
        layout = PresentationLayout(scenario)
        html_page = layout.render(
            map_html=map_panel.to_html(),
            graph_html=graph_panel.to_html(),
            event_log_html=event_log.to_html(),
            timeline_html=timeline.figure().to_html(...),
            target_chart_html=target_chart.figure().to_html(...),
            detail_html=detail.to_html(state),
            playback_state=PlaybackState(...),
            t_seconds=current_t,
        )
    """

    def __init__(self, scenario: DoDMissionScenario):
        self._scenario = scenario
        self._narration = NarrationOverlay(script=DOD_NARRATION)
        self._playback = PlaybackControls(
            phases=[(p.name, p.start.total_seconds())
                    for p in scenario.phases],
            duration=scenario.duration.total_seconds(),
        )
        self._presentation_mode = True

    def toggle_presentation_mode(self) -> None:
        self._presentation_mode = not self._presentation_mode
        self._narration.toggle_visibility()

    # ------------------------------------------------------------------

    def render(
        self,
        map_html: str = "",
        graph_html: str = "",
        event_log_html: str = "",
        timeline_html: str = "",
        target_chart_html: str = "",
        detail_html: str = "",
        playback_state: Optional[PlaybackState] = None,
        t_seconds: float = 0.0,
        current_phase: str = "Setup",
    ) -> str:
        """Render the full page as one HTML string."""
        if playback_state:
            self._playback.update(playback_state)

        self._narration.advance_to(t_seconds)
        narration_html = (
            self._narration.to_html() if self._presentation_mode else ""
        )

        legend_html = "".join(
            f'<div class="legend-item">'
            f'<span class="legend-dot" style="background:{color}"></span>'
            f'{label}</div>'
            for label, color in ROLE_LEGEND
        )

        clock = _format_clock(t_seconds)

        return _PAGE_TEMPLATE.format(
            clock=clock,
            phase=current_phase,
            legend=legend_html,
            map_html=map_html or _placeholder("Tactical map — Madison County, AL"),
            graph_html=graph_html or _placeholder("Trust network graph"),
            event_log_html=event_log_html or _placeholder("Event log"),
            timeline_html=timeline_html or _placeholder("Trust dynamics chart"),
            target_chart_html=target_chart_html or _placeholder("Target X-position chart"),
            detail_html=detail_html or "",
            playback_html=self._playback.to_html(),
            narration_html=narration_html,
        )

    def render_static_preview(self) -> str:
        """Render a preview with placeholders for offline / development use."""
        return self.render(
            map_html=_placeholder(
                "Tactical map — squad insertion at 34.706°N, "
                "RQ-86 orbit overhead, MQ-800 ingressing from the east",
                height=400,
            ),
            graph_html=_placeholder(
                "Force-directed trust graph — squad cohort at "
                "center, MQ-800 node turning red", height=400,
            ),
            event_log_html=_placeholder(
                "[T+0:00] Setup — Squad cohort forms<br>"
                "[T+2:30] sensor-1 excluded (forged identity)<br>"
                "[T+4:30] ANOMALY: mq800 target_position_x deviation 80m<br>"
                "[T+4:45] mq800 excluded (autonomous)",
                height=180, align="top",
            ),
            timeline_html=_placeholder(
                "Per-peer reputation over time, 8 phase markers",
                height=200,
            ),
            target_chart_html=_placeholder(
                "Target X-position — rq86-1, rq86-2 agree; "
                "mq800 diverges at T+4:15",
                height=180,
            ),
            playback_state=PlaybackState(
                playing=False, speed=1.0, current_t=0.0,
                duration=480.0, current_phase="Setup", mode="live",
            ),
            t_seconds=0.0,
            current_phase="Setup",
        )


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _placeholder(text: str, height: int = 240, align: str = "center") -> str:
    align_styles = {
        "center": "align-items:center;justify-content:center",
        "top":    "align-items:flex-start;justify-content:flex-start;padding:8px",
    }[align]
    return (
        f'<div style="height:{height}px;background:#0f1626;'
        f'display:flex;{align_styles};color:#475569;font-size:12px;'
        f'line-height:1.6">{text}</div>'
    )


# ----------------------------------------------------------------------
# Page template — kept inline so the module has no external HTML deps
# ----------------------------------------------------------------------

_PAGE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AutonomousTrust — DoD Squad Infiltration Demo</title>
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
        grid-template-rows: 48px 1fr auto auto;
        height: 100vh;
    }}
    .title-bar {{
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 0 16px;
        background: #1E293B;
        border-bottom: 1px solid #334155;
    }}
    .title-bar h1 {{
        font-size: 16px;
        font-weight: 600;
        color: #F1F5F9;
        margin-right: auto;
    }}
    .clock {{
        font-family: 'JetBrains Mono', 'Menlo', monospace;
        font-size: 14px;
        color: #94A3B8;
    }}
    .phase {{
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: #FDE68A;
        padding: 2px 8px;
        border: 1px solid #FDE68A;
        border-radius: 4px;
    }}
    .legend {{
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
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
        display: inline-block;
    }}
    .top-row, .mid-row {{
        display: grid;
        gap: 8px;
        padding: 8px;
        overflow: hidden;
    }}
    .top-row {{
        grid-template-columns: 2fr 1fr 1fr;
    }}
    .mid-row {{
        grid-template-columns: 2fr 1fr;
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
    .controls-bar {{
        padding: 8px 16px;
        border-top: 1px solid #334155;
    }}
</style>
</head>
<body>
<div class="layout">
    <div class="title-bar">
        <h1>AutonomousTrust — DoD Squad Infiltration</h1>
        <div class="clock">{clock}</div>
        <div class="phase">{phase}</div>
        <div class="legend">{legend}</div>
    </div>

    <div class="top-row">
        <div class="panel">
            <div class="panel-title">Tactical Map</div>
            {map_html}
        </div>
        <div class="panel">
            <div class="panel-title">Trust Network</div>
            {graph_html}
        </div>
        <div class="panel">
            <div class="panel-title">Event Log</div>
            {event_log_html}
        </div>
    </div>

    <div class="mid-row">
        <div class="panel">
            <div class="panel-title">Trust Dynamics</div>
            {timeline_html}
        </div>
        <div class="panel">
            <div class="panel-title">Target X-Position — ISR Cross-Source</div>
            {target_chart_html}
        </div>
    </div>

    <div class="controls-bar">
        {playback_html}
    </div>
</div>

{narration_html}
{detail_html}
</body>
</html>
"""


# Module-level CLI: render a static preview to stdout or to a file
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Render a static DoD dashboard preview.")
    p.add_argument("output", nargs="?", default="-",
                   help="Output file (default '-' = stdout).")
    args = p.parse_args()

    sc = DoDMissionScenario()
    layout = PresentationLayout(sc)
    html = layout.render_static_preview()

    if args.output == "-":
        print(html)
    else:
        Path(args.output).write_text(html)
        print(f"Wrote {args.output}  ({len(html):,} bytes)")
