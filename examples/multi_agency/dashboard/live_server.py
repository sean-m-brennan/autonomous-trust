"""Live Dash server for the multi-agency coordinator.

Spawns a minimal Dash app on port 8050 in a daemon thread so the
launcher's HTTP wait succeeds and the coordinator's panel components
(built by ``multi_agency_app.build_dashboard``) render against the live
scenario state instead of static placeholders.

Mirror of ``examples/dod_mission/dashboard/live_server.py``; the two
modules share a structure but stay separate so each demo can iterate
on its own layout without coordinating cross-demo changes.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable

import dash
from dash import dcc, html, Input, Output

from autonomous_trust.inspector.dashboard.trust_timeline import (
    ReputationSample, TrustTimeline,
)
from autonomous_trust.inspector.dashboard.event_log import EventLogPanel
from autonomous_trust.inspector.dashboard.sensor_chart import (
    SensorComparisonChart,
)


_TICK_MS = 1000


def _render_status_bar(title: str, state: dict[str, Any]) -> list:
    phase = state.get("phase") or "pre-mission"
    tick = state.get("tick", 0)
    return [
        html.Span(title,
                  style={"fontWeight": "600", "marginRight": "16px"}),
        html.Span(f"Phase: {phase}",
                  style={"color": "#FDE68A", "marginRight": "16px"}),
        html.Span(f"Tick: {tick}",
                  style={"color": "#94A3B8", "fontFamily": "monospace"}),
    ]


def _render_reputations(state: dict[str, Any]) -> list:
    reps = state.get("reputations", {})
    if not reps:
        return [html.Div("No reputations observed yet",
                         style={"color": "#475569", "fontSize": "12px"})]
    rows = [
        html.Tr([html.Td(name, style={"padding": "2px 8px"}),
                 html.Td(f"{score:.2f}",
                         style={"padding": "2px 8px",
                                "fontFamily": "monospace",
                                "color": ("#84CC16" if score >= 0.5
                                          else "#F87171")})])
        for name, score in sorted(reps.items())
    ]
    return [html.Table([html.Tbody(rows)],
                       style={"fontSize": "12px", "color": "#E2E8F0"})]


_SECTION_LABEL_STYLE = {
    "fontSize": "10px", "letterSpacing": "1px",
    "color": "#64748B", "marginBottom": "6px",
    "textTransform": "uppercase",
}


def make_app(name: str, title: str,
             panels: dict[str, Any],
             chart_keys: list[str],
             state_provider: Callable[[], dict[str, Any]]) -> dash.Dash:
    """Construct the Dash app.

    ``chart_keys`` is the ordered list of SensorComparisonChart panel
    keys to render (e.g. ``["target_x_chart", "noise_chart"]`` for
    dod-mission, ``["temperature_chart", "wind_chart"]`` for
    multi-agency).  ``state_provider`` is invoked on each tick and must
    return the latest state dict; ``panels`` is the bundle from
    ``build_dashboard(scenario)``.
    """
    timeline: TrustTimeline = panels["trust_timeline"]
    charts: list[SensorComparisonChart] = [panels[k] for k in chart_keys]
    event_log: EventLogPanel = panels["event_log"]

    app = dash.Dash(name, title=title, update_title=None)

    chart_graph_ids = [f"chart-{i}" for i in range(len(charts))]
    app.layout = html.Div(
        style={"backgroundColor": "#0F172A",
               "color": "#E2E8F0",
               "fontFamily": "Inter, system-ui, sans-serif",
               "padding": "12px",
               "minHeight": "100vh"},
        children=[
            html.Div(id="status-bar",
                     style={"padding": "8px 12px",
                            "background": "#1E293B",
                            "borderRadius": "6px",
                            "marginBottom": "12px"}),
            html.Div(style={"display": "grid",
                            "gridTemplateColumns": "2fr 1fr",
                            "gap": "12px"},
                     children=[
                html.Div(children=[
                    dcc.Graph(id="timeline-graph",
                              config={"displayModeBar": False}),
                    *[dcc.Graph(id=gid,
                                config={"displayModeBar": False})
                      for gid in chart_graph_ids],
                ]),
                html.Div(children=[
                    html.Div("Reputations", style=_SECTION_LABEL_STYLE),
                    html.Div(id="reputations",
                             style={"marginBottom": "16px"}),
                    html.Div("Event Log", style=_SECTION_LABEL_STYLE),
                    html.Div(id="event-log",
                             style={"maxHeight": "400px",
                                    "overflowY": "auto",
                                    "fontSize": "11px"}),
                ]),
            ]),
            dcc.Interval(id="tick", interval=_TICK_MS, n_intervals=0),
        ],
    )

    chart_outputs = [Output(gid, "figure") for gid in chart_graph_ids]

    @app.callback(
        Output("status-bar", "children"),
        Output("timeline-graph", "figure"),
        *chart_outputs,
        Output("reputations", "children"),
        Output("event-log", "children"),
        Input("tick", "n_intervals"),
    )
    def _refresh(_n):
        state = state_provider() or {}
        return (
            _render_status_bar(title, state),
            timeline.figure(),
            *[chart.figure() for chart in charts],
            _render_reputations(state),
            event_log.to_dash_children(),
        )

    return app


def start_in_thread(name: str, title: str,
                    panels: dict[str, Any],
                    chart_keys: list[str],
                    state_provider: Callable[[], dict[str, Any]],
                    host: str = "0.0.0.0", port: int = 8050,
                    ) -> threading.Thread:
    """Start the Dash app in a daemon thread and return the thread."""
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app = make_app(name, title, panels, chart_keys, state_provider)

    def _run():
        try:
            app.run(host=host, port=port,
                    debug=False, use_reloader=False)
        except Exception:
            logging.getLogger(__name__).exception(
                "Dashboard server crashed")

    t = threading.Thread(target=_run, daemon=True,
                         name="multi-agency-dashboard")
    t.start()
    return t


def feed_timeline_sample(panels: dict[str, Any],
                         t_seconds: float, peer_name: str,
                         score: float) -> None:
    """Push a reputation observation into the trust timeline."""
    panels["trust_timeline"].add_sample(
        ReputationSample(t=t_seconds, peer_name=peer_name, score=score))


def feed_event(panels: dict[str, Any], record: dict) -> None:
    """Append a scenario event record into the event log panel."""
    panels["event_log"].add_from_event_record(record)
