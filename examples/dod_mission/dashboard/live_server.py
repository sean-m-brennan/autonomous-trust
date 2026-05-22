"""Live Dash server for the DoD mission coordinator.

Spawns a minimal Dash app on port 8050 in a daemon thread so the
launcher's HTTP wait succeeds and the coordinator's panel components
(built by ``dod_app.build_dashboard``) render against the live scenario
state instead of static placeholders.

Scope: this is the bare wiring needed to (a) make the inspector URL
respond and (b) reflect the data already flowing inside the coordinator
(reputations, scenario phase, scenario events).  Sensor / ISR readings
will fill the comparison charts once the
generator-to-DataProcess runtime path documented in
``project-dod-demo-status`` is closed; until then the chart figures
render empty traces with their axes + threshold lines.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

import dash
from dash import dcc, html, Input, Output, State

from autonomous_trust.inspector.dashboard.trust_timeline import (
    ReputationSample, TrustTimeline,
)
from autonomous_trust.inspector.dashboard.event_log import EventLogPanel
from autonomous_trust.inspector.dashboard.sensor_chart import (
    SensorComparisonChart,
)
from autonomous_trust.inspector.dashboard.narration import (
    NarrationBlock, NarrationOverlay, STYLE_COLORS,
)


_TICK_MS = 1000


def _narration_div(block: Optional[NarrationBlock]) -> Any:
    """Render the current narration block as a Dash component.

    Returns an empty Div when no block is active (Dash callbacks can't
    return None for a children slot).
    """
    if block is None:
        return html.Div()
    colors = STYLE_COLORS.get(block.style, STYLE_COLORS["default"])
    children = [
        html.Div(block.text,
                 style={"fontSize": "16px",
                        "color": colors["text"],
                        "fontWeight": 500,
                        "lineHeight": 1.4})
    ]
    if block.subtext:
        children.append(
            html.Div(block.subtext,
                     style={"fontSize": "13px",
                            "color": colors["text"],
                            "opacity": 0.8,
                            "marginTop": "6px"}))
    return html.Div(children, style={
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
    })


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
    tiers = state.get("tiers", {}) or {}
    if not reps:
        return [html.Div("No reputations observed yet",
                         style={"color": "#475569", "fontSize": "12px"})]
    # Per-tier colour stops mirror the reputations colour ramp: low
    # tiers neutral, mid-tiers warm, top tier highlighted. Keeps the
    # column visually scannable at a glance.
    tier_colour = {
        0: "#475569",   # admitted, no trust yet
        1: "#94A3B8",   # network presence
        2: "#FACC15",   # sensor-report
        3: "#FB923C",   # fusion-validate
        4: "#84CC16",   # command-issue
    }
    rows = []
    for name, score in sorted(reps.items()):
        tier = tiers.get(name, 0)
        rows.append(html.Tr([
            html.Td(name, style={"padding": "2px 8px"}),
            html.Td(f"T{tier}", style={
                "padding": "2px 8px",
                "fontFamily": "monospace",
                "color": tier_colour.get(int(tier), "#475569"),
                "fontWeight": "600",
            }),
            html.Td(f"{score:.2f}",
                    style={"padding": "2px 8px",
                           "fontFamily": "monospace",
                           "color": ("#84CC16" if score >= 0.5
                                     else "#F87171")}),
        ]))
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
             state_provider: Callable[[], dict[str, Any]],
             narration_script: Optional[list[NarrationBlock]] = None,
             presentation_default: bool = False,
             ) -> dash.Dash:
    """Construct the Dash app.

    ``chart_keys`` is the ordered list of SensorComparisonChart panel
    keys to render (e.g. ``["target_x_chart", "noise_chart"]`` for
    dod-mission, ``["temperature_chart", "wind_chart"]`` for
    multi-agency).  ``state_provider`` is invoked on each tick and must
    return the latest state dict; ``panels`` is the bundle from
    ``build_dashboard(scenario)``.

    When ``narration_script`` is provided, the page renders a
    NarrationOverlay over the bottom of the screen and shows a
    "Presentation" + "Fullscreen" toggle pair in the status bar.  The
    state provider should include a ``t_seconds`` key (scenario seconds,
    float) so narration can advance with the demo clock.
    """
    timeline: TrustTimeline = panels["trust_timeline"]
    charts: list[SensorComparisonChart] = [panels[k] for k in chart_keys]
    event_log: EventLogPanel = panels["event_log"]

    overlay = (NarrationOverlay(narration_script)
               if narration_script else None)

    app = dash.Dash(name, title=title, update_title=None)

    chart_graph_ids = [f"chart-{i}" for i in range(len(charts))]
    presentation_visible_initially = (
        "visible" if presentation_default else "hidden")
    layout_children = [
        # dcc.Store carries presentation-mode + fullscreen flags so the
        # narration callback knows whether to render and the clientside
        # fullscreen toggle has somewhere to keep its state.
        dcc.Store(id="presentation-mode",
                  data={"on": bool(presentation_default)}),
        html.Div(
            id="control-bar",
            style={"display": "flex" if narration_script else "none",
                   "alignItems": "center",
                   "gap": "8px",
                   "padding": "6px 12px",
                   "background": "#0B1220",
                   "borderRadius": "6px",
                   "marginBottom": "8px"},
            children=[
                html.Button("Presentation Mode",
                            id="presentation-toggle",
                            n_clicks=0,
                            style={"padding": "4px 12px",
                                   "background": "#1E293B",
                                   "color": "#E2E8F0",
                                   "border": "1px solid #334155",
                                   "borderRadius": "4px",
                                   "cursor": "pointer"}),
                html.Button("Fullscreen",
                            id="fullscreen-toggle",
                            n_clicks=0,
                            style={"padding": "4px 12px",
                                   "background": "#1E293B",
                                   "color": "#E2E8F0",
                                   "border": "1px solid #334155",
                                   "borderRadius": "4px",
                                   "cursor": "pointer"}),
                html.Span(id="presentation-status",
                          style={"color": "#94A3B8",
                                 "fontSize": "11px",
                                 "marginLeft": "8px"}),
            ],
        ),
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
        html.Div(id="narration-overlay",
                 style={"visibility": presentation_visible_initially}),
        dcc.Interval(id="tick", interval=_TICK_MS, n_intervals=0),
    ]
    app.layout = html.Div(
        style={"backgroundColor": "#0F172A",
               "color": "#E2E8F0",
               "fontFamily": "Inter, system-ui, sans-serif",
               "padding": "12px",
               "minHeight": "100vh"},
        children=layout_children,
    )

    chart_outputs = [Output(gid, "figure") for gid in chart_graph_ids]

    @app.callback(
        Output("status-bar", "children"),
        Output("timeline-graph", "figure"),
        *chart_outputs,
        Output("reputations", "children"),
        Output("event-log", "children"),
        Output("narration-overlay", "children"),
        Output("narration-overlay", "style"),
        Input("tick", "n_intervals"),
        State("presentation-mode", "data"),
    )
    def _refresh(_n, presentation_data):
        state = state_provider() or {}
        narration_children: Any = html.Div()
        overlay_style = {"visibility": "hidden"}
        if overlay is not None:
            t_seconds = float(state.get("t_seconds", 0.0))
            overlay.advance_to(t_seconds)
            presentation_on = bool((presentation_data or {}).get("on"))
            if presentation_on:
                narration_children = _narration_div(overlay.current_block)
                overlay_style = {"visibility": "visible"}
        return (
            _render_status_bar(title, state),
            timeline.figure(),
            *[chart.figure() for chart in charts],
            _render_reputations(state),
            event_log.to_dash_children(),
            narration_children,
            overlay_style,
        )

    if narration_script:
        @app.callback(
            Output("presentation-mode", "data"),
            Output("presentation-status", "children"),
            Input("presentation-toggle", "n_clicks"),
            State("presentation-mode", "data"),
            prevent_initial_call=True,
        )
        def _toggle_presentation(_n, current):
            on = not bool((current or {}).get("on"))
            label = "presentation: on" if on else "presentation: off"
            return {"on": on}, label

        # Browser-side fullscreen toggle.  Dash clientside callbacks
        # run in the user's browser, so we get access to
        # document.documentElement.requestFullscreen()/exitFullscreen()
        # without round-tripping through the server.
        app.clientside_callback(
            """
            function(n_clicks) {
                if (n_clicks > 0) {
                    if (!document.fullscreenElement) {
                        document.documentElement.requestFullscreen();
                    } else if (document.exitFullscreen) {
                        document.exitFullscreen();
                    }
                }
                return n_clicks;
            }
            """,
            Output("fullscreen-toggle", "n_clicks"),
            Input("fullscreen-toggle", "n_clicks"),
        )

    return app


def start_in_thread(name: str, title: str,
                    panels: dict[str, Any],
                    chart_keys: list[str],
                    state_provider: Callable[[], dict[str, Any]],
                    host: str = "0.0.0.0", port: int = 8050,
                    narration_script: Optional[list[NarrationBlock]] = None,
                    presentation_default: bool = False,
                    ) -> threading.Thread:
    """Start the Dash app in a daemon thread and return the thread."""
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app = make_app(name, title, panels, chart_keys, state_provider,
                   narration_script=narration_script,
                   presentation_default=presentation_default)

    def _run():
        try:
            app.run(host=host, port=port,
                    debug=False, use_reloader=False)
        except Exception:
            logging.getLogger(__name__).exception(
                "Dashboard server crashed")

    t = threading.Thread(target=_run, daemon=True,
                         name="dod-dashboard")
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
