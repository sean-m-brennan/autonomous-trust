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
        # Pinned to the top of the viewport so the narration stays in
        # view as the (tall) dashboard is scrolled. position:fixed is
        # viewport-relative, so it tracks the scroll regardless.
        "position": "fixed",
        "top": "12px",
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
    # Access-icon labels track the access1..4 slide markup (the slide
    # numbers map onto tiers 1..4). Plain text rather than Font Awesome
    # so Dash doesn't need an external stylesheet to render them. Tier
    # 0 (admitted, no trust) gets an em-dash so the column never empties.
    access_label = {
        0: "—",      # admitted, no trust
        1: "NET",    # transport / network presence (access1)
        2: "COMM",   # communication (access2)
        3: "SVCS",   # services (access3)
        4: "DATA",   # data-sharing (access4)
    }
    rows = []
    for name, score in sorted(reps.items(), key=lambda kv: kv[0]):
        tier = int(tiers.get(name, 0))
        # score is None for a pre-established peer that hasn't produced a
        # consensus reputation yet — show it as "forming…" so the peer is
        # visibly present-but-pending rather than missing from the panel.
        if score is None:
            score_cell = html.Td("forming…", style={
                "padding": "2px 8px",
                "fontFamily": "monospace",
                "fontStyle": "italic",
                "color": "#64748B"})
        else:
            score_cell = html.Td(f"{score:.2f}", style={
                "padding": "2px 8px",
                "fontFamily": "monospace",
                "color": ("#84CC16" if score >= 0.5 else "#F87171")})
        rows.append(html.Tr([
            html.Td(name, style={"padding": "2px 8px"}),
            html.Td(f"T{tier}", style={
                "padding": "2px 8px",
                "fontFamily": "monospace",
                "color": tier_colour.get(tier, "#475569"),
                "fontWeight": "600",
            }),
            html.Td(access_label.get(tier, "—"), style={
                "padding": "2px 8px",
                "fontFamily": "monospace",
                "fontSize": "11px",
                "color": tier_colour.get(tier, "#475569"),
                "letterSpacing": "0.5px",
            }),
            score_cell,
        ]))
    # Lay the peers out across three columns so the panel fills the width
    # instead of one tall list. Split column-major so each column stays
    # alphabetically contiguous. Collapse to fewer columns only when the
    # roster is too small to fill three.
    ncols = min(3, len(rows)) if rows else 0
    per = (len(rows) + ncols - 1) // ncols if ncols else 0
    columns = [rows[i:i + per] for i in range(0, len(rows), per)] if per else []
    tables = [
        html.Table([html.Tbody(col)],
                   style={"fontSize": "12px", "color": "#E2E8F0",
                          "verticalAlign": "top"})
        for col in columns
    ]
    return [html.Div(tables, style={"display": "flex",
                                    "flexWrap": "wrap",
                                    "gap": "8px 24px",
                                    "alignItems": "flex-start"})]


_SECTION_LABEL_STYLE = {
    "fontSize": "10px", "letterSpacing": "1px",
    "color": "#64748B", "marginBottom": "6px",
    "textTransform": "uppercase",
}


def _render_map_legend(groups: list) -> list:
    """Render a chart panel's ``legend_groups()`` as an HTML legend.

    ``groups`` is ``[(title, [{"label","color"}, ...]), ...]``. Each group
    is a labelled row of colour-swatch chips that flex-wrap horizontally,
    so the legend fills the width and stays short instead of stacking into
    tall columns the way the in-figure Plotly legend did.
    """
    sections = []
    for title, items in groups:
        chips = [
            html.Div(
                [
                    html.Span(style={
                        "display": "inline-block", "width": "10px",
                        "height": "10px", "borderRadius": "50%",
                        "background": it["color"], "marginRight": "6px",
                        "flex": "0 0 auto"}),
                    html.Span(it["label"], style={"fontSize": "11px"}),
                ],
                style={"display": "flex", "alignItems": "center",
                       "marginRight": "16px", "marginBottom": "3px"},
            )
            for it in items
        ]
        sections.append(html.Div([
            html.Div(title, style=_SECTION_LABEL_STYLE),
            html.Div(chips, style={"display": "flex", "flexWrap": "wrap"}),
        ], style={"marginBottom": "8px"}))
    return sections


def make_app(name: str, title: str,
             panels: dict[str, Any],
             chart_keys: list[str],
             state_provider: Callable[[], dict[str, Any]],
             narration_script: Optional[list[NarrationBlock]] = None,
             presentation_default: bool = True,
             peer_names: Optional[list[str]] = None,
             ) -> dash.Dash:
    """Construct the Dash app.

    ``chart_keys`` is the ordered list of chart-shaped panel keys to
    render (e.g. ``["target_x_chart", "noise_chart"]`` for dod-mission,
    ``["temperature_chart", "wind_chart"]`` for multi-agency). Each
    referenced panel needs the duck-typed interface
    ``add_reading(reading)``, ``mark_anomalous(peer, t)``,
    ``figure(width, height)`` — both ``SensorComparisonChart`` and the
    dod-mission ``TargetPositionMapPanel`` satisfy it.
    ``state_provider`` is invoked on each tick and must return the
    latest state dict; ``panels`` is the bundle from
    ``build_dashboard(scenario)``.

    When ``narration_script`` is provided, the page renders a
    NarrationOverlay over the bottom of the screen and shows a
    "Presentation" + "Fullscreen" toggle pair in the status bar.  The
    state provider should include a ``t_seconds`` key (scenario seconds,
    float) so narration can advance with the demo clock.
    """
    timeline: TrustTimeline = panels["trust_timeline"]
    # Chart-shaped panels — see make_app docstring for the duck-typed
    # interface. Not annotated as SensorComparisonChart anymore because
    # dod-mission swaps target_x for a TargetPositionMapPanel.
    charts = [panels[k] for k in chart_keys]
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
                        # Left column sized to the fixed-width map; the
                        # right column holds the trust / noise charts (also
                        # fixed ~900px) above the reputations / event / peer
                        # panels, so it is kept at least 900px wide.
                        "gridTemplateColumns": "900px minmax(900px, 1fr)",
                        "gap": "12px"},
                 children=[
            # Left column: the square Target-position map + its HTML legend,
            # with the reputations table and event log beneath it.
            html.Div(children=[
                *([dcc.Graph(id=chart_graph_ids[0],
                             config={"displayModeBar": False}),
                   # External legend for the map panel — a sibling div so
                   # CSS controls its horizontal layout (see
                   # _render_map_legend / TargetPositionMapPanel.legend_groups).
                   html.Div(id="map-legend",
                            style={"maxWidth": "900px",
                                   "margin": "0 0 12px 8px"})]
                  if chart_graph_ids else []),
                html.Div("Reputations", style=_SECTION_LABEL_STYLE),
                html.Div(id="reputations",
                         style={"marginBottom": "16px"}),
                html.Div("Event Log", style=_SECTION_LABEL_STYLE),
                html.Div(id="event-log",
                         style={"maxHeight": "300px",
                                "overflowY": "auto",
                                "fontSize": "11px",
                                "marginBottom": "12px"}),
            ]),
            # Right column: Trust Dynamics + Noise Floor (kept at their
            # fixed ~900px width), then the peer-detail drawer.
            html.Div(children=[
                dcc.Graph(id="timeline-graph",
                          config={"displayModeBar": False}),
                *[dcc.Graph(id=gid,
                            config={"displayModeBar": False})
                  for gid in chart_graph_ids[1:]],
                # Stretch Goal 2 / Phase 4: peer-detail drawer slot.
                # Rendered as a self-contained HTML document inside an
                # Iframe so the drawer's <details>/<svg>/<style>
                # markup runs without colliding with Dash's outer
                # CSS. Dropdown drives the selected-peer Store.
                html.Div("Peer Detail", style=_SECTION_LABEL_STYLE),
                dcc.Dropdown(
                    id="peer-selector",
                    options=[{"label": p, "value": p}
                             for p in (peer_names or [])],
                    placeholder=("(select a peer)" if peer_names
                                 else "(no peers known)"),
                    clearable=True,
                    style={"marginBottom": "8px", "color": "#0F172A"},
                ),
                dcc.Store(id="selected-peer-name", data=None),
                html.Iframe(
                    id="peer-detail",
                    srcDoc="",
                    style={"width": "100%", "height": "520px",
                           "border": "1px solid #1f2a44",
                           "borderRadius": "6px",
                           "background": "#0B1220"},
                ),
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
        Output("map-legend", "children"),
        Output("reputations", "children"),
        Output("event-log", "children"),
        Output("narration-overlay", "children"),
        Output("narration-overlay", "style"),
        Input("tick", "n_intervals"),
        State("presentation-mode", "data"),
    )
    def _refresh(_n, presentation_data):
        state = state_provider() or {}
        # Feed live squad/microdrone positions to any panel that renders
        # them (the TargetPositionMapPanel) before its figure is built.
        platforms = state.get("platforms") or {}
        for chart in charts:
            if hasattr(chart, "set_platforms"):
                chart.set_platforms(platforms)
        # External HTML legend for the map panel (first chart exposing
        # legend_groups). Rebuilt each tick so it tracks the live markers.
        map_legend: Any = []
        for chart in charts:
            if hasattr(chart, "legend_groups"):
                map_legend = _render_map_legend(chart.legend_groups())
                break
        narration_children: Any = html.Div()
        overlay_style = {"visibility": "hidden"}
        if overlay is not None:
            t_seconds = float(state.get("t_seconds", 0.0))
            overlay.advance_to(t_seconds)
            presentation_on = bool((presentation_data or {}).get("on"))
            if presentation_on:
                narration_children = _narration_div(overlay.current_block)
                overlay_style = {"visibility": "visible"}
        # Pin the trust-dynamics and noise-floor charts to the map's
        # fixed width. charts[0] is the map; its width is authoritative.
        # We override via update_layout (not the figure(width=...) arg)
        # because the sensor chart's empty-data path returns before it
        # applies the width, which would otherwise autosize to fill the
        # wider right column and not line up with the map.
        chart_figs = [chart.figure() for chart in charts]
        map_w = chart_figs[0].layout.width or 900
        timeline_fig = timeline.figure()
        timeline_fig.update_layout(width=map_w)
        for cf in chart_figs[1:]:
            cf.update_layout(width=map_w)
        return (
            _render_status_bar(title, state),
            timeline_fig,
            *chart_figs,
            map_legend,
            _render_reputations(state),
            event_log.to_dash_children(),
            narration_children,
            overlay_style,
        )

    # Stretch Goal 2 / Phase 4: peer-detail drawer.
    # Dropdown change -> Store; Store + tick -> re-render the
    # iframe srcDoc from the cached detection + reputation state.
    @app.callback(
        Output("selected-peer-name", "data"),
        Input("peer-selector", "value"),
        prevent_initial_call=True,
    )
    def _sync_selected(value):
        return value or None

    @app.callback(
        Output("peer-detail", "srcDoc"),
        Input("tick", "n_intervals"),
        Input("selected-peer-name", "data"),
    )
    def _render_drawer(_n, selected_peer):
        if not selected_peer:
            return _DRAWER_PLACEHOLDER
        state = state_provider() or {}
        return _render_peer_drawer(state, selected_peer)

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
                    presentation_default: bool = True,
                    peer_names: Optional[list[str]] = None,
                    ) -> threading.Thread:
    """Start the Dash app in a daemon thread and return the thread."""
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app = make_app(name, title, panels, chart_keys, state_provider,
                   narration_script=narration_script,
                   presentation_default=presentation_default,
                   peer_names=peer_names)

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


# --- Stretch Goal 2 / Phase 3 helpers -------------------------------------
#
# These translate the coordinator's serialised detection cache (see
# coordinator.py `_push_dashboard_update`) into the inspector
# components. A dashboard callback wires them by reading
# state["detection_per_peer"] each tick.

def detection_summary_for(state: dict[str, Any],
                          peer_name: str):
    """Build a DetectionSummary for the inspector drawer.

    Returns None when the peer has no cached detection (so the
    drawer can render its 'no contacts' placeholder for active peers
    without injecting a fake summary).
    """
    try:
        from autonomous_trust.inspector.dashboard.peer_detail import (
            DetectionSummary,
        )
    except ImportError:
        return None
    bucket = (state.get("detection_per_peer") or {}).get(peer_name)
    if not bucket:
        return None
    return DetectionSummary(
        crop_b64=bucket.get("crop_b64", "") or "",
        crop_size_px=tuple(bucket.get("crop_size_px") or (0, 0)),
        bbox_in_crop_px=tuple(bucket.get("bbox_in_crop_px")
                              or (0, 0, 0, 0)),
        label=bucket.get("label", ""),
        world_uid=bucket.get("world_uid", ""),
        confidence=float(bucket.get("confidence", 0.0)),
        age_sec=max(0.0, float(state.get("t_seconds", 0.0))
                    - float(bucket.get("t_seconds", 0.0))),
    )


def detection_log_for(state: dict[str, Any], peer_name: str) -> list:
    """Build the drawer's per-peer detection_log list."""
    try:
        from autonomous_trust.inspector.dashboard.peer_detail import (
            DetectionSummary,
        )
    except ImportError:
        return []
    log = (state.get("detection_log_per_peer") or {}).get(peer_name) or []
    out = []
    t_now = float(state.get("t_seconds", 0.0))
    for bucket in log:
        out.append(DetectionSummary(
            crop_b64=bucket.get("crop_b64", "") or "",
            crop_size_px=tuple(bucket.get("crop_size_px") or (0, 0)),
            bbox_in_crop_px=tuple(bucket.get("bbox_in_crop_px")
                                  or (0, 0, 0, 0)),
            label=bucket.get("label", ""),
            world_uid=bucket.get("world_uid", ""),
            confidence=float(bucket.get("confidence", 0.0)),
            age_sec=max(0.0, t_now - float(bucket.get("t_seconds", 0.0))),
        ))
    return out


_DRAWER_PLACEHOLDER = (
    '<!DOCTYPE html><html><body style="margin:0;padding:20px;'
    'background:#0B1220;color:#64748b;font-family:Inter,sans-serif;'
    'font-size:12px">(select a peer above to inspect its detection,'
    ' reputation, and identity)</body></html>'
)


def _render_peer_drawer(state: dict[str, Any], peer_name: str) -> str:
    """Build the full Iframe srcDoc for a peer's detail drawer.

    Wraps PeerDetailPanel.to_html with a minimal HTML document so the
    inline <details>/<svg>/<style> markup runs cleanly under sandboxed
    iframe scoping. Returns a placeholder when the panel module or
    its deps are unavailable so the dashboard still loads.
    """
    try:
        from autonomous_trust.inspector.dashboard.peer_detail import (
            PeerDetailPanel, PeerDetailState, ReputationSnapshot,
        )
    except ImportError:
        return _DRAWER_PLACEHOLDER

    # A pre-established peer that hasn't produced a consensus reputation yet
    # has a None score (the Reputations list shows "forming…" for it). Treat
    # that distinctly: it is onboarding, NOT compromised — float(None) would
    # both crash here and, defaulting to 0.0, mislabel a forming peer as
    # compromised, contradicting the list.
    raw_rep = (state.get("reputations") or {}).get(peer_name, None)
    forming = raw_rep is None
    reputation = 0.0 if forming else float(raw_rep)
    tier = int((state.get("tiers") or {}).get(peer_name, 0))
    status = "active"
    if forming:
        status = "onboarding"
    elif reputation < 0.4:
        status = "compromised"
    elif tier < 1:
        status = "onboarding"

    summary = detection_summary_for(state, peer_name)
    log = detection_log_for(state, peer_name)
    panel = PeerDetailPanel()
    drawer_html = panel.to_html(PeerDetailState(
        name=peer_name,
        agency=str((state.get("agencies") or {}).get(peer_name, "")),
        kind=str((state.get("kinds") or {}).get(peer_name, "")),
        status=status,
        # Feed the SAME consensus score the Reputations list shows, so the
        # drawer and the list never disagree. Without this the panel used
        # ReputationSnapshot's 1.0 default and always read "1.00 ramping
        # up" regardless of the peer's actual (often much lower) rep.
        # bootstrap_complete tracks tier >= 1 (the >0.5-rep trust band).
        reputation=ReputationSnapshot(
            current_score=reputation,
            bootstrap_complete=(tier >= 1),
            forming=forming,
        ),
        detection=summary,
        detection_log=log,
    ))
    return (
        '<!DOCTYPE html><html><head><style>'
        'body{margin:0;padding:8px;background:#0F172A;color:#E2E8F0;'
        'font-family:Inter,system-ui,sans-serif;font-size:12px}'
        '.mono{font-family:monospace}'
        '</style></head><body>' + drawer_html
        + _DRAWER_STATE_SCRIPT + '</body></html>'
    )


# The drawer iframe's srcDoc is rebuilt every tick (1 s) to refresh live
# detection data, which reloads the document and would otherwise collapse
# any <details> the user expanded (and reset scroll). This script, injected
# into the iframe, persists the open rows + scroll position in sessionStorage
# (keyed by the row's summary text) and restores them on each reload, so the
# expand state survives the live refresh. Guarded with try/catch in case the
# iframe is ever sandboxed without storage access. The `toggle` event does
# not bubble, so we listen in the capture phase.
_DRAWER_STATE_SCRIPT = (
    "<script>(function(){"
    "var OK='pdOpen',SK='pdScroll';"
    "function rd(k){try{return JSON.parse(sessionStorage.getItem(k)||'[]');}"
    "catch(e){return [];}}"
    "function wr(k,v){try{sessionStorage.setItem(k,JSON.stringify(v));}"
    "catch(e){}}"
    "function kf(d){var s=d.querySelector('summary');"
    "return (s?s.textContent.trim():'').slice(0,120);}"
    "var open=rd(OK);"
    "document.querySelectorAll('details').forEach(function(d){"
    "if(open.indexOf(kf(d))!==-1)d.open=true;});"
    "try{var y=parseInt(sessionStorage.getItem(SK)||'0',10);"
    "if(y)window.scrollTo(0,y);}catch(e){}"
    "document.addEventListener('toggle',function(e){"
    "var d=e.target;if(!d||d.tagName!=='DETAILS')return;"
    "var k=kf(d),cur=rd(OK),i=cur.indexOf(k);"
    "if(d.open){if(i===-1)cur.push(k);}else{if(i!==-1)cur.splice(i,1);}"
    "wr(OK,cur);},true);"
    "window.addEventListener('scroll',function(){"
    "try{sessionStorage.setItem(SK,String(window.scrollY||0));}catch(e){}},"
    "{passive:true});"
    "})();</script>"
)


def push_detections_to_agency_map(agency_map, state: dict[str, Any]) -> None:
    """Mirror per-peer detection markers into an AgencyMap instance.

    Idempotent — clears any prior marker that's no longer present in
    the cache so the map doesn't carry stale targets when a peer goes
    quiet. Safe to call from a dashboard tick callback.
    """
    if agency_map is None:
        return
    fresh = state.get("detection_per_peer") or {}
    for peer_name, bucket in fresh.items():
        lat, lon = bucket.get("target_latlon") or (0.0, 0.0)
        if not lat and not lon:
            continue
        agency_map.set_peer_detection(
            peer_name=peer_name,
            target_lat=float(lat), target_lon=float(lon),
            world_uid=bucket.get("world_uid", ""),
            label=bucket.get("label", ""),
            confidence=float(bucket.get("confidence", 0.0)),
        )
    # Drop markers for peers that have evicted their cache entry.
    stale = [p for p in agency_map._detections.keys() if p not in fresh]
    for p in stale:
        agency_map.clear_peer_detection(p)
