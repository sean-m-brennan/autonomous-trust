# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Disaster-response dashboard layout.

Assembles the demo's six panels into the single-page grid described in
demo-implementation-plan.md §3a:

    +----------------------------+
    |  AGENCY MAP | GRAPH | LOG  |
    +-------------+-------+------+
    |  TIMELINE         | STREAMS|
    +-------------------+--------+
    |  PEER DETAIL (drawer)      |
    +-----------------------------
    |  PLAYBACK CONTROLS         |
    +-----------------------------

The function returns a `html.Div` populated with empty placeholders that
downstream callbacks fill at tick time. Element IDs are the stable contract
between this layout and the inspector's callback wiring.

The layout is renderer-agnostic: it does not instantiate any component
that needs a live Dash app, so it can be imported and exercised in tests
without a running server.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from dash_extensions.enrich import html


# Stable element IDs -- the inspector's callback layer references these.
IDS = {
    "topbar_clock":      "demo-topbar-clock",
    "topbar_phase":      "demo-topbar-phase",
    "topbar_keystats":   "demo-topbar-keystats",
    "panel_map":         "demo-panel-map",
    "panel_graph":       "demo-panel-graph",
    "panel_log":         "demo-panel-log",
    "panel_timeline":    "demo-panel-timeline",
    "panel_streams":     "demo-panel-streams",
    "panel_detail":      "demo-panel-detail",
    "panel_playback":    "demo-panel-playback",
    "narration_overlay": "demo-narration",
}


def _panel(area_class: str, title: str, body_id: str,
           subtitle: Optional[str] = None,
           body_pad_zero: bool = False,
           placeholder: str = "Awaiting data") -> html.Div:
    body_cls = "demo-panel__body"
    if body_pad_zero:
        body_cls += " demo-panel__body--pad0"
    return html.Div(
        className=f"demo-panel demo-panel--{area_class}",
        children=[
            html.Div(
                className="demo-panel__header",
                children=[
                    html.Div(title, className="demo-panel__title"),
                    html.Div(subtitle or "",
                             className="demo-panel__subtitle"),
                ],
            ),
            html.Div(
                id=body_id,
                className=body_cls,
                children=html.Div(placeholder, className="demo-placeholder"),
            ),
        ],
    )


def _topbar(scenario_title: str, scenario_subtitle: str) -> html.Div:
    return html.Div(
        className="demo-topbar",
        children=[
            html.Div(scenario_title, className="demo-topbar__brand"),
            html.Div(scenario_subtitle, className="demo-topbar__tagline"),
            html.Div("T+00:00", id=IDS["topbar_clock"],
                     className="demo-topbar__clock"),
            html.Div("-- / --", id=IDS["topbar_phase"],
                     className="demo-topbar__phase"),
            # Key-stat callouts (KeyStatTracker output). Pushed right via
            # margin-left:auto in CSS so it hugs the right edge of the
            # topbar. Empty by default; populated each tick.
            html.Div(id=IDS["topbar_keystats"], children=[],
                     className="demo-topbar__keystats"),
        ],
    )


def _grid(peer_count: int, phase_count: int) -> html.Div:
    # Row-handle divs sit on dedicated grid rows between panel rows; a
    # JS asset (assets/row_resize.js) attaches drag handlers that
    # rewrite grid-template-rows in px so the user can rebalance row
    # heights interactively.
    return html.Div(
        className="demo-grid",
        children=[
            _panel(
                area_class="map",
                title="Agency Map",
                subtitle=f"{peer_count} peers",
                body_id=IDS["panel_map"],
                placeholder="Geography loading",
            ),
            _panel(
                area_class="graph",
                title="Trust Network",
                subtitle="Bilateral trust (edge = weight)",
                body_id=IDS["panel_graph"],
                placeholder="Graph loading",
            ),
            _panel(
                area_class="log",
                title="Event Log",
                subtitle="Newest first",
                body_id=IDS["panel_log"],
                placeholder="No events yet",
            ),
            html.Div(className="demo-row-handle demo-row-handle--1",
                     title="Drag to resize rows"),
            _panel(
                area_class="time",
                title="Trust Dynamics",
                subtitle=f"{phase_count} phases",
                body_id=IDS["panel_timeline"],
                body_pad_zero=True,
                placeholder="Reputation history will populate at T+30s",
            ),
            _panel(
                area_class="streams",
                title="Data Streams",
                subtitle="Live feeds",
                body_id=IDS["panel_streams"],
                placeholder="No streams negotiated yet",
            ),
            html.Div(className="demo-row-handle demo-row-handle--2",
                     title="Drag to resize rows"),
            _panel(
                area_class="detail",
                title="Peer Detail",
                subtitle="Click a node in the graph or map",
                body_id=IDS["panel_detail"],
                placeholder="(nothing selected)",
            ),
        ],
    )


def _narration_overlay() -> html.Div:
    # Hidden by default; narration callback flips display style to show it.
    return html.Div(
        id=IDS["narration_overlay"],
        style={"display": "none"},
        children=[],
    )


def _playback_slot() -> html.Div:
    return html.Div(
        id=IDS["panel_playback"],
        className="demo-playback",
        children=html.Div("Controls loading...", className="demo-placeholder"),
    )


def build_dashboard(scenario=None,
                    scenario_title: Optional[str] = None,
                    scenario_subtitle: Optional[str] = None) -> html.Div:
    """Return the assembled dashboard as a single html.Div.

    Either pass a `scenario` object (the DisasterResponseScenario) or
    pass title/subtitle strings directly. All live data is injected by
    the inspector's callback layer via the IDs in `IDS`.
    """
    if scenario is not None:
        scenario_title = scenario_title or getattr(
            scenario, "name", "Disaster Response")
        scenario_subtitle = scenario_subtitle or getattr(
            scenario, "description", "")
        peer_count = len(getattr(scenario, "peers", {}) or {})
        phase_count = len(getattr(scenario, "phases", []) or [])
    else:
        scenario_title = scenario_title or "Disaster Response"
        scenario_subtitle = (scenario_subtitle
                             or "Multi-Agency Data Sharing")
        peer_count = 0
        phase_count = 0

    # Trim long subtitles -- the topbar is narrow.
    if scenario_subtitle and len(scenario_subtitle) > 140:
        scenario_subtitle = scenario_subtitle[:137] + "..."

    return html.Div(
        id="demo-root",
        className="demo-root",
        children=[
            _topbar(scenario_title, scenario_subtitle),
            _grid(peer_count=peer_count, phase_count=phase_count),
            _playback_slot(),
            _narration_overlay(),
        ],
    )


# ----------------------------------------------------------------------
# Top-bar status helpers (for callbacks) -- kept here to colocate the
# UI contract in one module.
# ----------------------------------------------------------------------

def format_clock(t: float) -> str:
    """Format scenario seconds as 'T+MM:SS'."""
    if t < 0:
        t = 0
    m = int(t) // 60
    s = int(t) % 60
    return f"T+{m:02d}:{s:02d}"


def format_phase(idx: int, total: int, name: str = "") -> str:
    """Format phase counter as '3/9 Bootstrap'."""
    if total <= 0:
        return name or "--"
    return f"{idx + 1}/{total} {name}".strip()


