# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Agency map panel for the disaster-response dashboard.

Scenario-driven; independent of the inspector's live CohortInterface.
Accepts peer-role metadata from the scenario module and renders a
Plotly Scattergeo (or Scattermap when MAPBOX env is set) with:

    * Agency-colored markers, one per peer, at the scenario's
      geographic position.
    * A second "pulse" trace for the compromised peer that the
      callback layer grows/shrinks over time to visually draw the eye.
    * An edge trace for active data flows between peers (weather,
      seismic, fusion, etc.).
    * An EPA fade-in: the late-joiner marker starts at opacity 0 and
      the callback layer ramps it up after Phase 7.

The class intentionally does NOT subscribe to a live data source; the
inspector's callback layer drives state changes via the public methods
`mark_compromised`, `mark_excluded`, `set_data_flow`, and `set_opacity`.
That keeps the module testable without a running AT cluster and keeps
cohort-coupling inside the existing DynamicMap component.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import plotly.graph_objects as go


# Agency -> marker symbol. Plotly Scattergeo supports a fixed vocabulary;
# pick shapes that read at projection scale.
_AGENCY_SYMBOLS = {
    "NOAA": "circle",
    "USGS": "diamond",
    "FEMA": "square",
    "EPA":  "triangle-up",
}

# Fallback colors if the caller doesn't pass agency_colors.
_DEFAULT_AGENCY_COLORS = {
    "NOAA": "#1f77b4",
    "USGS": "#8c564b",
    "FEMA": "#d62728",
    "EPA":  "#2ca02c",
}


@dataclass
class MapPeer:
    """A peer rendered on the map.

    Attributes:
        name:        Peer id (e.g. "noaa-3")
        agency:      "NOAA" / "USGS" / "FEMA" / "EPA"
        kind:        Role kind (e.g. "weather-sensor", "fusion-node")
        lat:         Decimal degrees north
        lon:         Decimal degrees east
        opacity:     0.0 - 1.0 (0 hides the marker; used for fade-ins)
        status:      "active" | "compromised" | "excluded"
        sitrep:      Optional short hover text
    """
    name: str
    agency: str
    kind: str
    lat: float
    lon: float
    opacity: float = 1.0
    status: str = "active"
    sitrep: str = ""


@dataclass
class DataFlow:
    """One active data flow between two peers."""
    source: str
    target: str
    data_type: str = ""
    active: bool = True


@dataclass
class MapStyle:
    """Visual tuning knobs."""
    marker_size: int = 14
    pulse_size: int = 30
    edge_width: int = 2
    paper_bg: str = "#121a2e"
    land_color: str = "#1b263b"
    water_color: str = "#0b0f1a"
    country_color: str = "#233554"


# Geographic hints -- Pacific Northwest plays well with the scenario's
# seeded positions. The rendered fitbounds still defaults to the data.
_PNW_CENTER = (46.75, -122.50)
_PNW_DEFAULT_ZOOM = 6


class AgencyMap:
    """Builds the agency map figure from scenario peers.

    Usage:
        m = AgencyMap(agency_colors={"NOAA": "#1f77b4", ...})
        for peer in scenario_peers:
            m.add_peer(MapPeer(...))
        m.set_data_flow("noaa-1", "fema-fusion", data_type="weather_stream")
        fig = m.figure()
    """

    def __init__(self,
                 agency_colors: Optional[dict[str, str]] = None,
                 style: Optional[MapStyle] = None,
                 width: int = 720,
                 height: int = 480):
        self._colors = agency_colors or dict(_DEFAULT_AGENCY_COLORS)
        self._style = style or MapStyle()
        self._width = width
        self._height = height
        self._peers: dict[str, MapPeer] = {}
        # Index of (source, target) -> DataFlow. A tuple key lets us
        # update/remove a flow in-place without scanning a list.
        self._flows: dict[tuple[str, str], DataFlow] = {}

        # Scattermap (mapbox) renders tiles; Scattergeo draws a vector
        # globe. We default to Scattergeo since MAPBOX requires an
        # access token; users can opt in via MAPBOX env.
        self._use_tiles = os.environ.get("MAPBOX") is not None

    # ------------------------------------------------------------------
    # Builder API (called once per peer at scenario setup)
    # ------------------------------------------------------------------

    def add_peer(self, peer: MapPeer):
        self._peers[peer.name] = peer

    def add_peer_from_role(self, name: str, role) -> None:
        """Convenience: accept a scenarios.scenario.PeerRole directly."""
        # Dual-position support: scenario GeoPosition uses .lat/.lon; if a
        # stubbed object is passed, fall through to its x/y. Both forms
        # appear in tests and the fallback path in disaster_response.py.
        lat = getattr(role.position, "lat", None)
        lon = getattr(role.position, "lon", None)
        if lat is None:
            lat = getattr(role.position, "x", 0.0)
        if lon is None:
            lon = getattr(role.position, "y", 0.0)
        # Start EPA hidden so the callback layer can ramp it in.
        initial_opacity = 0.0 if role.join_phase > 0 else 1.0
        self.add_peer(MapPeer(
            name=name,
            agency=role.agency,
            kind=role.kind,
            lat=float(lat),
            lon=float(lon),
            opacity=initial_opacity,
            sitrep=name,
        ))

    # ------------------------------------------------------------------
    # Mutation API (called by callbacks as the scenario progresses)
    # ------------------------------------------------------------------

    def set_opacity(self, name: str, opacity: float):
        peer = self._peers.get(name)
        if peer is not None:
            peer.opacity = max(0.0, min(1.0, opacity))

    def mark_compromised(self, name: str):
        peer = self._peers.get(name)
        if peer is not None:
            peer.status = "compromised"

    def mark_excluded(self, name: str):
        peer = self._peers.get(name)
        if peer is not None:
            peer.status = "excluded"

    def reset_status(self, name: str):
        peer = self._peers.get(name)
        if peer is not None:
            peer.status = "active"

    def set_data_flow(self, source: str, target: str,
                      data_type: str = "", active: bool = True):
        if source not in self._peers or target not in self._peers:
            return
        self._flows[(source, target)] = DataFlow(
            source=source, target=target,
            data_type=data_type, active=active,
        )

    def clear_data_flow(self, source: str, target: str):
        self._flows.pop((source, target), None)

    # ------------------------------------------------------------------
    # Figure assembly
    # ------------------------------------------------------------------

    def _peer_color(self, peer: MapPeer) -> str:
        if peer.status == "excluded":
            # Dim the rogue so live peers read louder.
            return "#555"
        if peer.status == "compromised":
            # Red overrides agency color to flag the anomaly.
            return "#ef4444"
        return self._colors.get(peer.agency, "#888")

    def _edge_color(self, flow: DataFlow) -> str:
        # Flows involving the compromised/excluded peer are muted so the
        # viewer's eye stays on the healthy network.
        src = self._peers.get(flow.source)
        tgt = self._peers.get(flow.target)
        if src and src.status in ("compromised", "excluded"):
            return "rgba(239, 68, 68, 0.35)"
        if tgt and tgt.status in ("compromised", "excluded"):
            return "rgba(239, 68, 68, 0.35)"
        return "rgba(148, 163, 184, 0.6)"

    def _add_edges(self, fig: go.Figure):
        if not self._flows:
            return
        scatter = go.Scattermap if self._use_tiles else go.Scattergeo
        # Group by (color, active) so we submit one trace per style bucket.
        buckets: dict[tuple[str, bool], list[tuple]] = {}
        for flow in self._flows.values():
            src = self._peers.get(flow.source)
            tgt = self._peers.get(flow.target)
            if src is None or tgt is None:
                continue
            key = (self._edge_color(flow), flow.active)
            buckets.setdefault(key, []).append(
                (src.lat, src.lon, tgt.lat, tgt.lon))

        for (color, active), segs in buckets.items():
            lats, lons = [], []
            for lat1, lon1, lat2, lon2 in segs:
                lats.extend([lat1, lat2, None])
                lons.extend([lon1, lon2, None])
            fig.add_trace(scatter(
                lat=lats,
                lon=lons,
                mode="lines",
                # Plotly Scattergeo's dash works differently per scope;
                # width alone is the reliable inactive-state signal.
                line=dict(color=color,
                          width=self._style.edge_width if active else 1),
                hoverinfo="skip",
                name=f"flows-{color}-{active}",
                showlegend=False,
            ))

    def _add_peers(self, fig: go.Figure):
        scatter = go.Scattermap if self._use_tiles else go.Scattergeo
        # One trace per agency so the legend is clean.
        per_agency: dict[str, list[MapPeer]] = {}
        for p in self._peers.values():
            per_agency.setdefault(p.agency, []).append(p)

        for agency, peers in per_agency.items():
            color = self._colors.get(agency, "#888")
            marker_colors = [self._peer_color(p) for p in peers]
            opacities = [p.opacity for p in peers]
            hover = [
                f"<b>{p.name}</b><br>{p.agency} &middot; {p.kind}"
                f"<br>status: {p.status}"
                for p in peers
            ]
            marker = dict(
                color=marker_colors,
                opacity=opacities,
                size=self._style.marker_size,
                symbol=(_AGENCY_SYMBOLS.get(agency, "circle")
                        if not self._use_tiles else "circle"),
                line=dict(width=1, color=color),
            )
            fig.add_trace(scatter(
                lat=[p.lat for p in peers],
                lon=[p.lon for p in peers],
                mode="markers+text",
                text=[p.name for p in peers],
                textposition="top center",
                textfont=dict(size=9, color="#e2e8f0"),
                marker=marker,
                hovertext=hover,
                hoverinfo="text",
                name=agency,
            ))

        # Pulse trace for compromised peers -- a larger, semi-transparent
        # halo that the callback layer can size-modulate for animation.
        pulse_peers = [p for p in self._peers.values()
                       if p.status == "compromised"]
        if pulse_peers:
            fig.add_trace(scatter(
                lat=[p.lat for p in pulse_peers],
                lon=[p.lon for p in pulse_peers],
                mode="markers",
                marker=dict(
                    color="#ef4444",
                    opacity=0.25,
                    size=self._style.pulse_size,
                    symbol="circle" if self._use_tiles else "circle-open",
                ),
                hoverinfo="skip",
                name="compromise-pulse",
                showlegend=False,
            ))

    def figure(self) -> go.Figure:
        fig = go.Figure()
        # Order matters: draw edges first so markers sit on top.
        self._add_edges(fig)
        self._add_peers(fig)

        layout: dict = dict(
            autosize=True,
            width=self._width,
            height=self._height,
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor=self._style.paper_bg,
            legend=dict(
                bgcolor="rgba(18, 26, 46, 0.7)",
                bordercolor="#1f2a44",
                borderwidth=1,
                orientation="h",
                yanchor="bottom", y=0.0,
                xanchor="left",   x=0.01,
                font=dict(size=10, color="#e2e8f0"),
            ),
        )

        if self._use_tiles:
            layout["map"] = dict(
                style=os.environ.get("MAPBOX_STYLE", "dark"),
                center=dict(lat=_PNW_CENTER[0], lon=_PNW_CENTER[1]),
                zoom=_PNW_DEFAULT_ZOOM,
            )
        else:
            layout["geo"] = dict(
                scope="usa",
                projection=dict(type="albers usa"),
                showland=True,
                landcolor=self._style.land_color,
                bgcolor=self._style.paper_bg,
                subunitcolor=self._style.country_color,
                showcountries=False,
                showsubunits=True,
                center=dict(lat=_PNW_CENTER[0], lon=_PNW_CENTER[1]),
                # Fit bounds to the peer cluster if present.
                fitbounds="locations" if self._peers else None,
            )

        fig.update_layout(**layout)
        return fig


# ----------------------------------------------------------------------
# Convenience builder: one-shot figure from a scenario + runtime state
# ----------------------------------------------------------------------

def build_map_from_scenario(scenario,
                            compromised: Optional[set[str]] = None,
                            excluded: Optional[set[str]] = None,
                            active_flows: Optional[list[tuple[str, str, str]]]
                            = None,
                            peer_opacity: Optional[dict[str, float]] = None,
                            agency_colors: Optional[dict[str, str]] = None
                            ) -> go.Figure:
    """Build a complete map figure in one pass.

    Args:
        scenario:      DisasterResponseScenario (or any scenario whose
                       peers expose .agency, .kind, and .position).
        compromised:   Set of peer names currently flagged compromised.
        excluded:      Set of peer names currently flagged excluded.
        active_flows:  List of (source, target, data_type).
        peer_opacity:  Per-peer override; later-joining peers start at 0.
        agency_colors: Agency -> CSS color map.
    """
    m = AgencyMap(agency_colors=agency_colors)
    for name, role in scenario.peers.items():
        m.add_peer_from_role(name, role)
        if peer_opacity and name in peer_opacity:
            m.set_opacity(name, peer_opacity[name])

    for name in (compromised or ()):
        m.mark_compromised(name)
    for name in (excluded or ()):
        m.mark_excluded(name)

    for src, tgt, dtype in (active_flows or ()):
        m.set_data_flow(src, tgt, data_type=dtype, active=True)

    return m.figure()
