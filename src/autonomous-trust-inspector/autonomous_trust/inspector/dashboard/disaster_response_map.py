# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

import math
import os
from dataclasses import dataclass, field
from typing import Optional

import plotly.graph_objects as go


# Earth radius in km for the haversine-based offsets used by
# range circles. WGS-84 mean; precise enough for visual radii up
# to ~hundreds of km without needing per-latitude ellipsoid math.
_EARTH_RADIUS_KM = 6371.0088


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
        range_km:    Sensor/comm-range radius. 0 (default) suppresses
                     the circle so peers without a documented range
                     don't acquire phantom coverage.
    """
    name: str
    agency: str
    kind: str
    lat: float
    lon: float
    opacity: float = 1.0
    status: str = "active"
    sitrep: str = ""
    range_km: float = 0.0


@dataclass
class DataFlow:
    """One active data flow between two peers.

    Attributes:
        source:      Peer name producing the data.
        target:      Peer name consuming it.
        data_type:   Short label (e.g. "weather_stream"); hover only.
        active:      False renders a thinner, dimmer edge.
        progress:    0.0..1.0 fraction along source→target at which
                     to draw the "messenger" particle. Static within
                     a single figure(); the callback layer advances
                     it each tick to animate flow direction. 0.5
                     (midpoint) is the default so a non-animated
                     consumer still gets a plausible-looking marker.
    """
    source: str
    target: str
    data_type: str = ""
    active: bool = True
    progress: float = 0.5


@dataclass
class MovementPath:
    """Historical trajectory for a peer.

    Used for mobile assets — drones, vehicles, rescue boats — where the
    static marker alone hides movement context. Render order: paths
    sit *under* peers so the current-position marker stays on top.

    Attributes:
        peer:        Peer name the path belongs to.
        lats:        Sequence of decimal-degree latitudes, oldest first.
        lons:        Sequence of decimal-degree longitudes, oldest first.

    `lats` and `lons` must be the same length; mismatched inputs are
    dropped in render rather than raising, because the callback layer
    may be mid-update.
    """
    peer: str
    lats: list[float] = field(default_factory=list)
    lons: list[float] = field(default_factory=list)


@dataclass
class DetectionMarker:
    """One peer's most-recent guess at where a target sits.

    The MQ-800-vs-RQ-86 disagreement story (Stretch Goal 2) shows up
    here visually: honest peers agree on a target's lat/lon so their
    markers cluster on the map; a compromised peer's marker sits
    visibly offset.

    Attributes:
        peer_name:    Producing peer; marker is coloured by its agency.
        target_lat:   Reported target latitude.
        target_lon:   Reported target longitude.
        world_uid:    Catalogue ID the peer thinks it's tracking.
        label:        Short class/role label for hover (e.g. "target-building").
        confidence:   0..1; rendered as marker opacity floor.
    """
    peer_name: str
    target_lat: float
    target_lon: float
    world_uid: str = ""
    label: str = ""
    confidence: float = 1.0


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
        # Movement paths keyed by peer name. The callback layer
        # extends these in-place each tick; the figure renders them
        # under the peer markers.
        self._paths: dict[str, MovementPath] = {}
        # Per-peer detection markers (Stretch Goal 2). Latest only;
        # the callback layer overwrites each tick. Keyed by peer_name
        # so a peer's marker tracks the operator's most-recent
        # reported target.
        self._detections: dict[str, DetectionMarker] = {}

        # Scattermap (mapbox) renders tiles; Scattergeo draws a vector
        # globe. We default to Scattergeo since MAPBOX requires an
        # access token; users can opt in by setting MAPBOX to a truthy
        # value. An empty-string export won't count.
        self._use_tiles = bool(os.environ.get("MAPBOX"))

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
                      data_type: str = "", active: bool = True,
                      progress: Optional[float] = None):
        if source not in self._peers or target not in self._peers:
            return
        existing = self._flows.get((source, target))
        # Preserve an in-flight `progress` across re-`set` calls so
        # the callback layer can update other fields (e.g. flip
        # active off, change data_type) without snapping the
        # messenger back to the midpoint.
        if progress is None:
            progress = existing.progress if existing else 0.5
        self._flows[(source, target)] = DataFlow(
            source=source, target=target,
            data_type=data_type, active=active,
            progress=max(0.0, min(1.0, progress)),
        )

    def clear_data_flow(self, source: str, target: str):
        self._flows.pop((source, target), None)

    def set_peer_detection(self, peer_name: str, target_lat: float,
                           target_lon: float, world_uid: str = "",
                           label: str = "",
                           confidence: float = 1.0):
        """Record peer_name's latest target lat/lon for the map.

        No-op when the peer wasn't added (callback layer races with
        scenario setup). Overwrites any prior marker for the same peer.
        """
        if peer_name not in self._peers:
            return
        self._detections[peer_name] = DetectionMarker(
            peer_name=peer_name,
            target_lat=float(target_lat), target_lon=float(target_lon),
            world_uid=world_uid, label=label,
            confidence=max(0.0, min(1.0, float(confidence))),
        )

    def clear_peer_detection(self, peer_name: str):
        self._detections.pop(peer_name, None)

    def set_flow_progress(self, source: str, target: str,
                          progress: float):
        """Advance the messenger particle along an active flow.

        Idempotent and bounds-clamped. No-op when the flow doesn't
        exist — the caller is the dashboard tick driver, which may
        race a `clear_data_flow` on a neighbouring callback.
        """
        flow = self._flows.get((source, target))
        if flow is None:
            return
        flow.progress = max(0.0, min(1.0, progress))

    def add_movement_path(self, peer: str,
                          lats: Optional[list[float]] = None,
                          lons: Optional[list[float]] = None):
        """Register (or replace) a peer's trajectory polyline.

        Pass `lats=lons=None` to seed an empty path that the
        callback layer will extend via :meth:`extend_movement_path`.
        Unknown peer names are ignored — keeps the API tolerant of
        out-of-order setup vs the scenario import.
        """
        if peer not in self._peers:
            return
        self._paths[peer] = MovementPath(
            peer=peer,
            lats=list(lats or ()),
            lons=list(lons or ()),
        )

    def extend_movement_path(self, peer: str, lat: float, lon: float,
                             max_points: int = 512):
        """Append a new sample to the peer's path, bounded in size.

        `max_points` caps the polyline to avoid unbounded memory
        growth on long-running demos. The bound is generous; a
        boat ticking at 1 Hz fills it in ~8.5 minutes, which is
        plenty for a single demo session.
        """
        path = self._paths.get(peer)
        if path is None:
            if peer not in self._peers:
                return
            path = MovementPath(peer=peer, lats=[], lons=[])
            self._paths[peer] = path
        path.lats.append(lat)
        path.lons.append(lon)
        if len(path.lats) > max_points:
            # Drop oldest samples in a single slice rather than
            # pop()ing per tick — O(N) amortised vs O(N) per call.
            drop = len(path.lats) - max_points
            path.lats = path.lats[drop:]
            path.lons = path.lons[drop:]

    def clear_movement_path(self, peer: str):
        self._paths.pop(peer, None)

    def set_range(self, peer: str, range_km: float):
        """Set or update a peer's sensor/comm range circle.

        `range_km <= 0` removes the circle. Mirrors the
        `mark_compromised` mutator style so the callback layer
        treats it uniformly.
        """
        p = self._peers.get(peer)
        if p is not None:
            p.range_km = max(0.0, range_km)

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

    def _add_paths(self, fig: go.Figure):
        """Render historical trajectories under the peer markers."""
        if not self._paths:
            return
        scatter = go.Scattermap if self._use_tiles else go.Scattergeo
        # One bundled trace keeps the legend clean. Plotly accepts a
        # break sentinel — None for Scattergeo, ``np.nan`` would also
        # work — to join multiple polylines into a single trace.
        lats: list = []
        lons: list = []
        for path in self._paths.values():
            if len(path.lats) != len(path.lons) or len(path.lats) < 2:
                continue
            lats.extend(path.lats)
            lons.extend(path.lons)
            lats.append(None)
            lons.append(None)
        if not lats:
            return
        fig.add_trace(scatter(
            lat=lats,
            lon=lons,
            mode="lines",
            # Trails sit visually behind agency-colored edges; pick a
            # neutral grey that reads on both land and water at low
            # opacity so it doesn't pull focus from the current edges.
            line=dict(color="rgba(148, 163, 184, 0.4)", width=1),
            hoverinfo="skip",
            name="movement-paths",
            showlegend=False,
        ))

    def _add_ranges(self, fig: go.Figure):
        """Render per-peer range circles as polygon approximations.

        Scattergeo/Scattermap have no native circle primitive, so
        we draw a 36-vertex regular polygon around each (lat, lon)
        with the radius supplied in km. The polygon is closed by
        repeating the first vertex, then `None`-separated from the
        next peer's polygon so a single trace covers everything.
        """
        peers_with_range = [p for p in self._peers.values()
                            if p.range_km > 0.0]
        if not peers_with_range:
            return
        scatter = go.Scattermap if self._use_tiles else go.Scattergeo
        lats: list = []
        lons: list = []
        # 36 vertices = 10° steps; smooth enough at typical demo
        # zoom levels and cheap to recompute on every figure() call.
        steps = 36
        for p in peers_with_range:
            lat_rad = math.radians(p.lat)
            # km per degree at this latitude — flat-earth approximation
            # good to ~0.5% within a few hundred km. Avoids the heavier
            # great-circle-destination formula that would otherwise
            # need to run per vertex.
            km_per_deg_lat = math.pi * _EARTH_RADIUS_KM / 180.0
            km_per_deg_lon = km_per_deg_lat * math.cos(lat_rad)
            if km_per_deg_lon <= 1e-6:
                # Near the poles longitude collapses; skip the circle
                # rather than draw a degenerate horizontal line.
                continue
            dlat = p.range_km / km_per_deg_lat
            dlon = p.range_km / km_per_deg_lon
            for i in range(steps + 1):  # +1 closes the polygon
                theta = 2.0 * math.pi * i / steps
                lats.append(p.lat + dlat * math.sin(theta))
                lons.append(p.lon + dlon * math.cos(theta))
            lats.append(None)
            lons.append(None)
        if not lats:
            return
        fig.add_trace(scatter(
            lat=lats,
            lon=lons,
            mode="lines",
            line=dict(color="rgba(56, 189, 248, 0.35)", width=1),
            hoverinfo="skip",
            name="ranges",
            showlegend=False,
        ))

    def _add_flow_particles(self, fig: go.Figure):
        """Render a "messenger dot" along each active flow.

        Position is a simple lerp between source/target — fine for
        demo-scale distances. Great-circle interpolation would matter
        at intercontinental scales; the disaster-response cluster
        sits in the Pacific Northwest. Static within a figure(); the
        callback layer ticks `progress` to move it.
        """
        if not self._flows:
            return
        scatter = go.Scattermap if self._use_tiles else go.Scattergeo
        lats: list = []
        lons: list = []
        hover: list = []
        for flow in self._flows.values():
            if not flow.active:
                continue
            src = self._peers.get(flow.source)
            tgt = self._peers.get(flow.target)
            if src is None or tgt is None:
                continue
            t = flow.progress
            lats.append(src.lat + (tgt.lat - src.lat) * t)
            lons.append(src.lon + (tgt.lon - src.lon) * t)
            label = flow.data_type or "flow"
            hover.append(f"{flow.source} → {flow.target}<br>{label}")
        if not lats:
            return
        # Bright cyan reads well on the dark paper background and is
        # distinct from any of the agency colors above.
        fig.add_trace(scatter(
            lat=lats,
            lon=lons,
            mode="markers",
            marker=dict(
                color="#22d3ee",
                size=8,
                opacity=0.9,
                symbol="circle" if self._use_tiles else "circle",
            ),
            hovertext=hover,
            hoverinfo="text",
            name="flow-particles",
            showlegend=False,
        ))

    def _add_detection_markers(self, fig: go.Figure):
        """Render per-peer detection markers at reported target lat/lon.

        Each marker is coloured by the producing peer's agency and
        tagged with the world_uid for hover. A thin line from the peer
        to its reported target reads as a sight-line; honest peers'
        sight-lines converge on the same point, the compromised
        peer's sight-line diverges visibly.
        """
        if not self._detections:
            return
        scatter = go.Scattermap if self._use_tiles else go.Scattergeo
        # Sight-lines first so they sit under the marker dots.
        line_lats: list = []
        line_lons: list = []
        marker_lats: list = []
        marker_lons: list = []
        marker_colors: list = []
        marker_hover: list = []
        marker_text: list = []
        for marker in self._detections.values():
            peer = self._peers.get(marker.peer_name)
            if peer is None:
                continue
            colour = self._colors.get(peer.agency, "#94a3b8")
            line_lats += [peer.lat, marker.target_lat, None]
            line_lons += [peer.lon, marker.target_lon, None]
            marker_lats.append(marker.target_lat)
            marker_lons.append(marker.target_lon)
            marker_colors.append(colour)
            marker_text.append(marker.world_uid or "")
            marker_hover.append(
                f"{marker.peer_name} → {marker.world_uid or '(no uid)'}<br>"
                f"{marker.label or '(unlabelled)'} "
                f"(conf {marker.confidence:.2f})"
            )
        if line_lats:
            # Scattergeo.line supports `dash`; Scattermap.line does NOT
            # (it rejects the property key even when the value is None), so
            # only include it on the vector-globe path. Mirrors the flows
            # trace, which drops dash for the same reason.
            line_kw = dict(color="rgba(148, 163, 184, 0.55)", width=1)
            if not self._use_tiles:
                line_kw["dash"] = "dot"
            fig.add_trace(scatter(
                lat=line_lats,
                lon=line_lons,
                mode="lines",
                line=line_kw,
                hoverinfo="skip",
                name="detection-sightlines",
                showlegend=False,
            ))
        if marker_lats:
            fig.add_trace(scatter(
                lat=marker_lats,
                lon=marker_lons,
                mode="markers+text",
                marker=dict(
                    color=marker_colors,
                    size=9,
                    opacity=0.85,
                    symbol=("circle" if self._use_tiles
                            else "circle-open"),
                ),
                text=marker_text,
                textposition="bottom center",
                textfont=dict(size=8, color="#cbd5f5"),
                hovertext=marker_hover,
                hoverinfo="text",
                name="detection-targets",
                showlegend=False,
            ))

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
            )
            # Scattergeo.marker supports .line (outline); Scattermap's
            # does not — validator rejects it.
            if not self._use_tiles:
                marker["line"] = dict(width=1, color=color)
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
        # Layer order (back → front) is load-bearing:
        #   1. ranges — broadest, dimmest; bottom of the stack so
        #      they tint the underlying terrain without obscuring
        #      anything overlaid.
        #   2. movement paths — trails read as history; sit under
        #      everything else.
        #   3. edges — current data flows; thin lines.
        #   4. flow particles — bright dots ON the edges; need to
        #      be above the edges to be visible.
        #   5. detection markers — per-peer target guesses; clusters
        #      visually for agreeing peers, offsets for disagreeing
        #      ones. Sits under peers so the producer marker stays on
        #      top.
        #   6. peers — primary subject; above all.
        self._add_ranges(fig)
        self._add_paths(fig)
        self._add_edges(fig)
        self._add_flow_particles(fig)
        self._add_detection_markers(fig)
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
