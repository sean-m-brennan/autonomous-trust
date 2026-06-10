"""Target-position map panel for the DoD mission dashboard.

Replaces the time-series ``target_x_chart`` in the live dashboard with
a Plotly map showing each peer's *reported* target position. Useful
when the storyline is "the peers disagree on *where* the target is",
which is the MQ-800 compromise beat: at T+4:15 the MQ-800 reports
compound-bravo's coordinates under the ``compound-alpha`` label while
the RQ-86s correctly report compound-alpha — on the chart this was
an X-coordinate divergence, on the map it's a visibly different
building.

Component interface (mirrors
``autonomous_trust.inspector.dashboard.sensor_chart.SensorComparisonChart``
so the existing dashboard plumbing in coordinator.py +
dod_app.py + live_server.py needs no special-casing):

    panel = TargetPositionMapPanel(peer_colors=...)
    panel.add_reading(reading)           # ingests target_position_x/_y
    panel.mark_anomalous(peer_name, t)   # validator hit → red ring
    fig = panel.figure(width, height)    # Plotly go.Figure
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

import plotly.graph_objects as go


# Squad insertion landmark — the local-frame origin every
# target_position_x/_y reading is offset from. Mirrors
# examples/dod_mission/generators/detection.py:70-71.
SQUAD_ORIGIN_LAT = 34.706505
SQUAD_ORIGIN_LON = -86.633657

# Mission objective (target building) + extraction point — the vectors the
# microdrone FOV cones face. Mirror examples/dod_mission/scenario.py:GROUND_MID
# / GROUND_EXFIL so the panel needs no scenario import (kept in sync by hand, as
# with SQUAD_ORIGIN_LAT/LON above).
OBJECTIVE_LAT = 34.72352
OBJECTIVE_LON = -86.63792
EXFIL_LAT = 34.699600
EXFIL_LON = -86.668604
# Exfil phase start (T+7:00). Mirrors scenario JOIN_DELAY_SEC[7] / the Exfil
# phase boundary; past this the drones egress to the extraction point and their
# FOV scan switches from "face the objective" to "alternate forward/backward".
_EXFIL_START_SEC = 420.0

# Microdrone field-of-view wedge geometry. This is a PRESENTATION cue — the
# detection FOV itself is a bearing-independent box (see generators/detection.py
# ROLE_FOV["microdrone"]); the wedge shows the swarm sweeping its sightline.
_FOV_HALF_ANGLE_DEG = 24.0
_FOV_MIN_M = 160.0
_FOV_MAX_M = 1200.0
_FOV_EXFIL_M = 240.0          # fixed wedge reach while egressing (no fixed target)
_FOV_ARC_STEPS = 8
_EARTH_R_M = 6371000.0
# Scan sweep: a slight side-to-side wobble of the wedge bearing so the cone
# reads as "scanning". During exfil the side-to-side is reduced and the wedge
# also alternates forward (egress heading) / backward (back toward the
# objective — watching their six).
_SCAN_PERIOD_SEC = 5.0        # side-to-side sweep period
_SCAN_SIDE_AMP_DEG = 16.0     # approach/hold side-to-side half-amplitude
_EXFIL_SIDE_AMP_DEG = 6.0     # reduced side-to-side while egressing
_EXFIL_ALT_PERIOD_SEC = 8.0   # forward<->backward alternation period


def _rgba(hex_color: str, alpha: float) -> str:
    """'#1FB8CD' -> 'rgba(31,184,205,a)' for a translucent Plotly fill."""
    h = (hex_color or "").lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    try:
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except (ValueError, IndexError):
        r, g, b = 31, 184, 205  # microdrone cyan fallback
    return f"rgba({r},{g},{b},{alpha})"


def _latlon_offset_m(lat: float, lon: float,
                     east_m: float, north_m: float) -> tuple[float, float]:
    """Shift (lat, lon) by east/north metres (equirectangular approx — exact
    enough over the few-km objective area)."""
    dlat = math.degrees(north_m / _EARTH_R_M)
    dlon = math.degrees(east_m / (_EARTH_R_M * math.cos(math.radians(lat))))
    return lat + dlat, lon + dlon


def _enu_m(lat0: float, lon0: float,
           lat1: float, lon1: float) -> tuple[float, float]:
    """East/north metres of (lat1, lon1) relative to (lat0, lon0)."""
    east = math.radians(lon1 - lon0) * _EARTH_R_M * math.cos(math.radians(lat0))
    north = math.radians(lat1 - lat0) * _EARTH_R_M
    return east, north


def _fov_cone(lat: float, lon: float, bearing_rad: float,
              radius_m: float) -> tuple[list, list]:
    """Polygon (lats, lons) for a FOV wedge apexed at (lat, lon), centred on
    ``bearing_rad`` (0 = N, +ve toward E), reaching ``radius_m``."""
    half = math.radians(_FOV_HALF_ANGLE_DEG)
    lats, lons = [lat], [lon]            # apex at the drone
    for i in range(_FOV_ARC_STEPS + 1):  # arc along the far edge
        a = bearing_rad - half + (2.0 * half) * (i / _FOV_ARC_STEPS)
        plat, plon = _latlon_offset_m(
            lat, lon, radius_m * math.sin(a), radius_m * math.cos(a))
        lats.append(plat)
        lons.append(plon)
    lats.append(lat)                    # close back to the apex
    lons.append(lon)
    return lats, lons


def _microdrone_fov_aim(lat: float, lon: float, t: float, name: str,
                        tgt_lat: float = OBJECTIVE_LAT,
                        tgt_lon: float = OBJECTIVE_LON
                        ) -> Optional[tuple[float, float]]:
    """(bearing_rad, radius_m) for a microdrone's FOV wedge at scenario-second
    ``t``, aimed at the target (tgt_lat, tgt_lon — the live drifting ISR
    target, or the static objective fallback). Pre-exfil: face the target with
    a slight side-to-side sweep. During exfil: alternate forward (egress
    heading) / backward (toward the objective) with a reduced side-to-side
    sweep. Returns None at zero range.

    Each drone gets a phase offset from its name so the swarm doesn't sweep in
    lockstep (reads as independent scanning)."""
    phase = (hash(name) % 997) / 997.0 * 2.0 * math.pi
    side = math.sin(2.0 * math.pi * t / _SCAN_PERIOD_SEC + phase)
    if t < _EXFIL_START_SEC:
        east, north = _enu_m(lat, lon, tgt_lat, tgt_lon)
        rng = math.hypot(east, north)
        if rng < 1e-6:
            return None
        bearing = math.atan2(east, north)
        bearing += math.radians(_SCAN_SIDE_AMP_DEG) * side
        radius = max(_FOV_MIN_M, min(rng, _FOV_MAX_M))
    else:
        # Egress heading: the objective -> extraction vector (stable; "forward"
        # is the way out, "backward" is back toward the objective they left).
        e_fwd, n_fwd = _enu_m(OBJECTIVE_LAT, OBJECTIVE_LON, EXFIL_LAT, EXFIL_LON)
        fwd = math.atan2(e_fwd, n_fwd)
        alt = math.sin(2.0 * math.pi * t / _EXFIL_ALT_PERIOD_SEC + phase)
        bearing = fwd if alt >= 0.0 else fwd + math.pi
        bearing += math.radians(_EXFIL_SIDE_AMP_DEG) * side
        radius = _FOV_EXFIL_M
    return bearing, radius

WGS84_EPSG = 4326
UTM_ZONE_16N_EPSG = 32616


def _wgs84_to_utm(lat: float, lon: float) -> tuple[float, float]:
    from pyproj import Transformer
    tx = Transformer.from_crs(WGS84_EPSG, UTM_ZONE_16N_EPSG, always_xy=True)
    e, n = tx.transform(lon, lat)
    return e, n


def _squad_xy_to_latlon(x: float, y: float) -> tuple[float, float]:
    """Squad-frame (metres east/north of insertion) -> WGS84 lat/lon.

    Inverse of detection.py:_utm_to_squad_xy. Memoised at module
    scope because the origin doesn't change and the round-trip
    pyproj call is otherwise the dominant cost of figure().
    """
    global _origin_utm
    if _origin_utm is None:
        _origin_utm = _wgs84_to_utm(SQUAD_ORIGIN_LAT, SQUAD_ORIGIN_LON)
    origin_e, origin_n = _origin_utm
    e, n = origin_e + x, origin_n + y
    from pyproj import Transformer
    tx = Transformer.from_crs(UTM_ZONE_16N_EPSG, WGS84_EPSG, always_xy=True)
    lon, lat = tx.transform(e, n)
    return lat, lon


_origin_utm: Optional[tuple[float, float]] = None


@dataclass
class _PeerTarget:
    """Most-recent (x, y) reported by a peer, plus optional anomaly mark."""
    last_x: Optional[float] = None
    last_y: Optional[float] = None
    last_t: float = 0.0
    color: str = "#888"
    anomalous_since: Optional[float] = None
    history: list[tuple[float, float, float]] = field(default_factory=list)


class TargetPositionMapPanel:
    """Plotly-map dashboard panel matching the SensorComparisonChart API."""

    def __init__(self, peer_colors: dict[str, str],
                 window_sec: float = 120.0,
                 title: Optional[str] = None,
                 history_points: int = 40):
        self._peer_colors = peer_colors
        self._window_sec = window_sec
        self._title = title or "Asset Positions / Target Position via Overhead ISR"
        self._history_points = history_points
        self._targets: dict[str, _PeerTarget] = {}
        # Live squad / microdrone positions (fed via set_platforms), plus
        # a short per-platform trail. Rendered alongside the reported
        # target markers so the storyline reads as "assets converging on
        # the objective, then exfiltrating".
        self._platforms: dict[str, dict] = {}
        self._platform_history: dict[str, list[tuple[float, float]]] = {}
        # Current scenario time (seconds), fed by set_platforms; drives the
        # microdrone FOV scan sweep + the exfil-mode switch. Falls back to a
        # per-frame tick when the caller doesn't supply it.
        self._t_seconds: float = 0.0
        # Live (drifting) ISR target lat/lon the FOV wedges aim at; None falls
        # back to the static OBJECTIVE_LAT/LON landmark.
        self._target_latlon: Optional[tuple[float, float]] = None

    def add_reading(self, reading) -> None:
        """Pair target_position_x/_y readings into a (lat, lon) per peer.

        Each peer sends parallel x/y readings; we stash the latest of
        each and only refresh the map marker when both are present.
        """
        dt = getattr(reading, "data_type", None)
        if dt not in ("target_position_x", "target_position_y"):
            return
        name = reading.peer_name
        if name not in self._targets:
            self._targets[name] = _PeerTarget(
                color=self._peer_colors.get(name, "#888"))
        target = self._targets[name]
        target.last_t = reading.timestamp.total_seconds()
        if dt == "target_position_x":
            target.last_x = float(reading.value)
        else:
            target.last_y = float(reading.value)
        if target.last_x is not None and target.last_y is not None:
            target.history.append((target.last_t,
                                    target.last_x, target.last_y))
            # Bound the per-peer history so figure() stays cheap.
            if len(target.history) > self._history_points:
                target.history = target.history[-self._history_points:]

    def set_platforms(self, platforms: dict,
                      t_seconds: Optional[float] = None,
                      target_latlon: Optional[tuple] = None) -> None:
        """Ingest live platform positions for display.

        ``platforms`` maps name -> {lat, lon, alt, kind, color}. Keeps a
        short per-platform trail bounded by ``history_points``. Fed once
        per dashboard tick by the live/playback server from the
        scenario's moving squad + microdrone positions. ``t_seconds`` is the
        scenario clock (drives the microdrone FOV scan + exfil mode); when
        omitted it falls back to a per-frame increment so the sweep still
        animates. ``target_latlon`` is the live (drifting) ISR target the FOV
        wedges aim at; None keeps the static OBJECTIVE landmark."""
        if t_seconds is not None:
            self._t_seconds = float(t_seconds)
        else:
            self._t_seconds += 1.0
        if target_latlon is not None:
            self._target_latlon = (float(target_latlon[0]),
                                   float(target_latlon[1]))
        self._platforms = dict(platforms or {})
        for name, p in self._platforms.items():
            lat, lon = p.get("lat"), p.get("lon")
            if lat is None or lon is None:
                continue
            hist = self._platform_history.setdefault(name, [])
            if not hist or hist[-1] != (lat, lon):
                hist.append((lat, lon))
                if len(hist) > self._history_points:
                    del hist[:-self._history_points]

    def mark_anomalous(self, peer_name: str, t: float) -> None:
        """Flag a peer's marker — figure() draws a red ring around it."""
        if peer_name in self._targets:
            self._targets[peer_name].anomalous_since = t

    def legend_groups(self) -> list:
        """Structured legend data for an external (HTML) legend.

        The Plotly figure draws no legend of its own (showlegend=False);
        the dashboard renders this beside the map so CSS controls the
        horizontal layout. Returns an ordered list of
        ``(group_title, [{"label", "color"}, ...])`` — "Asset positions"
        (live platform markers) then "Target position" (per-peer reported
        targets, anomalous peers flagged in red)."""
        groups = []
        asset_items = []
        for name, p in self._platforms.items():
            if p.get("lat") is None or p.get("lon") is None:
                continue
            kind = p.get("kind", "")
            color = p.get("color") or (
                "#5B6E1F" if kind == "soldier" else "#1FB8CD")
            asset_items.append({"label": name, "color": color})
        if asset_items:
            groups.append(("Asset positions", asset_items))
        target_items = []
        for name, target in self._targets.items():
            if target.last_x is None or target.last_y is None:
                continue
            # Only while the reporter is a currently-active asset: a late
            # joiner's stored target report (e.g. the MQ-800's) must not show
            # before the platform itself arrives, nor linger after it drops.
            if name not in self._platforms:
                continue
            is_anom = target.anomalous_since is not None
            target_items.append({
                "label": name + (" (ANOMALOUS)" if is_anom else ""),
                "color": "#ef4444" if is_anom else target.color,
            })
        if target_items:
            groups.append(("Target position", target_items))
        return groups

    # Layout geometry. The map matches the trust/noise panes' fixed
    # width (900); margins are chosen so the *map area* (figure minus
    # margins) is square — width 900-2*10 == height 940-40-20 == 880 px.
    # The legend is rendered OUTSIDE the figure as a sibling HTML div
    # (see legend_groups() + live_server), so no bottom margin is
    # reserved for it here.
    _MAP_PX = 880          # square map-area side length
    _MARGIN_L = _MARGIN_R = 10
    _MARGIN_T = 40         # title
    _MARGIN_B = 20

    def figure(self, width: Optional[int] = None,
               height: Optional[int] = None) -> go.Figure:
        if width is None:
            width = self._MAP_PX + self._MARGIN_L + self._MARGIN_R   # 900
        if height is None:
            height = self._MAP_PX + self._MARGIN_T + self._MARGIN_B  # 1160
        fig = go.Figure()

        # Squad-insertion origin marker — anchors the map even when no
        # peer has reported yet.
        origin_trace = go.Scattermap(
            lat=[SQUAD_ORIGIN_LAT], lon=[SQUAD_ORIGIN_LON],
            mode="markers", marker={"size": 8, "color": "#5B6E1F"},
            name="squad insertion", hovertext=["squad insertion zone"],
            hoverinfo="text", showlegend=False,
        )
        traces = [origin_trace]

        latest_lat: list[float] = []
        latest_lon: list[float] = []
        for name, target in self._targets.items():
            if target.last_x is None or target.last_y is None:
                continue
            # Only render a reported target while its reporter is a currently-
            # active asset (in set_platforms). Keeps the MQ-800's target marker
            # from appearing before the MQ-800 itself joins (and from lingering
            # after a peer drops). The reading stays cached for when it returns.
            if name not in self._platforms:
                continue
            # Recent trail per peer — dotted line of last N positions.
            if len(target.history) > 1:
                lats: list[float] = []
                lons: list[float] = []
                for _t, x, y in target.history:
                    lat, lon = _squad_xy_to_latlon(x, y)
                    lats.append(lat)
                    lons.append(lon)
                traces.append(go.Scattermap(
                    lat=lats, lon=lons, mode="lines",
                    line={"width": 1, "color": target.color},
                    opacity=0.45,
                    name=f"{name} trail", showlegend=False,
                    hoverinfo="skip",
                ))
            # Current-position marker.
            lat, lon = _squad_xy_to_latlon(target.last_x, target.last_y)
            latest_lat.append(lat)
            latest_lon.append(lon)
            is_anom = target.anomalous_since is not None
            outer = go.Scattermap(
                lat=[lat], lon=[lon], mode="markers",
                marker={
                    "size": 22 if is_anom else 14,
                    "color": "#ef4444" if is_anom else target.color,
                    "opacity": 0.65 if is_anom else 0.95,
                },
                name=name + (" (ANOMALOUS)" if is_anom else ""),
                # customdata carries the bare peer name so a map click can
                # resolve to a drawer selection (live_server click callback).
                customdata=[name],
                legendgroup="target",
                legend="legend2",
                hovertext=[f"{name}: target at "
                           f"({target.last_x:+.0f} m, "
                           f"{target.last_y:+.0f} m)"
                           f"<br>lat={lat:.5f} lon={lon:.5f}"],
                hoverinfo="text",
            )
            traces.append(outer)
            if is_anom:
                # Inner dot in the peer colour so the agency colour is
                # still legible under the red anomaly ring.
                traces.append(go.Scattermap(
                    lat=[lat], lon=[lon], mode="markers",
                    marker={"size": 10, "color": target.color},
                    legendgroup="target", legend="legend2",
                    showlegend=False, hoverinfo="skip",
                ))

        # Live asset positions + flight-path trails (set_platforms). Drawn
        # after the target markers so assets sit on top. Soldiers render as
        # larger green dots, microdrones as smaller cyan dots, RQ-86 / MQ-800
        # as their role colours tracing broad circular orbits; an explicit
        # per-platform color overrides the kind default. These populate the
        # "Asset positions" legend group, distinct from the per-peer
        # "Target position" reports above — the same peer can appear in both
        # (we track where each asset *is* and where it *says the target is*).
        # Microdrone field-of-view wedges, sweeping their sightline so the swarm
        # visibly "scans" and the (otherwise small, mutually overlapping)
        # microdrone dots read clearly. Pre-exfil the wedge faces the objective
        # with a slight side-to-side sweep; during exfil it alternates forward
        # (egress) / backward (rear security) with a reduced sweep. Drawn before
        # the asset dots so the markers sit on top of the translucent fill.
        for name, p in self._platforms.items():
            if p.get("kind") != "microdrone":
                continue
            lat, lon = p.get("lat"), p.get("lon")
            if lat is None or lon is None:
                continue
            tgt_lat, tgt_lon = self._target_latlon or (OBJECTIVE_LAT,
                                                        OBJECTIVE_LON)
            aim = _microdrone_fov_aim(lat, lon, self._t_seconds, name,
                                      tgt_lat, tgt_lon)
            if aim is None:
                continue
            bearing, radius = aim
            cone_lats, cone_lons = _fov_cone(lat, lon, bearing, radius)
            color = p.get("color") or "#1FB8CD"
            traces.append(go.Scattermap(
                lat=cone_lats, lon=cone_lons, mode="lines",
                fill="toself", fillcolor=_rgba(color, 0.12),
                line={"width": 0.5, "color": color}, opacity=0.6,
                name=f"{name} FOV", legendgroup="asset", legend="legend",
                showlegend=False, hoverinfo="skip",
            ))

        for name, p in self._platforms.items():
            lat, lon = p.get("lat"), p.get("lon")
            if lat is None or lon is None:
                continue
            kind = p.get("kind", "")
            color = p.get("color") or (
                "#5B6E1F" if kind == "soldier" else "#1FB8CD")
            hist = self._platform_history.get(name, [])
            if len(hist) > 1:
                traces.append(go.Scattermap(
                    lat=[h[0] for h in hist], lon=[h[1] for h in hist],
                    mode="lines", line={"width": 1, "color": color},
                    opacity=0.5, name=f"{name} trail",
                    legendgroup="asset", legend="legend",
                    showlegend=False, hoverinfo="skip",
                ))
            traces.append(go.Scattermap(
                lat=[lat], lon=[lon], mode="markers",
                marker={"size": 11 if kind == "soldier" else 8,
                        "color": color},
                name=name,
                customdata=[name],
                legendgroup="asset",
                legend="legend",
                hovertext=[f"{name} ({kind})"
                           f"<br>alt {float(p.get('alt') or 0.0):.0f} m"],
                hoverinfo="text",
            ))

        for tr in traces:
            fig.add_trace(tr)

        # Center on the mean of reported positions; fall back to the
        # origin when no peer has reported yet. These only take effect on
        # the *first* render — see uirevision below.
        if latest_lat:
            c_lat = sum(latest_lat) / len(latest_lat)
            c_lon = sum(latest_lon) / len(latest_lon)
        else:
            c_lat, c_lon = SQUAD_ORIGIN_LAT, SQUAD_ORIGIN_LON

        fig.update_layout(
            title=self._title,
            template="plotly_dark",
            map={
                "style": "carto-darkmatter",
                "center": {"lat": c_lat, "lon": c_lon},
                "zoom": 13,
                # Constant across ticks: Plotly preserves the user's
                # pan/zoom and ignores the code-supplied center/zoom on
                # every render after the first, so the live update
                # refreshes the markers without snapping the view back.
                "uirevision": "target-position-map",
            },
            # Layout-level fallback so a Plotly build that reads the
            # master uirevision (rather than the per-subplot one) also
            # holds the view steady.
            uirevision="target-position-map",
            margin={"l": self._MARGIN_L, "r": self._MARGIN_R,
                    "t": self._MARGIN_T, "b": self._MARGIN_B},
            width=width, height=height,
            # The legend is drawn as a separate HTML div beside the map
            # (see legend_groups()), so the figure's own legend is off.
            showlegend=False,
        )
        return fig
