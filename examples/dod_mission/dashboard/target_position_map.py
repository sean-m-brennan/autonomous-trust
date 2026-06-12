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

# numpy and the bundled DEM loader are needed ONLY by the isometric terrain
# view. Import them defensively: numpy is an optional visualisation dependency,
# not required for the default 2D MapLibre map. A deployment without it (e.g. a
# slim coordinator image) must still import this module and serve the dashboard
# — the iso path checks for these and falls back to 2D when they're absent
# (see _ensure_terrain / figure()). This keeps a viz-only dependency from
# taking down the whole dashboard at import time.
try:
    import numpy as np
except ImportError:  # pragma: no cover - optional viz dependency
    np = None

try:
    from .build_terrain import load_terrain
except ImportError:
    try:
        from build_terrain import load_terrain  # top-level module, not package
    except ImportError:  # pragma: no cover - numpy missing => build_terrain unimportable
        load_terrain = None


# --- Isometric-view presentation knobs (tunable during demo prep) ----------
#
# The iso view (set_view_mode("iso")) renders a true 3D orthographic scene: a
# DEM terrain surface with the assets hovering above it, ALL placed at their
# real altitude in metres MSL on a LOG z-axis (scene.zaxis.type == "log").
# One coherent vertical axis means Plotly renders true-metre tick labels for
# free, and the log keeps the ~12-20 m microdrones, the ~600 m MQ-800 and the
# ~5000 m RQ-86 orbit all legible at once (~1.5 decades) instead of the high
# orbit dwarfing everything. Terrain relief (~170-380 m) sits in the bottom
# part of that same log axis.
#
#   _ISO_Z_ASPECT   z-box height relative to the (equal) x/y box. Bigger =>
#                   more vertical stretch, so terrain relief + the asset
#                   altitude spread read more strongly.
#   _ISO_ALT_TICKS  explicit z-axis tick positions, in metres MSL.
_ISO_Z_ASPECT = 0.55
_ISO_ALT_TICKS = [200, 300, 500, 1000, 2000, 5000]
# Drop the terrain surface this many metres below its true elevation so
# ground-level units (squad, sensors) sit visibly ABOVE the opaque surface
# instead of being buried in / z-fighting with it. Visual only — asset
# altitudes and the z-axis ticks stay true.
_TERRAIN_SINK_M = 12.0

# Orthographic camera eye for the isometric look. Positioned due SOUTH of and
# above the scene (x==0, y<0, z>0) looking NORTH, so the view is compass-aligned
# with the 2D overhead map: East -> screen-right, North -> screen-up/away. With
# x==0 the SOUTH edge is fronto-parallel, so the whole -6000 m North line runs
# straight along the BOTTOM of the display and +6000 m North recedes to the top.
# The y/z ratio sets the ~29° downward tilt that gives the 3D relief.
# uirevision preserves the operator's rotate/zoom across ticks; its value MUST
# change whenever the default eye changes, otherwise a client that already
# stored a camera under the old revision keeps the stale orientation (Plotly
# preserves the retained camera when uirevision is unchanged). Hence "-v2".
_ISO_CAMERA_EYE = dict(x=0.0, y=-1.9, z=1.05)
_ISO_UIREVISION = "tactical-iso-v2"


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

        # View mode: "2d" (default MapLibre top-down) or "iso" (3D orthographic
        # terrain). The default keeps the proven presentation flow untouched.
        self._view_mode: str = "2d"
        # Terrain cache for the iso view, built once on first iso render and
        # reused every tick (the DEM never changes — only the assets move).
        # _terrain_trace is the go.Surface; _terrain_x/_y are 1D ENU coordinate
        # vectors; _terrain_at samples elevation (metres) at a lat/lon.
        self._terrain_grid: Optional[np.ndarray] = None
        self._terrain_meta: Optional[dict] = None
        self._terrain_trace: Optional[go.Surface] = None
        self._terrain_x: Optional[np.ndarray] = None  # east metres per column
        self._terrain_y: Optional[np.ndarray] = None  # north metres per row
        self._iso_origin: Optional[tuple[float, float]] = None  # (lat, lon)
        self._iso_extent: Optional[tuple[float, float]] = None  # (max|x|, max|y|)
        # The orthographic camera (default iso eye) is emitted ONLY on the
        # first frame after entering iso; later frames omit scene.camera so
        # scene.uirevision preserves the operator's rotate/zoom. Plotly forces
        # the camera whenever scene.camera is present in an update — which
        # defeats uirevision — so the fix is simply to stop re-sending it.
        self._iso_camera_pending = True

    def set_view_mode(self, mode: str) -> None:
        """Select the render path: "2d" (MapLibre) or "iso" (3D terrain).

        Unknown values fall back to "2d" so a stale toggle state can't blank
        the panel. Cheap to call every tick (it just flips a flag); the
        dashboard threads this from the iso/2d toggle Store.
        """
        new_mode = "iso" if mode == "iso" else "2d"
        # Re-arm the default iso framing only when ENTERING iso; while staying
        # in iso we leave the camera out so uirevision holds the user's view.
        if new_mode == "iso" and self._view_mode != "iso":
            self._iso_camera_pending = True
        self._view_mode = new_mode

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
        """Dispatch to the active view's renderer.

        Falls back to the 2D map if the iso path can't build (e.g. the bundled
        DEM is missing) so the panel never blanks.
        """
        if self._view_mode == "iso":
            try:
                return self._figure_iso(width, height)
            except Exception:  # pragma: no cover - defensive, keep demo alive
                pass
        return self._figure_2d(width, height)

    def _figure_2d(self, width: Optional[int] = None,
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

    # ------------------------------------------------------------------
    # Isometric (3D orthographic terrain) view
    # ------------------------------------------------------------------

    # Topographic colour ramp for the terrain surface: valley green ->
    # foothill tan -> ridge stone. Reads as relief on the dark scene.
    _TERRAIN_COLORSCALE = [
        [0.0, "#2f4f2f"], [0.35, "#5c6b3a"],
        [0.7, "#8a7b54"], [1.0, "#c9bda3"],
    ]

    def _ensure_terrain(self) -> bool:
        """Load + cache the DEM and build the static terrain Surface once.

        Returns False when no bundled DEM is available (run build_terrain.py),
        leaving the caller to fall back. The Surface trace and ENU coordinate
        vectors are computed a single time and reused every tick — the terrain
        never changes, so this keeps the per-tick cost to just the assets.
        """
        if self._terrain_trace is not None:
            return True
        # numpy / DEM loader are optional (see top-of-module import guard); the
        # iso view simply isn't available without them, so fall back to 2D.
        if np is None or load_terrain is None:
            return False
        loaded = load_terrain()
        if loaded is None:
            return False
        grid, meta = loaded
        self._terrain_grid = grid
        self._terrain_meta = meta

        rows, cols = grid.shape
        south, north = meta["south"], meta["north"]
        west, east = meta["west"], meta["east"]
        olat = (south + north) / 2.0
        olon = (west + east) / 2.0
        self._iso_origin = (olat, olon)

        # 1D ENU coordinate vectors: east per column, north per row. Longitude
        # spacing folds in the cos(lat) factor at the AOI centre (good to well
        # under a metre over this 0.11-degree patch).
        lons = np.linspace(west, east, cols)
        lats = np.linspace(south, north, rows)  # row 0 = south (see build_terrain)
        self._terrain_x = np.array(
            [_enu_m(olat, olon, olat, lo)[0] for lo in lons])
        self._terrain_y = np.array(
            [_enu_m(olat, olon, la, olon)[1] for la in lats])
        self._iso_extent = (float(np.abs(self._terrain_x).max()),
                            float(np.abs(self._terrain_y).max()))

        self._terrain_trace = go.Surface(
            # z is true elevation in metres MSL (minus a small visual sink so
            # ground units aren't buried in the surface); the scene's log
            # z-axis does the compression (see _figure_iso). surfacecolor keys
            # off the TRUE elevation so the hypsometric tint still matches.
            x=self._terrain_x, y=self._terrain_y, z=grid - _TERRAIN_SINK_M,
            surfacecolor=grid,                  # colour by true elevation (m)
            colorscale=self._TERRAIN_COLORSCALE,
            showscale=False,
            opacity=1.0,
            # Soft directional lighting so ridges/valleys read as relief.
            lighting=dict(ambient=0.6, diffuse=0.8, specular=0.05,
                          roughness=0.9),
            lightposition=dict(x=-10000, y=20000, z=8000),
            hoverinfo="skip",
            name="terrain",
        )
        return True

    def _terrain_at(self, lat: float, lon: float) -> float:
        """Sample terrain elevation (metres) at a lat/lon (nearest cell)."""
        meta, grid = self._terrain_meta, self._terrain_grid
        if meta is None or grid is None:
            return 0.0
        rows, cols = grid.shape
        fi = (lat - meta["south"]) / (meta["north"] - meta["south"]) * (rows - 1)
        fj = (lon - meta["west"]) / (meta["east"] - meta["west"]) * (cols - 1)
        i = int(min(max(round(fi), 0), rows - 1))
        j = int(min(max(round(fj), 0), cols - 1))
        return float(grid[i, j])

    def _asset_z(self, lat: float, lon: float, alt: float,
                 kind: str) -> tuple[float, float, float, float, bool]:
        """Map an asset to ENU + its altitude in metres MSL (for the log axis).

        Returns ``(east_m, north_m, msl_m, agl_m, off_map)``. Datum
        normalization: the scenario stores microdrone altitude as AGL
        (~12-20 m) but everything else as MSL (~195-5000 m). Microdrone MSL =
        local terrain + its AGL; every other asset is already MSL and floored
        at the local terrain so it never renders underground. ``agl`` (height
        above local terrain) is returned for the on-plot label. The scene's log
        z-axis does the vertical compression — z values here are raw metres.

        ``off_map`` flags that the TRUE position lies outside the AOI extent
        (e.g. the jet loitering ~12 km east). The caller skips such assets so
        they simply aren't drawn — the jet appears as it crosses INTO the AOI
        on its strike run and disappears again as it egresses, rather than
        being pinned to the boundary wall. Positions are returned untouched
        (no clamping); within the AOI the true position is always used.
        """
        olat, olon = self._iso_origin
        east, north = _enu_m(olat, olon, lat, lon)
        ext_x, ext_y = self._iso_extent
        off_map = abs(east) > ext_x or abs(north) > ext_y
        terr = self._terrain_at(lat, lon)
        if kind == "microdrone":
            agl = max(0.0, alt)            # stored AGL
            msl = terr + agl
        else:
            msl = max(alt, terr)           # MSL; never below local ground
            agl = msl - terr
        return east, north, msl, agl, off_map

    def _figure_iso(self, width: Optional[int] = None,
                    height: Optional[int] = None) -> go.Figure:
        """Render the 3D orthographic terrain view.

        Raises if the terrain isn't available; ``figure()`` catches that and
        falls back to the 2D map.
        """
        if not self._ensure_terrain():
            raise RuntimeError("no bundled terrain DEM (run build_terrain.py)")
        if width is None:
            width = self._MAP_PX + self._MARGIN_L + self._MARGIN_R
        if height is None:
            height = self._MAP_PX + self._MARGIN_T + self._MARGIN_B

        fig = go.Figure()
        fig.add_trace(self._terrain_trace)   # cached, stable across ticks

        # Squad insertion anchor on the deck.
        o_e, o_n, o_z, _, _ = self._asset_z(
            SQUAD_ORIGIN_LAT, SQUAD_ORIGIN_LON, 0.0, "soldier")
        fig.add_trace(go.Scatter3d(
            x=[o_e], y=[o_n], z=[o_z], mode="markers",
            marker=dict(size=4, color="#5B6E1F"),
            hovertext=["squad insertion zone"], hoverinfo="text",
            name="squad insertion", showlegend=False,
        ))

        # Reported-target markers (the MQ-800-vs-RQ-86 disagreement story):
        # drawn on the terrain surface at the reported ground position, anomaly
        # peers ringed red. Only while the reporter is a currently-active asset.
        tgt_x: list = []; tgt_y: list = []; tgt_z: list = []
        tgt_color: list = []; tgt_name: list = []; tgt_hover: list = []
        for name, target in self._targets.items():
            if target.last_x is None or target.last_y is None:
                continue
            if name not in self._platforms:
                continue
            lat, lon = _squad_xy_to_latlon(target.last_x, target.last_y)
            e, n = _enu_m(*self._iso_origin, lat, lon)
            ext_x, ext_y = self._iso_extent
            e = min(max(e, -ext_x), ext_x); n = min(max(n, -ext_y), ext_y)
            is_anom = target.anomalous_since is not None
            tgt_x.append(e); tgt_y.append(n)
            tgt_z.append(self._terrain_at(lat, lon))  # on the terrain (m MSL)
            tgt_color.append("#ef4444" if is_anom else target.color)
            tgt_name.append(name + (" (ANOMALOUS)" if is_anom else ""))
            tgt_hover.append(f"{name} reports target<br>lat={lat:.5f} lon={lon:.5f}")
        if tgt_x:
            fig.add_trace(go.Scatter3d(
                x=tgt_x, y=tgt_y, z=tgt_z, mode="markers",
                marker=dict(size=6, color=tgt_color, symbol="diamond",
                            opacity=0.85),
                text=tgt_name, hovertext=tgt_hover, hoverinfo="text",
                customdata=[n for n in self._targets
                            if n in self._platforms
                            and self._targets[n].last_x is not None],
                name="reported targets", showlegend=False,
            ))

        # Live assets: a markers+text trace, plus a bundled "stalk" lines trace
        # dropping each asset to its ground point so altitude reads in ortho.
        a_x: list = []; a_y: list = []; a_z: list = []
        a_color: list = []; a_text: list = []; a_hover: list = []; a_cd: list = []
        s_x: list = []; s_y: list = []; s_z: list = []
        for name, p in self._platforms.items():
            lat, lon = p.get("lat"), p.get("lon")
            if lat is None or lon is None:
                continue
            kind = p.get("kind", "")
            alt = float(p.get("alt") or 0.0)
            color = p.get("color") or (
                "#5B6E1F" if kind == "soldier" else "#1FB8CD")
            e, n, z, agl, off_map = self._asset_z(lat, lon, alt, kind)
            if off_map:
                # Outside the AOI (e.g. the jet on its off-map loiter) — don't
                # draw it. It pops into view only while crossing the AOI on its
                # strike run, then disappears again on egress.
                continue
            ground_z = self._terrain_at(lat, lon)  # stalk base on terrain (m MSL)
            a_x.append(e); a_y.append(n); a_z.append(z)
            a_color.append(color); a_cd.append(name)
            # On-plot label: name + altitude above ground (matches the
            # log-scaled vertical position). Hover carries MSL + AGL both.
            a_text.append(f"{name}<br>{agl:,.0f} m AGL")
            a_hover.append(f"{name} ({kind})<br>alt {alt:.0f} m "
                           f"&middot; {agl:.0f} m AGL")
            s_x += [e, e, None]; s_y += [n, n, None]; s_z += [ground_z, z, None]
        if s_x:
            fig.add_trace(go.Scatter3d(
                x=s_x, y=s_y, z=s_z, mode="lines",
                line=dict(color="rgba(148,163,184,0.5)", width=2),
                hoverinfo="skip", name="altitude stalks", showlegend=False,
            ))
        if a_x:
            fig.add_trace(go.Scatter3d(
                x=a_x, y=a_y, z=a_z, mode="markers+text",
                marker=dict(size=5, color=a_color, opacity=0.95,
                            line=dict(width=0.5, color="#0b0f1a")),
                text=a_text, textposition="top center",
                textfont=dict(size=9, color="#e2e8f0"),
                hovertext=a_hover, hoverinfo="text",
                customdata=a_cd, name="assets", showlegend=False,
            ))

        # Fix the horizontal ranges to the AOI so unclamped far assets (the
        # jet's off-map hold) don't rescale the scene — terrain stays framed
        # and the jet moves into view as it crosses. A small margin keeps
        # AOI-edge markers off the wall.
        ext_x, ext_y = self._iso_extent
        rng_x = ext_x * 1.05
        rng_y = ext_y * 1.05
        scene = dict(
            # z is a single coherent axis: true altitude in metres MSL,
            # rendered LOG so terrain relief, low hovering drones, and the
            # high orbit all read at once. Real-metre tick labels are shown.
            xaxis=dict(title="East (m)", range=[-rng_x, rng_x],
                       backgroundcolor="#0b0f1a",
                       gridcolor="#233554", color="#94a3b8"),
            yaxis=dict(title="North (m)", range=[-rng_y, rng_y],
                       backgroundcolor="#0b0f1a",
                       gridcolor="#233554", color="#94a3b8"),
            zaxis=dict(title="Altitude (m MSL, log)", type="log",
                       showticklabels=True,
                       tickvals=_ISO_ALT_TICKS,
                       ticktext=[f"{v:,}" for v in _ISO_ALT_TICKS],
                       backgroundcolor="#0b0f1a", gridcolor="#233554",
                       color="#94a3b8"),
            aspectmode="manual",
            aspectratio=dict(x=1.0, y=1.0, z=_ISO_Z_ASPECT),
        )
        # Emit scene.camera on EVERY iso frame. scene.camera is a
        # uirevision-governed attribute, so with scene_uirevision held constant
        # Plotly.react preserves the operator's rotate/zoom across ticks and
        # treats this value only as the baseline — it does NOT snap the view
        # back. Crucially, ALWAYS sending it fixes the flash-then-revert bug:
        # the prior one-shot emit left scene.camera absent on every later
        # frame, and an absent camera makes react fall back to Plotly's
        # auto-computed default — so the configured orientation flashed once,
        # then the next tick reverted to the default direction. Always present
        # => the configured direction is the durable default.
        scene["camera"] = dict(projection=dict(type="orthographic"),
                               eye=_ISO_CAMERA_EYE)
        self._iso_camera_pending = False

        fig.update_layout(
            title=self._title,
            template="plotly_dark",
            paper_bgcolor="#0b0f1a",
            scene=scene,
            # Preserve the operator's rotate/zoom across live ticks.
            uirevision=_ISO_UIREVISION,
            scene_uirevision=_ISO_UIREVISION,
            margin={"l": 0, "r": 0, "t": self._MARGIN_T, "b": 0},
            width=width, height=height,
            showlegend=False,
        )
        return fig
