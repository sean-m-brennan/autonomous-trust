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

from dataclasses import dataclass, field
from typing import Optional

import plotly.graph_objects as go


# Squad insertion landmark — the local-frame origin every
# target_position_x/_y reading is offset from. Mirrors
# examples/dod_mission/generators/detection.py:70-71.
SQUAD_ORIGIN_LAT = 34.706505
SQUAD_ORIGIN_LON = -86.633657

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

    def set_platforms(self, platforms: dict) -> None:
        """Ingest live platform positions for display.

        ``platforms`` maps name -> {lat, lon, alt, kind, color}. Keeps a
        short per-platform trail bounded by ``history_points``. Fed once
        per dashboard tick by the live/playback server from the
        scenario's moving squad + microdrone positions.
        """
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
