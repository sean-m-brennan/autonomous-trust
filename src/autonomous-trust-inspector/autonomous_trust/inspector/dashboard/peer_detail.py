# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Peer detail drawer -- fills `panel_detail` when a peer is clicked.

Expected interactions (wired in the callback layer):
  * Click a node in the agency map or trust-network graph -> emit the
    selected peer name as a store update.
  * The callback reads the store, looks up the peer's runtime state
    from the inspector's in-memory views, and calls `to_html()` with
    the full snapshot.

The drawer is intentionally a single `html.Div` so the existing
`panel_detail` placeholder in disaster_response_layout.py can be
overwritten wholesale rather than patched piecemeal. That keeps the
inspector's callback wiring simple.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ----------------------------------------------------------------------
# Runtime data the drawer consumes
# ----------------------------------------------------------------------

@dataclass
class IdentityInfo:
    uuid: str = ""
    zta_valid: bool = True
    joined_at: float = 0.0       # scenario seconds
    key_fingerprint: str = ""    # short form, display only


@dataclass
class ReputationSnapshot:
    """Reputation score plus the last few transactions."""
    current_score: float = 1.0
    bootstrap_complete: bool = False
    # (t, event_text, delta) -- delta in +/- score
    recent_events: list[tuple[float, str, float]] = field(default_factory=list)


@dataclass
class StreamSummary:
    """Summary of one data stream this peer produces or consumes."""
    data_type: str
    unit: str
    cadence_sec: float = 1.0
    recent_values: list[float] = field(default_factory=list)
    direction: str = "producing"   # "producing" | "consuming"
    quality: float = 1.0
    peer_counterparty: str = ""    # for consuming streams


@dataclass
class PeerDetailState:
    """Everything the drawer needs to render one peer."""
    name: str
    agency: str
    kind: str
    status: str = "active"         # active | compromised | excluded
    lat: float = 0.0
    lon: float = 0.0
    identity: IdentityInfo = field(default_factory=IdentityInfo)
    reputation: ReputationSnapshot = field(default_factory=ReputationSnapshot)
    producing: list[StreamSummary] = field(default_factory=list)
    consuming: list[StreamSummary] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)


# ----------------------------------------------------------------------
# Renderer
# ----------------------------------------------------------------------

_STATUS_COLORS = {
    "active":      ("#4ade80", "ACTIVE"),
    "compromised": ("#ef4444", "COMPROMISED"),
    "excluded":    ("#555",    "EXCLUDED"),
    "onboarding":  ("#60a5fa", "ONBOARDING"),
}


class PeerDetailPanel:
    """Renders PeerDetailState as a multi-tab HTML drawer.

    Tabs are implemented as <details>/<summary> so no JS is required;
    the first tab is open by default. When a drawer state includes the
    sensor divergence flag the compromise tab becomes the default open.
    """

    def __init__(self,
                 agency_colors: Optional[dict[str, str]] = None):
        self._colors = agency_colors or {
            "NOAA": "#1f77b4",
            "USGS": "#8c564b",
            "FEMA": "#d62728",
            "EPA":  "#2ca02c",
        }

    # --- public ------------------------------------------------------

    def to_html(self, state: Optional[PeerDetailState]) -> str:
        """Entry point: render full drawer as HTML."""
        if state is None:
            return self._empty()
        return (
            '<div style="display:flex;flex-direction:column;gap:10px">'
            + self._header(state)
            + self._body(state)
            + '</div>'
        )

    def _empty(self) -> str:
        return ('<div class="demo-placeholder" style="padding:20px">'
                '(click any peer in the map or trust network)'
                '</div>')

    # --- header ------------------------------------------------------

    def _header(self, s: PeerDetailState) -> str:
        agency_color = self._colors.get(s.agency, "#888")
        status_color, status_label = _STATUS_COLORS.get(
            s.status, ("#888", s.status.upper()))

        coords = (f"{s.lat:.3f}&deg;, {s.lon:.3f}&deg;"
                  if (s.lat or s.lon) else "--")

        return (
            f'<div style="display:flex;align-items:center;gap:12px;'
            f'padding:8px 4px">'
            f'<div style="width:12px;height:12px;border-radius:50%;'
            f'background:{agency_color}"></div>'
            f'<div style="flex:1">'
            f'<div style="font-size:16px;font-weight:700;color:#e2e8f0">'
            f'{_esc(s.name)}</div>'
            f'<div style="font-size:11px;color:#94a3b8">'
            f'{_esc(s.agency)} &middot; {_esc(s.kind)} &middot; {coords}'
            f'</div>'
            f'</div>'
            f'<div style="padding:4px 10px;border-radius:4px;'
            f'background:{status_color}22;color:{status_color};'
            f'font-size:10px;letter-spacing:0.06em;text-transform:uppercase">'
            f'{status_label}</div>'
            f'</div>'
        )

    # --- body tabs ---------------------------------------------------

    def _body(self, s: PeerDetailState) -> str:
        # Compromised peers get the data streams panel open first; the
        # Sensor Readings chart itself lives outside the iframe (in a
        # sibling html.Details owned by the Dash callback layer) so the
        # actual chart can be a dcc.Graph rather than baked-in HTML.
        tabs = [
            self._section("Identity", self._identity(s),
                          default_open=(s.status != "compromised")),
            self._section("Reputation", self._reputation(s),
                          default_open=False),
            self._section("Data Streams", self._streams(s),
                          default_open=(s.status == "compromised")),
            self._section("Capabilities", self._capabilities(s),
                          default_open=False),
        ]
        return '<div>' + "".join(tabs) + '</div>'

    @staticmethod
    def _section(title: str, body_html: str, default_open: bool = False) -> str:
        attr = " open" if default_open else ""
        return (
            f'<details{attr} style="border:1px solid #1f2a44;'
            f'border-radius:6px;margin-bottom:6px;'
            f'background:#121a2e">'
            f'<summary style="padding:8px 12px;cursor:pointer;'
            f'color:#94a3b8;text-transform:uppercase;'
            f'letter-spacing:0.06em;font-size:11px">{_esc(title)}</summary>'
            f'<div style="padding:10px 12px;border-top:1px solid #1f2a44">'
            f'{body_html}</div>'
            f'</details>'
        )

    # --- section renderers -------------------------------------------

    def _identity(self, s: PeerDetailState) -> str:
        rows = [
            ("UUID", _esc(s.identity.uuid) or "--"),
            ("ZTA credentials",
             '<span style="color:#4ade80">valid</span>'
             if s.identity.zta_valid
             else '<span style="color:#ef4444">invalid</span>'),
            ("Joined at", _fmt_t(s.identity.joined_at)),
            ("Key fingerprint",
             f'<span class="mono">{_esc(s.identity.key_fingerprint) or "--"}'
             f'</span>'),
        ]
        return _table(rows)

    def _reputation(self, s: PeerDetailState) -> str:
        score = s.reputation.current_score
        # Color: green >=0.7, yellow >=0.4, red otherwise.
        color = ("#4ade80" if score >= 0.7
                 else "#fbbf24" if score >= 0.4
                 else "#ef4444")
        bar = (
            f'<div style="height:8px;background:#1f2a44;border-radius:4px;'
            f'overflow:hidden;margin:4px 0">'
            f'<div style="width:{100 * score:.1f}%;height:100%;'
            f'background:{color}"></div></div>'
        )
        head = (
            f'<div style="display:flex;align-items:center;gap:8px">'
            f'<span style="color:{color};font-size:18px;font-weight:700"'
            f' class="mono">{score:.2f}</span>'
            f'<span style="color:#94a3b8;font-size:11px">'
            f'{"bootstrapped" if s.reputation.bootstrap_complete else "ramping up"}'
            f'</span></div>'
            + bar
        )
        if not s.reputation.recent_events:
            return head + '<div style="color:#64748b;font-size:11px">(no events yet)</div>'

        items = []
        for t, text, delta in s.reputation.recent_events[-8:]:
            sign = "+" if delta >= 0 else ""
            dcolor = "#4ade80" if delta > 0 else "#ef4444" if delta < 0 else "#94a3b8"
            items.append(
                f'<div style="display:flex;gap:8px;align-items:center;'
                f'padding:2px 0;font-size:11px">'
                f'<span class="mono" style="color:#64748b">{_fmt_t(t)}</span>'
                f'<span style="flex:1">{_esc(text)}</span>'
                f'<span class="mono" style="color:{dcolor}">{sign}{delta:.2f}</span>'
                f'</div>'
            )
        return head + '<div style="margin-top:6px">' + "".join(items) + '</div>'

    def _streams(self, s: PeerDetailState) -> str:
        if not s.producing and not s.consuming:
            return ('<div style="color:#64748b;font-size:11px">'
                    '(no streams yet)</div>')

        def _block(title: str, items: list[StreamSummary]) -> str:
            if not items:
                return ''
            rows = []
            for st in items:
                spark = _sparkline(st.recent_values)
                q_color = ("#4ade80" if st.quality >= 0.9
                           else "#fbbf24" if st.quality >= 0.7
                           else "#ef4444")
                counterparty = (f'  <span style="color:#64748b">'
                                f'from {_esc(st.peer_counterparty)}</span>'
                                if st.peer_counterparty else '')
                rows.append(
                    f'<div style="display:flex;align-items:center;gap:8px;'
                    f'font-size:11px;padding:3px 0;'
                    f'border-bottom:1px solid #1f2a44">'
                    f'<span style="flex:1">'
                    f'{_esc(st.data_type)}{counterparty}</span>'
                    f'<span class="mono" style="color:#94a3b8">{spark}</span>'
                    f'<span style="color:{q_color};font-size:10px">'
                    f'{int(100 * st.quality)}%</span>'
                    f'</div>'
                )
            return (
                f'<div style="font-size:10px;color:#64748b;text-transform:uppercase;'
                f'letter-spacing:0.06em;margin-top:6px;margin-bottom:2px">'
                f'{title}</div>' + "".join(rows)
            )

        return _block("Producing", s.producing) + _block("Consuming", s.consuming)

    def _capabilities(self, s: PeerDetailState) -> str:
        if not s.capabilities:
            return ('<div style="color:#64748b;font-size:11px">'
                    '(none advertised)</div>')
        chips = []
        for cap in s.capabilities:
            chips.append(
                f'<span style="display:inline-block;padding:2px 8px;'
                f'margin:2px;background:#1f2a44;border-radius:10px;'
                f'font-size:10px;color:#e2e8f0;font-family:monospace">'
                f'{_esc(cap)}</span>'
            )
        return '<div>' + "".join(chips) + '</div>'


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _esc(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _fmt_t(t: float) -> str:
    if t < 0:
        t = 0
    m = int(t) // 60
    s = int(t) % 60
    return f"T+{m:02d}:{s:02d}"


def _table(rows: list[tuple[str, str]]) -> str:
    body = []
    for label, value in rows:
        body.append(
            f'<tr><td style="color:#64748b;padding:2px 8px 2px 0;'
            f'font-size:11px;vertical-align:top">{_esc(label)}</td>'
            f'<td style="font-size:11px;color:#e2e8f0">{value}</td></tr>'
        )
    return (f'<table style="border-collapse:collapse;width:100%">'
            f'{"".join(body)}</table>')


def _sparkline(values: list[float], width: int = 60, height: int = 14) -> str:
    """Tiny inline SVG sparkline for a stream's recent values."""
    if not values or len(values) < 2:
        return "<span style='color:#64748b'>--</span>"
    lo, hi = min(values), max(values)
    rng = (hi - lo) or 1.0
    step = width / (len(values) - 1)
    points = []
    for i, v in enumerate(values):
        x = i * step
        y = height - ((v - lo) / rng) * height
        points.append(f"{x:.1f},{y:.1f}")
    return (
        f'<svg width="{width}" height="{height}" '
        f'style="vertical-align:middle">'
        f'<polyline points="{" ".join(points)}" fill="none" '
        f'stroke="#60a5fa" stroke-width="1"/>'
        f'</svg>'
    )
