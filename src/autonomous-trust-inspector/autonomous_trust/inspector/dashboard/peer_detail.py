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
from typing import Any, Optional


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
    # True for a pre-established peer that has not yet produced a consensus
    # reputation. The drawer then renders "forming…" instead of a numeric
    # score, matching the Reputations list (which shows the same for a None
    # score) so the two panels never disagree for a still-forming peer.
    forming: bool = False
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
class DetectionSummary:
    """Latest sparse-detection emission from this peer.

    The dashboard caches one of these per peer and pushes it into the
    drawer when a peer is selected. Fields are intentionally kept
    JSON-serialisable so the cache survives a dcc.Store roundtrip.
    """
    crop_b64: str = ""                       # base64 JPEG; empty = no contact
    crop_size_px: tuple[int, int] = (0, 0)   # (width, height) of the crop
    bbox_in_crop_px: tuple[int, int, int, int] = (0, 0, 0, 0)
    label: str = ""
    world_uid: str = ""
    confidence: float = 0.0
    age_sec: float = 0.0                     # seconds since the reading landed


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
    # Sparse-detection panel (Stretch Goal 2 / Phase 3). None means the
    # peer has no detection source attached; a present DetectionSummary
    # with empty crop_b64 means "active, no contacts" (renders the
    # placeholder state); age_sec > STALE_AFTER_SEC dims the image.
    detection: Optional[DetectionSummary] = None
    detection_log: list[DetectionSummary] = field(default_factory=list)


# Detection age (sec) beyond which the rendered image dims to "STALE".
DETECTION_STALE_AFTER_SEC = 30.0
# Maximum thumbnails shown in the per-peer log strip.
DETECTION_LOG_DISPLAY_LIMIT = 5


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
        ]
        if s.detection is not None:
            tabs.append(self._section(
                "Detection", self._detection(s),
                default_open=(s.status == "compromised")))
        tabs.append(self._section(
            "Capabilities", self._capabilities(s), default_open=False))
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
        if s.reputation.forming:
            # No consensus reputation yet — show "forming…" (matching the
            # Reputations list) with an empty bar, rather than a misleading
            # numeric score that would read as compromised at 0.00.
            head = (
                '<div style="display:flex;align-items:center;gap:8px">'
                '<span style="color:#64748b;font-size:18px;font-weight:700"'
                ' class="mono">forming…</span>'
                '<span style="color:#94a3b8;font-size:11px">'
                'awaiting consensus</span></div>'
                '<div style="height:8px;background:#1f2a44;border-radius:4px;'
                'overflow:hidden;margin:4px 0"></div>'
            )
        else:
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

    def _detection(self, s: PeerDetailState) -> str:
        d = s.detection
        assert d is not None  # _body guards this
        # No contacts yet -> placeholder + (possibly) the log strip.
        if not d.crop_b64:
            return ('<div style="color:#64748b;font-size:11px;'
                    'padding:8px 4px">(active, no contacts)</div>'
                    + self._detection_log(s))

        stale = d.age_sec > DETECTION_STALE_AFTER_SEC
        # max_width=None -> the crop fills the full width of the drawer.
        main = _detection_image_svg(d, dimmed=stale, max_width=None)
        meta = (
            f'<div style="display:flex;align-items:center;gap:8px;'
            f'font-size:11px;margin-top:6px">'
            f'<span class="mono" style="color:#e2e8f0">'
            f'{_esc(d.label) or "(unlabelled)"}</span>'
            f'<span class="mono" style="color:#94a3b8">'
            f'conf {d.confidence:.2f}</span>'
            f'<span class="mono" style="color:#94a3b8">'
            f'uid {_esc(d.world_uid) or "-"}</span>'
            f'<span style="flex:1"></span>'
            f'<span class="mono" style="color:'
            f'{"#ef4444" if stale else "#64748b"}">'
            f'{int(d.age_sec)}s ago{" STALE" if stale else ""}</span>'
            f'</div>'
        )
        return main + meta + self._detection_log(s)

    def _detection_log(self, s: PeerDetailState) -> str:
        log = s.detection_log[-DETECTION_LOG_DISPLAY_LIMIT:]
        if not log:
            return ''
        thumbs = []
        for prev in reversed(log):  # newest first
            if not prev.crop_b64:
                continue
            thumbs.append(
                f'<img src="data:image/jpeg;base64,{prev.crop_b64}"'
                f' alt="{_esc(prev.world_uid)}"'
                f' title="{_esc(prev.label)} ({prev.confidence:.2f})"'
                f' style="width:48px;height:auto;border:1px solid #1f2a44;'
                f'border-radius:2px"/>'
            )
        if not thumbs:
            return ''
        return (f'<div style="display:flex;gap:4px;margin-top:8px;'
                f'overflow-x:auto">{"".join(thumbs)}</div>')

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


def _detection_image_svg(d: "DetectionSummary",
                         dimmed: bool = False,
                         max_width: int = 260) -> str:
    """Render the crop as inline SVG with a red bbox rectangle.

    The crop is embedded as a base64 data URI (no external assets).
    The SVG fills the width of its container (``width:100%``) and the
    ``viewBox`` makes the height scale with it, preserving aspect; the
    bbox coordinates are in the crop's pixel frame and are rendered in
    the same SVG userspace, so they auto-scale with the image.
    ``max_width`` is kept as an optional pixel cap (``None`` = fill
    unbounded) so a tiny crop isn't blown up past its sensible size.
    """
    cw, ch = d.crop_size_px
    if cw <= 0 or ch <= 0:
        return ('<div style="padding:8px 4px;color:#64748b;'
                'font-size:11px">(crop dimensions unknown)</div>')
    bx1, by1, bx2, by2 = d.bbox_in_crop_px
    opacity = "0.4" if dimmed else "1"
    cap = f'max-width:{int(max_width)}px;' if max_width else ''
    overlay_label = ('<text x="50%" y="50%" fill="#ef4444" '
                     'font-family="monospace" font-size="14" '
                     'font-weight="bold" text-anchor="middle">STALE</text>'
                     if dimmed else '')
    return (
        f'<svg viewBox="0 0 {cw} {ch}" '
        f'preserveAspectRatio="xMidYMid meet" '
        f'style="display:block;width:100%;height:auto;{cap}'
        f'border:1px solid #1f2a44;'
        f'border-radius:4px;background:#000">'
        f'<image href="data:image/jpeg;base64,{d.crop_b64}" '
        f'x="0" y="0" width="{cw}" height="{ch}" '
        f'opacity="{opacity}"/>'
        f'<rect x="{bx1}" y="{by1}" width="{bx2 - bx1}" '
        f'height="{by2 - by1}" fill="none" stroke="#ef4444" '
        f'stroke-width="2" stroke-dasharray="6,3"/>'
        f'{overlay_label}'
        f'</svg>'
    )


def detection_figure(summary: "DetectionSummary") -> Any:
    """Build a Plotly Figure for a detection (go.Image trace + bbox shape).

    Plan section 6.2 calls for this layout: a ``dcc.Graph`` consumer
    in the dashboard can plug straight in. Returns ``None`` if Plotly
    is unavailable (the inline-SVG renderer in ``_detection_image_svg``
    is the no-extra-deps fallback used by the HTML drawer).
    """
    if summary is None or not summary.crop_b64:
        return None
    try:
        import io
        import base64 as _b64
        import plotly.graph_objects as go
        from PIL import Image
    except ImportError:
        return None

    raw = _b64.b64decode(summary.crop_b64)
    img = Image.open(io.BytesIO(raw)).convert("RGB")
    cw, ch = img.size

    fig = go.Figure()
    fig.add_trace(go.Image(z=list(img.getdata()), dx=1, dy=1)
                  if False else go.Image(source=(
                      f"data:image/jpeg;base64,{summary.crop_b64}")))
    bx1, by1, bx2, by2 = summary.bbox_in_crop_px
    fig.add_shape(
        type="rect", x0=bx1, y0=by1, x1=bx2, y1=by2,
        line=dict(color="#ef4444", width=2, dash="dash"),
    )
    annotation = (
        f"{summary.label or '(unlabelled)'} "
        f"({summary.confidence:.2f}) — {int(summary.age_sec)}s ago"
    )
    fig.add_annotation(
        x=cw / 2, y=-12, xref="x", yref="y",
        showarrow=False, text=annotation,
        font=dict(color="#e2e8f0", size=11),
    )
    fig.update_layout(
        width=min(320, cw + 32), height=ch + 48,
        margin=dict(l=8, r=8, t=8, b=24),
        paper_bgcolor="#121a2e", plot_bgcolor="#000",
        xaxis=dict(visible=False, range=[0, cw]),
        yaxis=dict(visible=False, range=[ch, 0],
                   scaleanchor="x", scaleratio=1),
    )
    if summary.age_sec > DETECTION_STALE_AFTER_SEC:
        fig.add_annotation(
            x=cw / 2, y=ch / 2, xref="x", yref="y",
            text="STALE", showarrow=False,
            font=dict(color="#ef4444", size=22, family="monospace"),
        )
    return fig


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
