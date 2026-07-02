# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

"""
Data streams panel — reusable across demos.

Shows a live summary of active data feeds: which peers are providing
what data, at what rate, with quality indicators.  Designed as a
compact status table, not a full chart.

Renders as HTML for embedding in Dash layouts.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from dash_extensions.enrich import html

from autonomous_trust.services.data import Reading


@dataclass
class StreamStatus:
    """Status of a single data stream from a peer."""
    peer_name: str
    data_type: str
    last_value: float
    unit: str
    last_t: float         # scenario seconds
    reading_count: int
    avg_quality: float
    active: bool = True

    @property
    def rate_str(self) -> str:
        if self.reading_count < 2:
            return "--"
        return f"{self.reading_count}"

    @property
    def quality_color(self) -> str:
        if self.avg_quality >= 0.9:
            return "#4ADE80"   # green
        if self.avg_quality >= 0.7:
            return "#FBBF24"   # yellow
        return "#EF4444"       # red


class DataStreamsPanel:
    """Tracks active data streams and renders a status table.

    Usage:
        panel = DataStreamsPanel(peer_colors={...})
        # In tick loop:
        panel.update(reading)
        html = panel.to_html()
    """

    def __init__(self, peer_colors: dict[str, str]):
        self._peer_colors = peer_colors
        self._streams: dict[tuple[str, str], StreamStatus] = {}
        self._quality_sums: dict[tuple[str, str], float] = defaultdict(float)

    def update(self, reading: Reading):
        """Update stream status from a new reading."""
        key = (reading.peer_name, reading.data_type)

        if key not in self._streams:
            self._streams[key] = StreamStatus(
                peer_name=reading.peer_name,
                data_type=reading.data_type,
                last_value=reading.value,
                unit=reading.unit,
                last_t=reading.timestamp.total_seconds(),
                reading_count=0,
                avg_quality=reading.quality,
            )

        s = self._streams[key]
        s.last_value = reading.value
        s.last_t = reading.timestamp.total_seconds()
        s.reading_count += 1
        self._quality_sums[key] += reading.quality
        s.avg_quality = self._quality_sums[key] / s.reading_count

    def mark_inactive(self, peer_name: str):
        """Mark all streams from a peer as inactive (e.g. after exclusion)."""
        for key, s in self._streams.items():
            if s.peer_name == peer_name:
                s.active = False

    @property
    def active_count(self) -> int:
        return sum(1 for s in self._streams.values() if s.active)

    def to_dash_children(self) -> list:
        """Render as Dash html children, suitable for setting on an
        ``Output(..., 'children')``.  The caller is expected to provide
        the outer scrollable Div (with ``overflowY:auto`` + the rest of
        the panel styling) so that re-rendering this method's output
        replaces only the *inner* table — Dash patches children in
        place rather than recreating the DOM node, which preserves the
        user's scroll position across the ``dcc.Interval`` cadence.
        """
        rows = []
        for key in sorted(self._streams.keys()):
            s = self._streams[key]
            peer_color = self._peer_colors.get(s.peer_name, "#888")
            opacity = "1.0" if s.active else "0.4"
            strike = "line-through" if not s.active else "none"
            rows.append(html.Tr(
                style={"opacity": opacity, "textDecoration": strike},
                children=[
                    html.Td(s.peer_name, style={"color": peer_color}),
                    html.Td(s.data_type),
                    html.Td(f"{s.last_value:.1f} {s.unit}",
                            style={"textAlign": "right"}),
                    html.Td(s.rate_str, style={"textAlign": "right"}),
                    html.Td(f"{s.avg_quality:.0%}",
                            style={"textAlign": "center",
                                   "color": s.quality_color}),
                ],
            ))
        header = html.Tr(
            style={"color": "#94A3B8", "fontSize": "10px",
                   "borderBottom": "1px solid #334155"},
            children=[
                html.Th("Peer",    style={"textAlign": "left"}),
                html.Th("Type",    style={"textAlign": "left"}),
                html.Th("Latest",  style={"textAlign": "right"}),
                html.Th("Count",   style={"textAlign": "right"}),
                html.Th("Quality", style={"textAlign": "center"}),
            ],
        )
        return [
            html.Div(f"Active Streams: {self.active_count}",
                     style={"color": "#94A3B8", "fontSize": "10px",
                            "marginBottom": "4px"}),
            html.Table(
                style={"width": "100%", "borderCollapse": "collapse"},
                children=[html.Tbody([header] + rows)],
            ),
        ]

    def to_html(self, height: str = "250px") -> str:
        """Render as a scrollable HTML table."""
        rows = []
        for key in sorted(self._streams.keys()):
            s = self._streams[key]
            peer_color = self._peer_colors.get(s.peer_name, "#888")
            opacity = "1.0" if s.active else "0.4"
            strike = "line-through" if not s.active else "none"

            rows.append(
                f'<tr style="opacity:{opacity};text-decoration:{strike}">'
                f'<td style="color:{peer_color}">{s.peer_name}</td>'
                f'<td>{s.data_type}</td>'
                f'<td style="text-align:right">{s.last_value:.1f} {s.unit}</td>'
                f'<td style="text-align:right">{s.rate_str}</td>'
                f'<td style="text-align:center;color:{s.quality_color}">'
                f'{s.avg_quality:.0%}</td>'
                f'</tr>'
            )

        header = (
            '<tr style="color:#94A3B8;font-size:10px;border-bottom:1px solid #334155">'
            '<th style="text-align:left">Peer</th>'
            '<th style="text-align:left">Type</th>'
            '<th style="text-align:right">Latest</th>'
            '<th style="text-align:right">Count</th>'
            '<th style="text-align:center">Quality</th>'
            '</tr>'
        )

        return (
            f'<div style="height:{height};overflow-y:auto;'
            f'background:#1E1E2E;padding:8px;border-radius:6px;'
            f'font-size:11px;font-family:monospace">'
            f'<div style="color:#94A3B8;font-size:10px;margin-bottom:4px">'
            f'Active Streams: {self.active_count}</div>'
            f'<table style="width:100%;border-collapse:collapse">'
            f'{header}'
            f'{"".join(rows)}'
            f'</table>'
            f'</div>'
        )
