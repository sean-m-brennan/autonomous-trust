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
Trust dynamics timeline panel — reusable across demos.

Shows per-peer reputation over time as a multi-line chart with:
  - One line per peer, colored by agency/role
  - Phase markers (vertical dashed lines with labels)
  - Compromise detection annotations
  - Communication cut-off line (horizontal dotted at 0.1) with a shaded
    exclusion band beneath, plus a faint tier-1 trust-floor reference (0.5)

Extends the inspector's DashComponent pattern.  Can run standalone
(for development) or be registered into the inspector's Dash app.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Optional

import plotly.graph_objects as go
from plotly.subplots import make_subplots


# Communication cut-off (default 0.1), kept in sync with the reputation
# backend via the shared AT_REP_COMM_CUTOFF override so the dashboard
# cut-off line matches a re-adjusted deployment.
try:
    _DEFAULT_CUTOFF = float(os.environ.get('AT_REP_COMM_CUTOFF', '') or 0.1)
except (TypeError, ValueError):
    _DEFAULT_CUTOFF = 0.1


@dataclass
class ReputationSample:
    """A single reputation measurement."""
    t: float             # scenario seconds
    peer_name: str
    score: float         # 0.0 - 1.0


@dataclass
class PhaseMarker:
    """A vertical marker on the timeline."""
    t: float             # scenario seconds
    label: str
    color: str = "#666"
    dash: str = "dash"   # plotly line dash style


def _time_ticks(t_max):
    """Clean ``m:ss`` x-axis ticks spanning ``[0, t_max]`` seconds.

    Picks the smallest "nice" interval that yields at most ~10 ticks so the
    labels stay legible as the live timeline grows. Returns
    ``(tickvals_seconds, ticktext_mmss)``. Pure."""
    span = max(float(t_max), 1.0)
    step = 3600
    for candidate in (10, 15, 30, 60, 120, 300, 600, 900, 1800):
        if span / candidate <= 10:
            step = candidate
            break
    vals = list(range(0, int(span) + 1, step)) or [0]
    text = ["%d:%02d" % (int(v) // 60, int(v) % 60) for v in vals]
    return vals, text


class TrustTimeline:
    """Builds and updates a Plotly figure showing reputation over time.

    Usage:
        tl = TrustTimeline(peer_colors={"noaa-sensor-1": "#1E90FF", ...})
        tl.add_phase_marker(0, "Formation")
        tl.add_phase_marker(60, "Bootstrap")
        ...
        # In the tick loop:
        tl.add_sample(ReputationSample(t=42.0, peer_name="noaa-sensor-1", score=0.72))
        fig = tl.figure()  # returns a Plotly Figure
    """

    def __init__(self, peer_colors: dict[str, str],
                 threshold: float = _DEFAULT_CUTOFF,
                 title: str = "Trust Dynamics"):
        self._peer_colors = peer_colors
        # Communication cut-off (reputation scale is [0, 1]): a peer whose
        # reputation falls below this is EXCLUDED from the network. Drawn
        # as a red dotted line with a shaded exclusion band beneath it. The
        # tier-1 trust floor (0.5) is drawn as a faint reference above it.
        self._threshold = threshold
        self._title = title
        self._samples: dict[str, list[ReputationSample]] = {}
        self._phase_markers: list[PhaseMarker] = []

    def add_sample(self, sample: ReputationSample):
        """Add a reputation sample for a peer."""
        if sample.peer_name not in self._samples:
            self._samples[sample.peer_name] = []
        self._samples[sample.peer_name].append(sample)

    def add_phase_marker(self, t_seconds: float, label: str,
                         color: str = "#666"):
        """Add a vertical phase marker."""
        self._phase_markers.append(PhaseMarker(
            t=t_seconds, label=label, color=color,
        ))

    def figure(self, width: int = 900, height: int = 350) -> go.Figure:
        """Build the Plotly figure from current data."""
        fig = go.Figure()

        # Reputation threshold line
        if self._samples:
            all_t = [s.t for samples in self._samples.values() for s in samples]
            t_max = max(all_t) if all_t else 480
        else:
            t_max = 480

        # Shaded exclusion band beneath the communication cut-off: any peer
        # whose line dips into this region is excluded from the network.
        fig.add_hrect(
            y0=0, y1=self._threshold,
            fillcolor="rgba(255, 68, 68, 0.10)",
            line_width=0, layer="below",
        )
        # Faint tier-1 trust-floor reference (0.5): elevated-trust tasking
        # requires a peer above this. Reference only, not a cut-off.
        fig.add_trace(go.Scatter(
            x=[0, t_max],
            y=[0.5, 0.5],
            mode="lines",
            line=dict(color="rgba(148, 163, 184, 0.5)", width=1, dash="dash"),
            name="Trust tier-1 (0.5)",
            showlegend=True,
        ))
        # Communication cut-off line: below this a peer is excluded.
        fig.add_trace(go.Scatter(
            x=[0, t_max],
            y=[self._threshold, self._threshold],
            mode="lines",
            line=dict(color="#FF4444", width=1, dash="dot"),
            name="Comm cut-off (%g)" % self._threshold,
            showlegend=True,
        ))

        # Per-peer reputation lines
        for peer_name, samples in sorted(self._samples.items()):
            color = self._peer_colors.get(peer_name, "#888")
            ts = [s.t for s in samples]
            scores = [s.score for s in samples]
            fig.add_trace(go.Scatter(
                x=ts, y=scores,
                mode="lines",
                name=peer_name,
                line=dict(color=color, width=2),
            ))

        # Phase markers
        for marker in self._phase_markers:
            fig.add_vline(
                x=marker.t, line_dash=marker.dash,
                line_color=marker.color, line_width=1,
                annotation_text=marker.label,
                annotation_position="top",
                annotation_font_size=10,
                annotation_font_color=marker.color,
            )

        # Explicit m:ss time ticks + vertical gridlines so a reader can drop a
        # line from any feature (e.g. a sawtooth) straight to a readable time.
        # x is elapsed seconds since tasking_start (see ReputationSample.t).
        xtickvals, xticktext = _time_ticks(t_max)

        fig.update_layout(
            title=dict(text=self._title, font=dict(size=14)),
            xaxis=dict(
                title="Time (m:ss)",
                tickvals=xtickvals,
                ticktext=xticktext,
                showgrid=True,
                gridcolor="rgba(148, 163, 184, 0.18)",
                range=[0, t_max] if self._samples else None,
            ),
            yaxis_title="Reputation",
            yaxis=dict(range=[0, 1.05]),
            template="plotly_dark",
            width=width,
            height=height,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.3,
                xanchor="center",
                x=0.5,
                font=dict(size=9),
                # Transparent so it doesn't paint over the m:ss x-axis tick
                # labels it sits on top of (legend is anchored below the plot).
                bgcolor="rgba(0, 0, 0, 0)",
                bordercolor="rgba(0, 0, 0, 0)",
                borderwidth=0,
            ),
            margin=dict(l=50, r=20, t=40, b=80),
        )

        return fig
