"""
Trust dynamics timeline panel — reusable across demos.

Shows per-peer reputation over time as a multi-line chart with:
  - One line per peer, colored by agency/role
  - Phase markers (vertical dashed lines with labels)
  - Compromise detection annotations
  - Reputation threshold line (horizontal dashed at 0.5)

Extends the inspector's DashComponent pattern.  Can run standalone
(for development) or be registered into the inspector's Dash app.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Optional

import plotly.graph_objects as go
from plotly.subplots import make_subplots


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
                 threshold: float = 0.5,
                 title: str = "Trust Dynamics"):
        self._peer_colors = peer_colors
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

        fig.add_trace(go.Scatter(
            x=[0, t_max],
            y=[self._threshold, self._threshold],
            mode="lines",
            line=dict(color="#FF4444", width=1, dash="dot"),
            name="Exclusion Threshold",
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

        fig.update_layout(
            title=dict(text=self._title, font=dict(size=14)),
            xaxis_title="Time (seconds)",
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
            ),
            margin=dict(l=50, r=20, t=40, b=80),
        )

        return fig
