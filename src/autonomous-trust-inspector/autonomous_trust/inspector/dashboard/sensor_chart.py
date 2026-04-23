"""
Sensor comparison chart — reusable across demos.

Overlays readings from multiple peers of the same data type on one
chart so divergence is visually obvious.  This is the "money shot"
panel: when the compromised sensor starts deviating, its line visually
separates from the honest sensors.

Features:
  - Multi-peer overlay with per-peer coloring
  - Anomaly shading (red background when divergence detected)
  - Optional consensus band (gray fill between min/max of honest sensors)
  - Scrolling time window (configurable, default 120s)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Optional

import plotly.graph_objects as go

from autonomous_trust.services.data import Reading


@dataclass
class _PeerTrace:
    """Internal: buffered readings for one peer."""
    times: deque       # float seconds
    values: deque      # float readings
    color: str
    anomalous_since: Optional[float] = None  # t when flagged


class SensorComparisonChart:
    """Builds a Plotly figure comparing sensor readings across peers.

    Usage:
        chart = SensorComparisonChart(
            data_type="temperature",
            unit="C",
            peer_colors={"noaa-sensor-1": "#1E90FF", ...},
            window_sec=120,
        )
        # In tick loop:
        chart.add_reading(reading)
        chart.mark_anomalous("noaa-sensor-3", t=240.0)
        fig = chart.figure()
    """

    def __init__(self, data_type: str, unit: str,
                 peer_colors: dict[str, str],
                 window_sec: float = 120.0,
                 title: Optional[str] = None):
        self._data_type = data_type
        self._unit = unit
        self._peer_colors = peer_colors
        self._window_sec = window_sec
        self._title = title or f"{data_type.replace('_', ' ').title()} Comparison"
        self._traces: dict[str, _PeerTrace] = {}
        self._max_points = int(window_sec / 5) * 2  # generous buffer

    def add_reading(self, reading: Reading):
        """Add a reading from any peer."""
        if reading.data_type != self._data_type:
            return

        name = reading.peer_name
        if name not in self._traces:
            self._traces[name] = _PeerTrace(
                times=deque(maxlen=self._max_points),
                values=deque(maxlen=self._max_points),
                color=self._peer_colors.get(name, "#888"),
            )

        trace = self._traces[name]
        trace.times.append(reading.timestamp.total_seconds())
        trace.values.append(reading.value)

    def mark_anomalous(self, peer_name: str, t: float):
        """Mark a peer as anomalous starting at time t."""
        if peer_name in self._traces:
            self._traces[peer_name].anomalous_since = t

    def figure(self, width: int = 900, height: int = 300) -> go.Figure:
        """Build the Plotly figure."""
        fig_width, fig_height = width, height
        fig = go.Figure()

        # Determine current time window
        all_t = [t for tr in self._traces.values() for t in tr.times]
        if not all_t:
            fig.update_layout(title=self._title, template="plotly_dark")
            return fig

        t_max = max(all_t)
        t_min = max(0, t_max - self._window_sec)

        # Consensus band: fill between min and max of non-anomalous peers
        honest_peers = [
            name for name, tr in self._traces.items()
            if tr.anomalous_since is None
        ]
        if len(honest_peers) >= 2:
            # Collect aligned time points from honest peers
            time_set = sorted(set(
                t for name in honest_peers
                for t in self._traces[name].times
                if t >= t_min
            ))
            if time_set:
                mins, maxs = [], []
                for t in time_set:
                    vals = []
                    for name in honest_peers:
                        tr = self._traces[name]
                        # Find closest value to this time
                        for i, tt in enumerate(tr.times):
                            if abs(tt - t) < 6:  # within one cadence
                                vals.append(tr.values[i])
                                break
                    if vals:
                        mins.append(min(vals))
                        maxs.append(max(vals))
                    else:
                        mins.append(None)
                        maxs.append(None)

                fig.add_trace(go.Scatter(
                    x=list(time_set), y=maxs,
                    mode="lines", line=dict(width=0),
                    showlegend=False,
                ))
                fig.add_trace(go.Scatter(
                    x=list(time_set), y=mins,
                    mode="lines", line=dict(width=0),
                    fill="tonexty",
                    fillcolor="rgba(100,200,100,0.15)",
                    name="Consensus Band",
                    showlegend=True,
                ))

        # Per-peer traces
        for name, trace in sorted(self._traces.items()):
            ts = [t for t in trace.times if t >= t_min]
            vs = [v for t, v in zip(trace.times, trace.values) if t >= t_min]

            dash = "solid"
            line_width = 2
            if trace.anomalous_since is not None:
                dash = "dash"
                line_width = 3

            fig.add_trace(go.Scatter(
                x=ts, y=vs,
                mode="lines",
                name=name,
                line=dict(color=trace.color, width=line_width, dash=dash),
            ))

        # Anomaly shading
        for name, trace in self._traces.items():
            if trace.anomalous_since is not None:
                fig.add_vrect(
                    x0=trace.anomalous_since, x1=t_max,
                    fillcolor="rgba(239,68,68,0.1)",
                    line_width=0,
                    annotation_text="Anomaly Detected",
                    annotation_position="top left",
                    annotation_font_color="#EF4444",
                    annotation_font_size=10,
                )
                break  # only one shading region

        fig.update_layout(
            title=dict(text=self._title, font=dict(size=14)),
            xaxis_title="Time (seconds)",
            xaxis=dict(range=[t_min, t_max]),
            yaxis_title=f"{self._data_type.replace('_', ' ').title()} ({self._unit})",
            template="plotly_dark",
            width=fig_width,
            height=fig_height,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.35,
                xanchor="center",
                x=0.5,
                font=dict(size=9),
            ),
            margin=dict(l=50, r=20, t=40, b=80),
        )

        return fig
