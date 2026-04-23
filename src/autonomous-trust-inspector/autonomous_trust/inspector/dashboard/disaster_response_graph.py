# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Trust-network panel: Plotly force-directed graph.

Built from the scenario's peer roster plus runtime state (bilateral
reputation scores, active stream counts, compromise/exclusion flags).
Sister component to disaster_response_map.py -- this one answers "who
trusts whom," where the map answers "who is where."

Why Plotly over D3?
    The existing viz/js/force.js is a live-WebSocket D3 system tightly
    bound to the simulator cohort. Reusing it for a scenario-driven demo
    would require rewiring both sides of the socket. Plotly's Scatter
    with custom layout reaches feature parity (weighted edges, color by
    group, size by metric) in ~150 lines and plugs straight into the
    Dash placeholder in dashboard layout.

Usage:
    g = TrustNetworkGraph(agency_colors={...})
    for name, role in scenario.peers.items():
        g.add_peer(name, role.agency, role.kind, role.join_phase)
    for src, tgt, score in bilateral_scores:
        g.set_trust(src, tgt, score)
    g.set_stream_count("fema-fusion", 5)
    g.mark_compromised("noaa-3")
    fig = g.figure()
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

import plotly.graph_objects as go


_DEFAULT_AGENCY_COLORS = {
    "NOAA": "#1f77b4",
    "USGS": "#8c564b",
    "FEMA": "#d62728",
    "EPA":  "#2ca02c",
}


# Trust -> color ramp. Green at high trust, yellow mid, red low.
def _trust_color(score: float) -> str:
    """Map a trust score in [0, 1] to a CSS color."""
    s = max(0.0, min(1.0, score))
    if s >= 0.7:
        # green -> yellow at 0.7-1.0
        return f"rgba(74, 222, 128, {0.4 + 0.5 * s:.3f})"
    if s >= 0.4:
        # yellow band
        return f"rgba(251, 191, 36, {0.4 + 0.5 * s:.3f})"
    # red band (low trust)
    return f"rgba(239, 68, 68, {0.4 + 0.4 * s:.3f})"


@dataclass
class _Node:
    name: str
    agency: str
    kind: str
    x: float = 0.0
    y: float = 0.0
    opacity: float = 1.0
    status: str = "active"       # "active" | "compromised" | "excluded"
    stream_count: int = 0        # drives node size


@dataclass
class _Edge:
    a: str
    b: str
    trust: float = 1.0            # 0..1
    active: bool = True


class TrustNetworkGraph:
    """Scenario-driven trust-network figure builder.

    Layout: agencies pinned at fixed angular sectors on a ring so the
    viewer can pattern-match agency clusters between runs. Within a
    sector, peers are spread evenly on a small arc. We don't use a true
    force-directed layout because:
      (a) jitter between updates distracts from the trust dynamics,
      (b) with 10 peers the pinned ring is legible without simulation.
    """

    RING_RADIUS = 1.0
    SUB_RADIUS = 0.25

    def __init__(self,
                 agency_colors: Optional[dict[str, str]] = None,
                 width: int = 480,
                 height: int = 420):
        self._colors = agency_colors or dict(_DEFAULT_AGENCY_COLORS)
        self._width = width
        self._height = height
        self._nodes: dict[str, _Node] = {}
        self._edges: dict[tuple[str, str], _Edge] = {}

    # ------------------------------------------------------------------
    # Builder API
    # ------------------------------------------------------------------

    def add_peer(self, name: str, agency: str, kind: str,
                 join_phase: int = 0):
        # Late joiners start hidden; callback layer ramps opacity.
        opacity = 0.0 if join_phase > 0 else 1.0
        self._nodes[name] = _Node(
            name=name, agency=agency, kind=kind, opacity=opacity,
        )

    def add_peer_from_role(self, name: str, role):
        """Convenience: accept a scenarios.scenario.PeerRole."""
        self.add_peer(name, role.agency, role.kind, role.join_phase)

    def _sorted_agencies(self) -> list[str]:
        # Stable agency order so angular positions don't jump between
        # renders as peers are added incrementally.
        return sorted({n.agency for n in self._nodes.values()})

    def _relayout(self):
        """Recompute node (x, y) coordinates."""
        agencies = self._sorted_agencies()
        n_agencies = max(1, len(agencies))
        for i, agency in enumerate(agencies):
            # Base angle for this agency's sector.
            theta = 2 * math.pi * i / n_agencies - math.pi / 2  # start at top
            cx = self.RING_RADIUS * math.cos(theta)
            cy = self.RING_RADIUS * math.sin(theta)
            peers = [n for n in self._nodes.values() if n.agency == agency]
            if len(peers) == 1:
                peers[0].x, peers[0].y = cx, cy
                continue
            # Spread peers on a small arc inside the sector. Arc spans
            # +/- pi/6 around the sector midline -- tight enough to read
            # as one cluster, loose enough that the nodes don't overlap.
            spread = math.pi / 6
            for j, peer in enumerate(sorted(peers, key=lambda p: p.name)):
                frac = (j - (len(peers) - 1) / 2) / max(1, len(peers) - 1)
                a = theta + spread * frac
                peer.x = cx + self.SUB_RADIUS * math.cos(a)
                peer.y = cy + self.SUB_RADIUS * math.sin(a)

    # ------------------------------------------------------------------
    # Runtime mutations (callback layer)
    # ------------------------------------------------------------------

    def set_opacity(self, name: str, opacity: float):
        if name in self._nodes:
            self._nodes[name].opacity = max(0.0, min(1.0, opacity))

    def set_stream_count(self, name: str, count: int):
        if name in self._nodes:
            self._nodes[name].stream_count = max(0, count)

    def mark_compromised(self, name: str):
        if name in self._nodes:
            self._nodes[name].status = "compromised"

    def mark_excluded(self, name: str):
        if name in self._nodes:
            self._nodes[name].status = "excluded"

    def reset_status(self, name: str):
        if name in self._nodes:
            self._nodes[name].status = "active"

    def set_trust(self, a: str, b: str, score: float):
        """Bilateral trust from a to b (or undirected; we store canonical)."""
        if a not in self._nodes or b not in self._nodes:
            return
        # Canonicalize so set_trust("a","b") and set_trust("b","a") share key.
        key = tuple(sorted((a, b)))
        self._edges[key] = _Edge(a=key[0], b=key[1], trust=max(0.0, min(1.0, score)))

    def clear_trust(self, a: str, b: str):
        key = tuple(sorted((a, b)))
        self._edges.pop(key, None)

    def deactivate_edges_for(self, name: str):
        """Called when a peer is excluded: mark its edges inactive."""
        for edge in self._edges.values():
            if edge.a == name or edge.b == name:
                edge.active = False

    # ------------------------------------------------------------------
    # Figure building
    # ------------------------------------------------------------------

    def _node_size(self, node: _Node) -> float:
        base = 16
        return base + 3 * min(node.stream_count, 10)

    def _node_color(self, node: _Node) -> str:
        if node.status == "excluded":
            return "#555"
        if node.status == "compromised":
            return "#ef4444"
        return self._colors.get(node.agency, "#888")

    def _edge_width(self, edge: _Edge) -> float:
        if not edge.active:
            return 0.5
        # 0.5 at trust=0 up to 5.0 at trust=1
        return 0.5 + 4.5 * edge.trust

    def _edge_color(self, edge: _Edge) -> str:
        # Inactive edges fade to very low opacity grey (cutoff visible).
        if not edge.active:
            return "rgba(148, 163, 184, 0.15)"
        na = self._nodes.get(edge.a)
        nb = self._nodes.get(edge.b)
        if ((na and na.status in ("compromised", "excluded"))
                or (nb and nb.status in ("compromised", "excluded"))):
            # Low-trust / compromised edges go red with the trust-based fade.
            return _trust_color(min(edge.trust, 0.3))
        return _trust_color(edge.trust)

    def figure(self) -> go.Figure:
        self._relayout()
        fig = go.Figure()

        # Edges first (drawn under nodes).
        for edge in self._edges.values():
            na = self._nodes.get(edge.a)
            nb = self._nodes.get(edge.b)
            if na is None or nb is None:
                continue
            # Hide edges to hidden peers (opacity 0).
            if na.opacity <= 0 or nb.opacity <= 0:
                continue
            fig.add_trace(go.Scatter(
                x=[na.x, nb.x],
                y=[na.y, nb.y],
                mode="lines",
                line=dict(color=self._edge_color(edge),
                          width=self._edge_width(edge)),
                hoverinfo="text",
                hovertext=(f"{edge.a} &harr; {edge.b}<br>"
                           f"trust: {edge.trust:.2f}"
                           f"{'' if edge.active else ' (inactive)'}"),
                showlegend=False,
            ))

        # Nodes: one trace per agency for legend cleanliness.
        per_agency: dict[str, list[_Node]] = {}
        for n in self._nodes.values():
            per_agency.setdefault(n.agency, []).append(n)

        for agency, nodes in sorted(per_agency.items()):
            fig.add_trace(go.Scatter(
                x=[n.x for n in nodes],
                y=[n.y for n in nodes],
                mode="markers+text",
                text=[n.name for n in nodes],
                textposition="bottom center",
                textfont=dict(size=10, color="#e2e8f0"),
                marker=dict(
                    size=[self._node_size(n) for n in nodes],
                    color=[self._node_color(n) for n in nodes],
                    opacity=[n.opacity for n in nodes],
                    line=dict(width=1.5,
                              color=self._colors.get(agency, "#888")),
                ),
                hovertext=[
                    f"<b>{n.name}</b><br>{n.agency} &middot; {n.kind}"
                    f"<br>streams: {n.stream_count}"
                    f"<br>status: {n.status}"
                    for n in nodes
                ],
                hoverinfo="text",
                name=agency,
            ))

        # Compromise pulse halo.
        pulse_nodes = [n for n in self._nodes.values()
                       if n.status == "compromised"]
        if pulse_nodes:
            fig.add_trace(go.Scatter(
                x=[n.x for n in pulse_nodes],
                y=[n.y for n in pulse_nodes],
                mode="markers",
                marker=dict(
                    color="#ef4444",
                    opacity=0.25,
                    size=[self._node_size(n) * 2.2 for n in pulse_nodes],
                    line=dict(width=0),
                ),
                hoverinfo="skip",
                showlegend=False,
                name="compromise-pulse-graph",
            ))

        fig.update_layout(
            width=self._width,
            height=self._height,
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="#121a2e",
            plot_bgcolor="#121a2e",
            xaxis=dict(visible=False, range=[-1.6, 1.6]),
            yaxis=dict(visible=False, range=[-1.6, 1.6],
                       scaleanchor="x", scaleratio=1),
            legend=dict(
                orientation="h",
                yanchor="bottom", y=-0.05,
                xanchor="center", x=0.5,
                bgcolor="rgba(18, 26, 46, 0.4)",
                font=dict(size=10, color="#e2e8f0"),
            ),
            showlegend=True,
        )
        return fig


# ----------------------------------------------------------------------
# One-shot builder
# ----------------------------------------------------------------------

def build_graph_from_scenario(scenario,
                              trust_matrix: Optional[list[tuple[str, str, float]]]
                                  = None,
                              stream_counts: Optional[dict[str, int]] = None,
                              compromised: Optional[set[str]] = None,
                              excluded: Optional[set[str]] = None,
                              peer_opacity: Optional[dict[str, float]] = None,
                              agency_colors: Optional[dict[str, str]] = None
                              ) -> go.Figure:
    """Build a complete trust-network figure from a scenario + state."""
    g = TrustNetworkGraph(agency_colors=agency_colors)
    for name, role in scenario.peers.items():
        g.add_peer_from_role(name, role)
        if peer_opacity and name in peer_opacity:
            g.set_opacity(name, peer_opacity[name])
    for name, n in (stream_counts or {}).items():
        g.set_stream_count(name, n)
    for a, b, score in (trust_matrix or ()):
        g.set_trust(a, b, score)
    for name in (compromised or ()):
        g.mark_compromised(name)
    for name in (excluded or ()):
        g.mark_excluded(name)
        g.deactivate_edges_for(name)
    return g.figure()
