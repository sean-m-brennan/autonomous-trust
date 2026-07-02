# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

import networkx as nx
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

    Layout: an *agency-anchored hybrid* force-directed layout. Each agency
    owns a fixed 'home' anchor on a ring (so clusters stay recognizable and
    stable between runs), and then a spring simulation lays the peers out:
      - every peer is spring-tethered to its agency's anchor (soft
        clustering — keeps the sector recognizable),
      - every trust edge is a spring whose strength scales with reputation,
        so high-trust pairs pull *closer* (and low-trust / compromised peers,
        held only by weak springs, get pushed toward the periphery by the
        repulsion below),
      - all nodes repel one another, spreading the bunching apart.

    The solve is warm-started from the previous frame's positions and run
    for only a few iterations per tick (see WARM_ITERS), so the graph glides
    smoothly as reputation shifts instead of jittering — which is why a live
    per-tick panel should hold ONE persistent instance and call
    apply_scenario_state()/figure() each frame (see TrustNetworkPanel) rather
    than rebuilding via the one-shot build_graph_from_scenario().
    """

    RING_RADIUS = 1.0
    SUB_RADIUS = 0.6
    # --- Agency-anchored hybrid force layout tuning ---------------------
    SPRING_K = 0.55           # target node separation; larger => more spread
    ANCHOR_WEIGHT = 1.2       # spring pulling a peer to its agency home sector
    TRUST_WEIGHT_BASE = 0.15  # floor attraction present on any trust edge
    TRUST_WEIGHT_SCALE = 1.9  # reputation-scaled pull (high trust => stronger)
    WARM_ITERS = 8            # relaxation steps/frame when warm-started (smooth)
    COLD_ITERS = 60           # steps for the first, cold solve
    LAYOUT_SEED = 42          # deterministic placement (no per-frame RNG jitter)
    # spring_layout re-heats its cooling temperature on every call, so even on
    # unchanged input the raw solve wiggles ~0.1/frame. Low-pass the write-back
    # (glide a fraction of the way to the solved point) and freeze motion below
    # a deadband, so the graph animates on real reputation changes but goes
    # still once settled.
    LAYOUT_EASE = 0.45        # fraction of the solved step to apply per frame
    SETTLE_DEADBAND = 0.12    # skip sub-threshold moves (kills residual wiggle)

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

    def _agency_anchors(self) -> dict[str, tuple[float, float]]:
        """Fixed 'home sector' point per agency, evenly spaced on the ring."""
        agencies = self._sorted_agencies()
        n_agencies = max(1, len(agencies))
        anchors = {}
        for i, agency in enumerate(agencies):
            theta = 2 * math.pi * i / n_agencies - math.pi / 2  # start at top
            anchors[agency] = (self.RING_RADIUS * math.cos(theta),
                               self.RING_RADIUS * math.sin(theta))
        return anchors

    def _relayout(self):
        """Recompute node (x, y) via the agency-anchored force layout.

        Warm-starts from the current node coordinates when they exist (the
        previous frame), so the graph relaxes smoothly rather than jumping;
        a fresh graph (all coords still 0) instead seeds each peer near its
        agency anchor with a deterministic offset and solves cold.
        """
        peers = list(self._nodes.values())
        if not peers:
            return
        anchors = self._agency_anchors()

        g = nx.Graph()
        # Anchor nodes are pinned; each peer is spring-tethered to its
        # agency's anchor (soft clustering).
        for agency in anchors:
            g.add_node(("anchor", agency))
        for n in peers:
            g.add_node(n.name)
            g.add_edge(n.name, ("anchor", n.agency), weight=self.ANCHOR_WEIGHT)
        # Reputation springs: higher trust => larger weight => stronger pull.
        for edge in self._edges.values():
            if edge.a in self._nodes and edge.b in self._nodes:
                w = self.TRUST_WEIGHT_BASE + self.TRUST_WEIGHT_SCALE * edge.trust
                g.add_edge(edge.a, edge.b, weight=w)

        # Initial positions: anchors fixed at their ring points; peers
        # warm-start from their current coords, else seed near the anchor.
        init_pos = {("anchor", a): p for a, p in anchors.items()}
        warm = False
        for idx, n in enumerate(peers):
            if n.x != 0.0 or n.y != 0.0:
                init_pos[n.name] = (n.x, n.y)
                warm = True
            else:
                ax, ay = anchors[n.agency]
                ang = 2 * math.pi * idx / max(1, len(peers))
                init_pos[n.name] = (ax + 0.25 * math.cos(ang),
                                    ay + 0.25 * math.sin(ang))

        pos = nx.spring_layout(
            g,
            pos=init_pos,
            fixed=[("anchor", a) for a in anchors],
            weight="weight",
            k=self.SPRING_K,
            iterations=self.WARM_ITERS if warm else self.COLD_ITERS,
            seed=self.LAYOUT_SEED,
        )
        for n in peers:
            sx, sy = pos[n.name]
            if n.x == 0.0 and n.y == 0.0:
                # First placement (cold solve, or a freshly-added late joiner):
                # snap to the solved point rather than gliding in from origin.
                n.x, n.y = float(sx), float(sy)
                continue
            dx, dy = float(sx) - n.x, float(sy) - n.y
            if math.hypot(dx, dy) < self.SETTLE_DEADBAND:
                continue  # settled — hold still (no perpetual wiggle)
            n.x += self.LAYOUT_EASE * dx
            n.y += self.LAYOUT_EASE * dy

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

    def apply_scenario_state(self, scenario,
                             trust_matrix: Optional[list] = None,
                             stream_counts: Optional[dict[str, int]] = None,
                             compromised: Optional[set[str]] = None,
                             excluded: Optional[set[str]] = None,
                             peer_opacity: Optional[dict[str, float]] = None):
        """(Re)apply a full scenario + runtime snapshot in place.

        Idempotent across frames: peers are *upserted* so their laid-out
        positions survive (that's what lets the layout warm-start and glide),
        while edges and status are rebuilt from the snapshot each call. This
        is the per-tick entry point for a persistent panel; the one-shot
        build_graph_from_scenario() calls it once on a fresh instance.
        """
        for name, role in scenario.peers.items():
            if name not in self._nodes:
                self.add_peer_from_role(name, role)
        for name, op in (peer_opacity or {}).items():
            self.set_opacity(name, op)
        for name, cnt in (stream_counts or {}).items():
            self.set_stream_count(name, cnt)
        # Trust edges live only on _edges (positions are on nodes), so it's
        # safe to rebuild the edge set from scratch each frame.
        self._edges.clear()
        for a, b, score in (trust_matrix or ()):
            self.set_trust(a, b, score)
        # Status is monotonic in the demo, but reset+re-mark keeps us correct
        # if a snapshot ever clears a flag.
        for node in self._nodes.values():
            node.status = "active"
        for name in (compromised or ()):
            self.mark_compromised(name)
        for name in (excluded or ()):
            self.mark_excluded(name)
            self.deactivate_edges_for(name)

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
            # A touch wider than the RING_RADIUS=1.0 anchors so peers that
            # the repulsion / reputation forces push outward stay in frame.
            xaxis=dict(visible=False, range=[-2.0, 2.0]),
            yaxis=dict(visible=False, range=[-2.0, 2.0],
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
    """Build a complete trust-network figure from a scenario + state.

    One-shot: a fresh graph each call, so the force layout solves *cold*
    (still deterministic via LAYOUT_SEED). A live per-tick panel that wants
    smooth, warm-started motion should instead hold one persistent
    TrustNetworkGraph and call apply_scenario_state()/figure() each frame —
    see TrustNetworkPanel.
    """
    g = TrustNetworkGraph(agency_colors=agency_colors)
    g.apply_scenario_state(
        scenario,
        trust_matrix=trust_matrix,
        stream_counts=stream_counts,
        compromised=compromised,
        excluded=excluded,
        peer_opacity=peer_opacity,
    )
    return g.figure()
