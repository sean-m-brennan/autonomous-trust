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
import os
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


# Trust -> color ramp on the [0, 1] scale. Green at high trust, yellow
# mid, red low, and a distinct dark red below the communication cut-off
# (default 0.1) so an excluded peer reads differently from merely
# low-trust. Kept in sync with the reputation backend via the shared
# AT_REP_COMM_CUTOFF override.
try:
    _COMM_CUTOFF = float(os.environ.get('AT_REP_COMM_CUTOFF', '') or 0.1)
except (TypeError, ValueError):
    _COMM_CUTOFF = 0.1


def _trust_color(score: float) -> str:
    """Map a trust score in [0, 1] to a CSS color."""
    s = max(0.0, min(1.0, score))
    if s >= 0.7:
        # green -> yellow at 0.7-1.0
        return f"rgba(74, 222, 128, {0.4 + 0.5 * s:.3f})"
    if s >= 0.4:
        # yellow band
        return f"rgba(251, 191, 36, {0.4 + 0.5 * s:.3f})"
    if s >= _COMM_CUTOFF:
        # red band (low but still participating)
        return f"rgba(239, 68, 68, {0.4 + 0.4 * s:.3f})"
    # below the communication cut-off: excluded — deep, opaque crimson
    # distinct from the merely-low red band above.
    return "rgba(136, 19, 55, 0.95)"


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
    # The figure autoscales its viewport to the solved bounding box (see
    # figure()), so absolute scale no longer matters -- only the *relative*
    # spread. These are tuned for legibility: nodes separate cleanly, agency
    # clusters stay cohesive, and higher-trust pairs sit visibly closer.
    # Repulsion-dominant: a dense high-trust roster (e.g. a hub trusted by
    # everyone) otherwise collapses inward and reads as a tight blob. Keep the
    # attractions weak enough that trust still ORDERS distances (high-trust
    # visibly closer) without COLLAPSING them, and let repulsion spread the
    # nodes. Tuned against the normalized display (see _display_coords): with
    # these, the closest node pair sits ~80px apart in a 480x420 panel (markers
    # are ~16-46px) instead of crowding, while agencies stay visibly grouped.
    SPRING_K = 1.2            # target node separation; larger => more spread
    # The agency anchor must only BIAS the sector, not PIN distance: when it
    # was on the same scale as the trust springs (0.40 vs a 0.03..0.48 trust
    # weight) it dominated placement across the whole sub-0.5 band, so node
    # distance tracked agency membership and trust (hence edge color) barely
    # moved anything. Keeping the anchor an order of magnitude weaker than the
    # top trust weight lets trust ORDER the inter-peer distances (validated:
    # ~1.9x spread, monotonic in a multi-peer roster) while the anchor still
    # clusters each agency into its home sector.
    ANCHOR_WEIGHT = 0.06      # weak: biases agency sector, does NOT pin distance
    TRUST_WEIGHT_BASE = 0.02  # floor attraction present on any trust edge
    TRUST_WEIGHT_SCALE = 0.70 # reputation-scaled pull (high trust => stronger)
    EDGE_TRUST_EPS = 1e-9     # trust <= this is "no relationship" => no edge
                              # drawn and no spring (cold-start 0.0 lands here)
    WARM_ITERS = 60           # relaxation steps/frame when warm-started; enough
                              # to reach the same equilibrium each frame so a
                              # settled graph is bit-identical (zero jitter) --
                              # spring_layout re-heats its temperature per call
                              # and the wider spread from SPRING_K amplifies the
                              # wiggle, so a short solve never fully converges.
    COLD_ITERS = 60           # steps for the first, cold solve
    LAYOUT_SEED = 42          # deterministic placement (no per-frame RNG jitter)
    # spring_layout re-heats its cooling temperature on every call, so even on
    # unchanged input the raw solve wiggles ~0.1/frame. Low-pass the write-back
    # (glide a fraction of the way to the solved point) and freeze motion below
    # a deadband, so the graph animates on real reputation changes but goes
    # still once settled.
    LAYOUT_EASE = 0.45        # fraction of the solved step to apply per frame
    SETTLE_DEADBAND = 0.12    # skip sub-threshold moves (kills residual wiggle)
    # --- Viewport ------------------------------------------------------
    # Rather than autoscaling the *axis range* to the node cloud (which a
    # live panel's constant `uirevision` would preserve-and-discard, so the
    # frame would never re-fit), we NORMALIZE the rendered coordinates into a
    # fixed box and keep a fixed axis range. Visually identical -- the cloud
    # always fills the panel instead of swimming in a too-big box (marker
    # sizes are in pixels, so a tight fit de-crowds the nodes) -- but
    # uirevision-safe because the range is constant. Node motion is
    # deadband-frozen at steady state, so the normalization is stable at rest
    # and only re-fits during real transitions.
    DISPLAY_HALFSPAN = 1.0    # normalized cloud half-span (maps bbox -> +/-1)
    DISPLAY_MIN_FILL = 0.5    # re-fit scale only if the cloud shrinks below
                              # this fraction of the box (else hold, so trust
                              # changes move nodes instead of rescaling all)
    DISPLAY_REFIT_EASE = 0.25 # glide factor when a re-fit is warranted
    NORMALIZE_FLOOR = 0.35    # floor on raw half-span so a sparse graph (few
                              # near-coincident nodes) doesn't blow up in scale
    VIEW_MARGIN = 1.32        # axis padding around the normalized cloud: leaves
                              # an outer band for the barely-beyond disconnected
                              # nodes AND room for wide labels at the cloud edge
    # A node with NO trust edges is held only by its (weak) agency-anchor
    # spring, so repulsion flings it far out -- which, if it defined the
    # normalization bbox, would crush the connected core into a clump. Instead
    # we normalize to the CONNECTED nodes and pull each disconnected node in to
    # sit just barely beyond the furthest connected node.
    DISCONNECTED_OUTER = 1.12  # disconnected radius cap, x the connected extent

    def __init__(self,
                 agency_colors: Optional[dict[str, str]] = None,
                 peer_colors: Optional[dict[str, str]] = None,
                 width: int = 480,
                 height: int = 420):
        self._colors = agency_colors or dict(_DEFAULT_AGENCY_COLORS)
        # Per-peer color overrides (keyed by node name). Needed where peers in
        # the same agency carry different role colors -- e.g. the DoD roster,
        # whose ODA agency holds both green squad nodes and cyan microdrones,
        # so coloring by agency alone would render them identically. Takes
        # precedence over the agency color in _node_color().
        self._peer_colors = dict(peer_colors or {})
        self._width = width
        self._height = height
        self._nodes: dict[str, _Node] = {}
        self._edges: dict[tuple[str, str], _Edge] = {}
        # Layout convergence gate. nx.spring_layout re-heats its temperature on
        # every call, so re-solving each frame makes the (weak-anchor) cloud
        # wander forever -- which the display normalization then has to mask,
        # hiding real trust-driven movement along with the wander. Instead we
        # solve ONLY while the trust/topology inputs differ from the last
        # converged solve (or the glide toward them is still in progress), and
        # hold perfectly still once settled. A trust change flips the signature
        # and re-arms the solve, so nodes visibly move when (and only when) the
        # forces actually change.
        self._layout_sig = None
        self._settled = False
        # Display-transform scale is held stable across trust changes (re-fit
        # only when the connected set changes or the cloud spills the box) so a
        # force change actually moves the affected nodes on screen instead of
        # being normalized away. See _display_coords.
        self._disp_scale = None
        self._disp_topo = None

    def _layout_signature(self):
        """Hashable snapshot of everything the force solve depends on: each
        edge's endpoints + trust (rounded so float dust doesn't re-trigger)
        and each node's agency (drives its anchor). Opacity/status are excluded
        -- they change color, not position."""
        edges = frozenset((e.a, e.b, round(e.trust, 3))
                          for e in self._edges.values())
        nodes = frozenset((n.name, n.agency) for n in self._nodes.values())
        return (edges, nodes)

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
        all_peers = list(self._nodes.values())
        if not all_peers:
            return
        # Convergence gate: skip the solve entirely while the forces are
        # unchanged and we've already settled, so a settled graph holds
        # perfectly still (no re-heat wander) and only real trust/topology
        # changes move nodes. A changed signature re-arms the glide.
        sig = self._layout_signature()
        if sig != self._layout_sig:
            self._layout_sig = sig
            self._settled = False
        elif self._settled:
            return
        anchors = self._agency_anchors()

        # Only edge-bearing peers take part in the force solve. An edge-less
        # peer is held only by a weak anchor spring, so repulsion would fling
        # it far out AND leave it wandering (no trust edge pins its angle) --
        # which both distorts the frame and perturbs the others so nothing
        # settles. We drop those from the solve and place them deterministically
        # in _display_coords (just beyond the connected cloud). Fall back to
        # solving everyone when almost nothing is connected yet (pre-trust).
        linked = set()
        for edge in self._edges.values():
            if not self._is_layout_edge(edge):
                continue
            if edge.a in self._nodes and edge.b in self._nodes:
                linked.add(edge.a)
                linked.add(edge.b)
        peers = ([n for n in all_peers if n.name in linked]
                 if len(linked) >= 2 else all_peers)

        g = nx.Graph()
        # Anchor nodes are pinned; each solved peer is spring-tethered to its
        # agency's anchor (soft clustering).
        for agency in anchors:
            g.add_node(("anchor", agency))
        for n in peers:
            g.add_node(n.name)
            g.add_edge(n.name, ("anchor", n.agency), weight=self.ANCHOR_WEIGHT)
        # Reputation springs: higher trust => larger weight => stronger pull.
        solved = {n.name for n in peers}
        for edge in self._edges.values():
            if not self._is_layout_edge(edge):
                continue  # null edges are display-only; no spring
            if edge.a in solved and edge.b in solved:
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
        max_step = 0.0
        for n in peers:
            sx, sy = pos[n.name]
            if n.x == 0.0 and n.y == 0.0:
                # First placement (cold solve, or a freshly-added late joiner):
                # snap to the solved point rather than gliding in from origin.
                n.x, n.y = float(sx), float(sy)
                max_step = max(max_step, self.SETTLE_DEADBAND)  # solve again
                continue
            dx, dy = float(sx) - n.x, float(sy) - n.y
            step = math.hypot(dx, dy)
            if step < self.SETTLE_DEADBAND:
                continue  # this node is at rest this frame
            n.x += self.LAYOUT_EASE * dx
            n.y += self.LAYOUT_EASE * dy
            max_step = max(max_step, step)
        # Once every node's solve target is within the deadband, the glide is
        # done: latch settled so subsequent frames skip the solve (and its
        # re-heat wander) until the trust/topology signature changes again.
        if max_step < self.SETTLE_DEADBAND:
            self._settled = True

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
        score = max(0.0, min(1.0, score))
        # A 0.0-weight bilateral edge IS drawn (thin, sparsely dashed -- see
        # _edge_dash), but it stays DISPLAY-ONLY: it's excluded from the force
        # solve (see _is_layout_edge / _relayout / _display_coords) so a peer
        # whose only edge is null still floats at the periphery rather than
        # being tethered by a null spring. This preserves the trust-driven
        # layout while surfacing the zero relationship visually.
        self._edges[key] = _Edge(a=key[0], b=key[1], trust=score)

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
            return "#94a3b8"  # slate-400: dimmed but still visible on the dark
                              # bg (was #555, near-invisible on #121a2e)
        if node.status == "compromised":
            return "#ef4444"
        # Per-peer color wins over agency (same agency can hold multiple role
        # colors, e.g. DoD ODA = squad + microdrones); fall back to agency,
        # then a neutral grey.
        return (self._peer_colors.get(node.name)
                or self._colors.get(node.agency, "#888"))

    def _is_layout_edge(self, edge: _Edge) -> bool:
        """True if the edge should exert a force-solve spring. Null
        (zero-weight) edges are DISPLAY-ONLY: drawn, but they neither pull
        nodes together nor count a node as "connected" for placement."""
        return edge.trust > self.EDGE_TRUST_EPS

    def _edge_width(self, edge: _Edge) -> float:
        if not edge.active:
            return 0.5
        if not self._is_layout_edge(edge):
            return 1.0     # thin: a null (zero-weight) relationship
        # 0.5 at trust=0 up to 5.0 at trust=1
        return 0.5 + 4.5 * edge.trust

    def _edge_dash(self, edge: _Edge) -> Optional[str]:
        """Dash pattern for the edge line. Null (zero-weight) bilateral edges
        render as a thin, sparsely dashed line (short dashes, wide gaps);
        every other edge is solid."""
        if edge.active and not self._is_layout_edge(edge):
            return "3px,9px"
        return None        # solid

    def _edge_color(self, edge: _Edge) -> str:
        # Inactive edges fade to very low opacity grey (cutoff visible).
        if not edge.active:
            return "rgba(148, 163, 184, 0.15)"
        if not self._is_layout_edge(edge):
            # Null (zero-weight) bilateral edge: faint grey so it reads as a
            # present-but-trustless relationship, not a strong tie.
            return "rgba(148, 163, 184, 0.45)"
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

    def _display_coords(self) -> dict[str, tuple[float, float]]:
        """Normalize solved node positions into a fixed display box.

        Maps the (aspect-locked, square) bounding box of the *connected* node
        cloud to +/-DISPLAY_HALFSPAN, centered, so the graph fills the panel
        regardless of the solve's absolute scale. Nodes with no trust edges
        would otherwise be flung far out by repulsion and, defining the bbox,
        crush the connected core into a clump -- so they are excluded from the
        normalization and pulled radially inward to sit just beyond the
        furthest connected node (DISCONNECTED_OUTER). Applied only to the
        rendered coordinates; the stored solve-space positions are untouched so
        the layout can still warm-start and glide.
        """
        nodes = list(self._nodes.values())
        if not nodes:
            return {}
        # A node is "connected" if it appears in any LAYOUT trust edge. Null
        # (zero-weight) edges are display-only and don't count -- a peer held
        # only by null edges was dropped from the solve (see _relayout) and is
        # placed deterministically at the periphery below, consistent with
        # that. (Must match _relayout's linked set or the two disagree.)
        linked = set()
        for e in self._edges.values():
            if not self._is_layout_edge(e):
                continue
            linked.add(e.a)
            linked.add(e.b)
        ref = [n for n in nodes if n.name in linked]
        if len(ref) < 2:
            # Nothing connected yet (pre-trust): frame everyone by their bbox.
            xs = [n.x for n in nodes]
            ys = [n.y for n in nodes]
            cx = 0.5 * (min(xs) + max(xs))
            cy = 0.5 * (min(ys) + max(ys))
            raw = 0.5 * max(max(xs) - min(xs), max(ys) - min(ys))
            sc = self.DISPLAY_HALFSPAN / max(raw, self.NORMALIZE_FLOOR)
            return {n.name: ((n.x - cx) * sc, (n.y - cy) * sc) for n in nodes}

        # Center on the connected cloud's bbox every frame -- this cancels the
        # solve's frame-to-frame translation/rotation drift. The SCALE, though,
        # is held stable across trust changes: re-fitting it every frame (as a
        # plain bbox-normalize does) silently cancels the very expansion a
        # trust drop produces, so nodes never appear to move. Instead we re-fit
        # only when the connected set changes (a peer joins/leaves) or when the
        # cloud would spill the box / collapse well inside it; between those a
        # force change moves the affected nodes on screen at a fixed scale.
        cx = 0.5 * (min(n.x for n in ref) + max(n.x for n in ref))
        cy = 0.5 * (min(n.y for n in ref) + max(n.y for n in ref))
        raw_half = 0.5 * max(max(n.x for n in ref) - min(n.x for n in ref),
                             max(n.y for n in ref) - min(n.y for n in ref))
        target = self.DISPLAY_HALFSPAN / max(raw_half, self.NORMALIZE_FLOOR)
        topo = frozenset(n.name for n in ref)
        if self._disp_scale is None or topo != self._disp_topo:
            self._disp_scale = target          # (re)frame on topology change
            self._disp_topo = topo
        else:
            extent = raw_half * self._disp_scale
            if (extent > self.DISPLAY_HALFSPAN
                    or extent < self.DISPLAY_HALFSPAN * self.DISPLAY_MIN_FILL):
                # cloud spilled out / collapsed inward: ease back toward a fit
                self._disp_scale += self.DISPLAY_REFIT_EASE * (target - self._disp_scale)
        scale = self._disp_scale
        disp = {n.name: ((n.x - cx) * scale, (n.y - cy) * scale) for n in ref}

        # Deterministically place edge-less nodes just beyond the furthest
        # connected node, along their agency's outward direction (fanned so
        # co-located ones -- e.g. microdrone-3 & -4 -- don't overlap). Capped
        # to stay inside the frame with room for the label.
        stray = [n for n in nodes if n.name not in linked]
        if stray:
            conn_r = max((math.hypot(x, y) for x, y in disp.values()),
                         default=self.DISPLAY_HALFSPAN)
            out_r = min(conn_r * self.DISCONNECTED_OUTER,
                        self.DISPLAY_HALFSPAN * self.VIEW_MARGIN * 0.95)
            anchors = self._agency_anchors()
            by_agency: dict[str, list[_Node]] = {}
            for n in stray:
                by_agency.setdefault(n.agency, []).append(n)
            for agency, members in by_agency.items():
                ax, ay = anchors.get(agency, (0.0, 0.0))
                base = math.atan2(ay - cy, ax - cx)
                if ax == cx and ay == cy:
                    base = math.atan2(ay, ax)  # agency anchor at the center
                m = len(members)
                for j, n in enumerate(sorted(members, key=lambda z: z.name)):
                    theta = base + (j - (m - 1) / 2.0) * (0.45 if m > 1 else 0.0)
                    disp[n.name] = (out_r * math.cos(theta),
                                    out_r * math.sin(theta))
        return disp

    def figure(self) -> go.Figure:
        self._relayout()
        disp = self._display_coords()
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
            ax, ay = disp[edge.a]
            bx, by = disp[edge.b]
            fig.add_trace(go.Scatter(
                x=[ax, bx],
                y=[ay, by],
                mode="lines",
                line=dict(color=self._edge_color(edge),
                          width=self._edge_width(edge),
                          dash=self._edge_dash(edge)),
                hoverinfo="text",
                hovertext=(f"{edge.a} &harr; {edge.b}<br>"
                           f"trust: {edge.trust:.2f}"
                           f"{'' if edge.active else ' (inactive)'}"
                           f"{' (no trust)' if edge.active and not self._is_layout_edge(edge) else ''}"),
                showlegend=False,
            ))

        # Nodes: one trace per agency for legend cleanliness.
        per_agency: dict[str, list[_Node]] = {}
        for n in self._nodes.values():
            per_agency.setdefault(n.agency, []).append(n)

        for agency, nodes in sorted(per_agency.items()):
            fig.add_trace(go.Scatter(
                x=[disp[n.name][0] for n in nodes],
                y=[disp[n.name][1] for n in nodes],
                mode="markers+text",
                text=[n.name for n in nodes],
                textposition="bottom center",
                textfont=dict(size=10, color="#e2e8f0"),
                marker=dict(
                    size=[self._node_size(n) for n in nodes],
                    color=[self._node_color(n) for n in nodes],
                    opacity=[n.opacity for n in nodes],
                    line=dict(width=1.5,
                              color=[self._node_color(n) for n in nodes]),
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
                x=[disp[n.name][0] for n in pulse_nodes],
                y=[disp[n.name][1] for n in pulse_nodes],
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

        # Fixed square range around the normalized cloud (which _display_coords
        # already scaled to +/-DISPLAY_HALFSPAN). Constant across ticks, so a
        # live panel's uirevision keeps the view steady instead of discarding
        # a changing range -- the cloud still fills the frame because the
        # coordinates, not the axis, are what re-fit.
        view = self.DISPLAY_HALFSPAN * self.VIEW_MARGIN
        fig.update_layout(
            width=self._width,
            height=self._height,
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="#121a2e",
            plot_bgcolor="#121a2e",
            xaxis=dict(visible=False, range=[-view, view]),
            yaxis=dict(visible=False, range=[-view, view],
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
