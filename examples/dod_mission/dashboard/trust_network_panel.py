# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Trust Network panel (transitive-trust Stage 5).

Renders peer-of-peer (bilateral) trust as a network graph over the scenario
roster, using the shared ``build_graph_from_scenario`` builder (the same one the
multi_agency demo uses). The live edge weights come from the coordinator's
``trust_matrix`` — each observer's view of every subject, min-combined per pair —
which the coordinator gathers via the peer-pair reputation query round
(``TransitiveTrustMixin``) and publishes in its dashboard state.

Shaped like the other chart panels: a no-arg ``figure()`` the live_server tick
callback renders each frame, and a ``set_trust_matrix()`` feed hook (mirroring
the map panel's ``set_platforms``) the callback calls with fresh state.
"""

from autonomous_trust.inspector.dashboard.disaster_response_graph import (
    TrustNetworkGraph,
)


class TrustNetworkPanel:
    # dcc.Graph config the live_server chart loop picks up (the other charts
    # pass displayModeBar=False). The Trust Network is the one panel a user
    # pans/zooms to read a dense cohort, so it shows a modebar. Scroll-zoom is
    # DISABLED because the panel lives in a vertically-scrolling column and
    # wheel-zoom would hijack page scroll; zoom is via the modebar +/-
    # (zoomIn2d / zoomOut2d) buttons instead, pan is click-drag (dragmode set in
    # figure()), and resetScale2d returns to the fitted view. Whitelisting the
    # buttons drops box-zoom/select/lasso/autoscale we don't want here.
    graph_config = {
        "displayModeBar": True,
        "displaylogo": False,
        "scrollZoom": False,
        "modeBarButtons": [["pan2d", "zoomIn2d", "zoomOut2d", "resetScale2d"]],
    }

    def __init__(self, scenario, peer_colors=None,
                 title="Trust Network — Bilateral Trust"):
        self._scenario = scenario
        self._title = title
        self._trust_matrix: list = []
        self._compromised = None
        self._excluded = None
        # One persistent graph across ticks: its agency-anchored force layout
        # warm-starts from the previous frame's node positions, so the network
        # glides as reputation shifts instead of re-solving (and jumping) every
        # frame. Rebuilding via build_graph_from_scenario() each tick would
        # forfeit that warm start.
        #
        # peer_colors (name -> CSS) carries the DoD role colors so nodes render
        # in their role color instead of a fallback grey (same-agency peers
        # differ, so agency-keyed coloring won't do -- see TrustNetworkGraph).
        self._graph = TrustNetworkGraph(peer_colors=peer_colors)

    def set_trust_matrix(self, trust_matrix, compromised=None, excluded=None):
        """Feed the latest bilateral trust edges (list of (observer, subject,
        score)) plus optional compromised/excluded peer name sets. Tolerates
        None (renders the roster with no trust edges yet)."""
        self._trust_matrix = trust_matrix or []
        self._compromised = compromised
        self._excluded = excluded

    def figure(self):
        # The trust network shows the WHOLE cohort at full opacity -- including
        # late joiners (mq800 phase 4, jet-1 phase 6, which add_peer would leave
        # at opacity 0) and disconnected peers (ECM casualties, not-yet-queried
        # nodes). Disconnected nodes render just beyond the connected cluster
        # (see _display_coords) -- shown, just not linked -- never faded out.
        self._graph.apply_scenario_state(
            self._scenario,
            trust_matrix=self._trust_matrix,
            compromised=self._compromised,
            excluded=self._excluded,
            peer_opacity={name: 1.0 for name in self._scenario.peers},
        )
        fig = self._graph.figure()
        # Stable view across ticks (no zoom/pan reset), and our own title.
        # The base figure uses a tight 10px top margin (no title of its own);
        # the chart panels stack with no gap, so give the title its own band
        # of headroom, otherwise it renders on top of the plot / collides with
        # the chart above it.
        fig.update_layout(
            title=dict(text=self._title, x=0.02, xanchor="left",
                       y=0.98, yanchor="top",
                       font=dict(size=13, color="#e2e8f0")),
            margin=dict(l=10, r=10, t=34, b=10),
            # Click-drag pans (the modebar +/- buttons zoom; see graph_config).
            # The default 'zoom' dragmode would box-select instead, which reads
            # as broken on a graph the user expects to drag around.
            dragmode="pan",
            uirevision="dod-trust-network",
        )
        return fig
