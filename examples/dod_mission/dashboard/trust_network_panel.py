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
    def __init__(self, scenario, title="Trust Network — Bilateral Trust"):
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
        self._graph = TrustNetworkGraph()

    def set_trust_matrix(self, trust_matrix, compromised=None, excluded=None):
        """Feed the latest bilateral trust edges (list of (observer, subject,
        score)) plus optional compromised/excluded peer name sets. Tolerates
        None (renders the roster with no trust edges yet)."""
        self._trust_matrix = trust_matrix or []
        self._compromised = compromised
        self._excluded = excluded

    def figure(self):
        self._graph.apply_scenario_state(
            self._scenario,
            trust_matrix=self._trust_matrix,
            compromised=self._compromised,
            excluded=self._excluded,
        )
        fig = self._graph.figure()
        # Stable view across ticks (no zoom/pan reset), and our own title.
        fig.update_layout(title=self._title, uirevision="dod-trust-network")
        return fig
