# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

"""Layout-behavior regression tests for the trust-network force graph.

Locks in the two invariants behind "an edge changes color, so the nodes must
move": (1) a settled graph holds perfectly still when nothing changes (no
spring_layout re-heat wander), and (2) a trust change actually moves the
affected nodes on screen (it is not normalized away by the display transform).
"""
import math

import pytest

try:
    import networkx  # noqa: F401
    import plotly  # noqa: F401
    from autonomous_trust.inspector.dashboard.disaster_response_graph import (
        TrustNetworkGraph,
    )
    _has_deps = True
except (ImportError, ModuleNotFoundError):
    _has_deps = False

pytestmark = pytest.mark.skipif(not _has_deps,
                                reason="networkx/plotly not installed")


def _roster():
    g = TrustNetworkGraph()
    for name, agency in (('hub', 'A'), ('p1', 'A'), ('p2', 'A'),
                         ('p3', 'B'), ('p4', 'B')):
        g.add_peer(name, agency, kind='squad')
    for (a, b), t in {('hub', 'p1'): 0.6, ('hub', 'p2'): 0.85,
                      ('hub', 'p3'): 0.6, ('hub', 'p4'): 0.9,
                      ('p1', 'p2'): 0.5}.items():
        g.set_trust(a, b, t)
    return g


def _settle(g, frames=80):
    for _ in range(frames):
        g._relayout()


def _solve_snapshot(g):
    return {k: (v.x, v.y) for k, v in g._nodes.items()}


def _total_move(a, b):
    return sum(math.hypot(a[k][0] - b[k][0], a[k][1] - b[k][1]) for k in a)


def _disp_dist(disp, a, b):
    return math.hypot(disp[a][0] - disp[b][0], disp[a][1] - disp[b][1])


class TestLayoutConvergence:
    def test_settles_and_freezes(self):
        """Once converged, further frames with unchanged trust move nothing —
        the re-heat wander that the display used to mask is gone."""
        g = _roster()
        _settle(g)
        assert g._settled is True
        before = _solve_snapshot(g)
        for _ in range(10):
            g._relayout()
        assert _total_move(before, _solve_snapshot(g)) == 0.0

    def test_trust_change_rearms_and_moves(self):
        """A trust change re-arms the solve and the affected node actually
        moves; an unchanged graph would have stayed frozen."""
        g = _roster()
        _settle(g)
        p1_before = g._nodes['p1'].x, g._nodes['p1'].y
        g.set_trust('hub', 'p1', 0.15)   # yellow -> red
        _settle(g)
        p1_after = g._nodes['p1'].x, g._nodes['p1'].y
        assert math.hypot(p1_after[0] - p1_before[0],
                          p1_after[1] - p1_before[1]) > 0.1


class TestDisplayReflectsForce:
    def test_lower_trust_pushes_apart_on_screen(self):
        """Dropping an edge's trust must increase the on-screen distance of
        that pair — the movement must survive the display normalization."""
        g = _roster()
        _settle(g)
        d0 = g._display_coords()
        before = _disp_dist(d0, 'hub', 'p1')
        g.set_trust('hub', 'p1', 0.15)
        _settle(g)
        d1 = g._display_coords()
        after = _disp_dist(d1, 'hub', 'p1')
        # visibly farther (the whole point): well beyond float noise
        assert after > before * 1.2

    def test_unchanged_pair_stays_relatively_put(self):
        """A pair whose trust did not change should not be flung around by a
        different edge's change (the old per-frame rescale did exactly that)."""
        g = _roster()
        _settle(g)
        d0 = g._display_coords()
        p4_before = _disp_dist(d0, 'hub', 'p4')
        g.set_trust('hub', 'p1', 0.15)
        _settle(g)
        d1 = g._display_coords()
        p4_after = _disp_dist(d1, 'hub', 'p4')
        # changed far less than the changed pair (which moves >20%)
        assert abs(p4_after - p4_before) / p4_before < 0.20

    def test_display_stable_when_frozen(self):
        """Display coordinates are identical frame-to-frame once settled."""
        g = _roster()
        _settle(g)
        d0 = g._display_coords()
        g._relayout()
        d1 = g._display_coords()
        for name in d0:
            assert d0[name] == pytest.approx(d1[name])
