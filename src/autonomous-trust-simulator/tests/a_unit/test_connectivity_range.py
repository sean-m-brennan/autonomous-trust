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
"""Finite comms-range cutoff + sparse reachability matrix +
spatial-grid candidate pruning in Simulator.compute_step.

Exercises the connectivity helpers directly (no path/movement plumbing) with a
real UTMPosition/Ident and lightweight fake peers, so we can place nodes at
exact distances and assert the range/sparse/grid contracts.
"""
import math
import random
from types import SimpleNamespace

import pytest

from autonomous_trust.simulator.simulator import Simulator
from autonomous_trust.simulator.sim_data import Ident
from autonomous_trust.services.peer.position import UTMPosition

ZONE = '16N'  # Madison County, AL area — arbitrary consistent UTM zone
BASE_E, BASE_N = 500000.0, 3800000.0


class FakePeer:
    """Minimal stand-in for PeerInfo: a uuid and a controllable can_reach."""
    def __init__(self, uuid, reach=lambda other, loss: True):
        self.uuid = uuid
        self._reach = reach

    def can_reach(self, other, terrain_loss_db=None):
        return self._reach(other, terrain_loss_db)


def make_sim(max_range_m=None, path_loss_matrix=None, space_mode=False):
    """A Simulator with just the cfg attributes the helpers read (no __init__)."""
    sim = object.__new__(Simulator)
    sim.cfg = SimNamespaceCfg(max_range_m, path_loss_matrix, space_mode)
    return sim


class SimNamespaceCfg(SimpleNamespace):
    def __init__(self, max_range_m, path_loss_matrix, space_mode):
        super().__init__(max_range_m=max_range_m, path_loss_matrix=path_loss_matrix,
                         space_mode=space_mode, comm_freq_hz=None, sun_position=None)


def place(peers_positions):
    """peers_positions: {uuid: (east_offset_m, north_offset_m)} -> (eligible, mapp)."""
    eligible, mapp = [], {}
    for uuid, (de, dn) in peers_positions.items():
        pos = UTMPosition(ZONE, BASE_E + de, BASE_N + dn, 0.0)
        eligible.append(FakePeer(uuid))
        mapp[uuid] = Ident(pos, 0.0, 'node', uuid)
    return eligible, mapp


def run_terrestrial(sim, eligible, mapp, path_loss=None):
    matrix, sig = {}, {}
    sim._connectivity_terrestrial(eligible, mapp, matrix, sig, path_loss)
    return matrix, sig


# ---- _effective_max_range --------------------------------------------------

def test_default_range_is_finite():
    assert make_sim(max_range_m=None)._effective_max_range() == Simulator.DEFAULT_MAX_RANGE_M


def test_range_override():
    assert make_sim(max_range_m=5000.0)._effective_max_range() == 5000.0


@pytest.mark.parametrize('disable', [0, -1, -1000.0])
def test_range_disabled_is_infinite(disable):
    assert math.isinf(make_sim(max_range_m=disable)._effective_max_range())


# ---- sparse emission + range cutoff ---------------------------------------

def test_matrix_is_sparse_true_only():
    """Reachable pairs are present as True; no False entries are emitted."""
    sim = make_sim(max_range_m=100_000.0)
    eligible, mapp = place({'a': (0, 0), 'b': (1000, 0), 'c': (2000, 0)})
    matrix, _ = run_terrestrial(sim, eligible, mapp)
    for row in matrix.values():
        assert all(v is True for v in row.values())  # sparse: only True stored


def test_far_pair_excluded_within_pair_included():
    """A pair beyond max_range is omitted; a pair within it is present."""
    sim = make_sim(max_range_m=50_000.0)  # 50 km
    # a-b are 10 km apart (within); a-c are 300 km apart (beyond)
    eligible, mapp = place({'a': (0, 0), 'b': (10_000, 0), 'c': (300_000, 0)})
    matrix, _ = run_terrestrial(sim, eligible, mapp)
    assert matrix.get('a', {}).get('b') is True
    assert 'c' not in matrix.get('a', {})   # far pair pruned
    assert 'a' not in matrix.get('c', {})


def test_disabled_range_connects_all_pairs():
    """With the cutoff disabled, every ordered pair is evaluated (legacy)."""
    sim = make_sim(max_range_m=0)  # infinite
    eligible, mapp = place({'a': (0, 0), 'b': (10_000, 0), 'c': (1_000_000, 0)})
    matrix, _ = run_terrestrial(sim, eligible, mapp)
    ids = ['a', 'b', 'c']
    for p in ids:
        for o in ids:
            if p != o:
                assert matrix[p][o] is True  # can_reach always True, no range cut


# ---- grid correctness ------------------------------------------------------

def test_grid_matches_bruteforce():
    """The finite-range grid path yields exactly the same reachable set as an
    exhaustive all-pairs scan with the same distance + can_reach filter."""
    max_range = 30_000.0
    sim = make_sim(max_range_m=max_range)
    rng = random.Random(1234)
    positions = {f'n{i}': (rng.uniform(0, 200_000), rng.uniform(0, 200_000))
                 for i in range(60)}
    eligible, mapp = place(positions)

    grid_matrix, _ = run_terrestrial(sim, eligible, mapp)

    # Brute-force reference: every ordered pair within range (can_reach True).
    ref = {}
    ids = list(positions)
    for p in ids:
        for o in ids:
            if p == o:
                continue
            d = mapp[p].position.distance(mapp[o].position)
            if d <= max_range:
                ref.setdefault(p, {})[o] = True

    # Normalise (drop empty rows) and compare.
    norm = lambda m: {k: dict(v) for k, v in m.items() if v}
    assert norm(grid_matrix) == norm(ref)


# ---- terrain sig_quality ---------------------------------------------------

def test_sig_quality_only_for_reachable_terrain_pairs():
    """sig_quality carries terrain loss only for reachable pairs that have a
    path-loss entry."""
    sim = make_sim(max_range_m=100_000.0)
    eligible, mapp = place({'a': (0, 0), 'b': (5000, 0)})
    path_loss = {'a': {'b': 92.5}, 'b': {'a': 92.5}}
    matrix, sig = run_terrestrial(sim, eligible, mapp, path_loss=path_loss)
    assert matrix['a']['b'] is True
    assert sig['a']['b'] == 92.5
