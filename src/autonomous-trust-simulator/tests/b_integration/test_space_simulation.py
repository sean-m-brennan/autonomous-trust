# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

"""Integration tests for asteroid belt space simulation (Phase 5).

Tests the full simulation loop: orbital motion, connectivity via FSPL,
light delay computation, and sun occultation detection.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

try:
    from examples.asteroid_belt.scenario import (
        create_asteroid_belt_config,
    )
    from autonomous_trust.simulator.simulator import Simulator
    from autonomous_trust.simulator.radio.space_link import AU_M, C_M_S
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")


class TestAsteroidBeltSimulation:
    """Run the asteroid belt scenario through the simulator."""

    @pytest.fixture
    def sim(self, tmp_path):
        """Create a simulator with the asteroid belt scenario.

        Default duration is 15 years — long enough for differential
        orbital motion (inner habitats orbit faster than outer ones per
        Kepler's third law, creating changing inter-habitat distances).
        """
        cfg_path = create_asteroid_belt_config(
            output_file=str(tmp_path / 'belt.cfg'),
        )
        return Simulator(cfg_path, max_time_steps=200, precompute=False)

    def test_simulation_runs_without_error(self, sim):
        """All 200 timesteps complete without exception."""
        for tick in range(200):
            result = sim.compute_step(tick)
            assert result is not None

    def test_all_habitats_active(self, sim):
        """All 7 habitats are active at every timestep."""
        for tick in range(1, 200, 40):
            _, _, _, _, active, _, _, _ = sim.compute_step(tick)
            assert len(active) == 7

    def test_delays_are_positive(self, sim):
        """All light delays are positive (habitats are separated)."""
        _, _, _, _, _, _, delay, _ = sim.compute_step(1)
        for src, dests in delay.items():
            for dst, d in dests.items():
                assert d > 0, f"Zero/negative delay between {src} and {dst}"

    def test_delays_in_expected_range(self, sim):
        """Light delays should be in a plausible range for belt distances.

        Minimum ~0.1 AU apart (nearby habitats) = ~0.8 min.
        Maximum ~6 AU apart (opposition) = ~50 min.
        """
        _, _, _, _, _, _, delay, _ = sim.compute_step(1)
        for src, dests in delay.items():
            for dst, d in dests.items():
                delay_minutes = d / 60.0
                assert 0.5 < delay_minutes < 120.0, \
                    f"Delay {delay_minutes:.1f}min between {src}-{dst} outside expected range"

    def test_connectivity_changes_over_time(self, sim):
        """Connectivity matrix should change as orbits progress.

        With 15-year duration, Keplerian loops, and marginal link budgets
        (LASER_COMMS viable under ~2.5 AU, DEEP_SPACE under ~5 AU),
        differential orbital motion changes inter-habitat distances enough
        to push links across the viability threshold.
        """
        _, _, _, matrix_1, _, _, _, _ = sim.compute_step(1)
        _, _, _, matrix_100, _, _, _, _ = sim.compute_step(100)
        diffs = 0
        for src in matrix_1:
            for dst in matrix_1.get(src, {}):
                if dst in matrix_100.get(src, {}):
                    if matrix_1[src][dst] != matrix_100[src][dst]:
                        diffs += 1
        assert diffs > 0, (
            "No connectivity changes between step 1 and 100. "
            "Link budgets may need tuning — check receiver sensitivity "
            "vs FSPL at inter-habitat distances."
        )

    def test_habitats_move(self, sim):
        """Habitat positions change between timesteps (orbital motion)."""
        _, _, mapp_1, _, _, _, _, _ = sim.compute_step(1)
        _, _, mapp_100, _, _, _, _, _ = sim.compute_step(100)
        moved = 0
        for peer_id in mapp_1:
            pos_1 = mapp_1[peer_id].position
            pos_100 = mapp_100[peer_id].position
            if pos_1 is not None and pos_100 is not None:
                if pos_1.distance(pos_100) > 1000:  # moved more than 1 km
                    moved += 1
        assert moved >= 5, "Expected most habitats to move between steps 1 and 100"

    def test_precompute_mode(self, tmp_path):
        """Precompute mode works for space scenarios."""
        cfg_path = create_asteroid_belt_config(
            output_file=str(tmp_path / 'belt_pre.cfg'),
            duration=timedelta(days=30),
        )
        sim = Simulator(cfg_path, max_time_steps=20, precompute=True)
        assert len(sim.pre_state) == 20
