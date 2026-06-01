# ******************
#  Copyright 2026 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the DoD demo Approach-phase rank-gate (Phase 6 #2).

Run from the repo root:
    pytest examples/dod_mission/test_rank_gate.py
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from examples.dod_mission.scenario import (
    APPROACH_FRACTION_REQUIRED,
    APPROACH_TIER_THRESHOLD,
    DoDMissionScenario,
    _bootstrap_gate,
)


def _advance(sc: DoDMissionScenario, seconds: float) -> str:
    """Tick the scenario and return the current phase name."""
    sc.advance_to(timedelta(seconds=seconds))
    return sc.current_phase.name if sc.current_phase else ""


def test_gate_default_open_without_provider():
    """No tier_view_provider attached → gate clears so existing
    recordings (and tests that don't install a provider) replay
    unmodified."""
    sc = DoDMissionScenario(squad_size=2, swarm_size=2, sensor_count=2)
    assert _advance(sc, 0) == "Setup"
    # past Approach start (T+60s) without a provider → gate open
    assert _advance(sc, 61) == "Approach"


def test_gate_holds_at_setup_when_no_peers_yet():
    """Empty tier view: gate treats this as 'no peers formed yet'
    and stays closed, holding the scenario at Setup."""
    sc = DoDMissionScenario(squad_size=2, swarm_size=2, sensor_count=2)
    sc._tier_view_provider = lambda: {}
    assert _advance(sc, 0) == "Setup"
    assert _advance(sc, 61) == "Setup"
    # Even well past the Approach start time.
    assert _advance(sc, 120) == "Setup"


def test_gate_holds_when_below_fraction_threshold():
    """Less than APPROACH_FRACTION_REQUIRED (default 0.9) at
    tier ≥1 → gate closed → phase stays at Setup."""
    sc = DoDMissionScenario(squad_size=2, swarm_size=2, sensor_count=2)
    # 5 peers, 4 at tier 0 + 1 at tier 1 → 20% pass; well below 90%.
    sc._tier_view_provider = lambda: {
        "p1": 0, "p2": 0, "p3": 0, "p4": 0, "p5": 1,
    }
    assert _advance(sc, 61) == "Setup"


def test_gate_clears_at_or_above_threshold():
    """≥ APPROACH_FRACTION_REQUIRED at tier ≥1 → gate open."""
    sc = DoDMissionScenario(squad_size=2, swarm_size=2, sensor_count=2)
    # 10 peers all at tier 1 → 100% pass.
    sc._tier_view_provider = lambda: {
        f"p{i}": 1 for i in range(10)
    }
    assert _advance(sc, 61) == "Approach"


def test_gate_clears_exactly_at_threshold():
    """Boundary check: exactly the fraction floor should open the gate."""
    sc = DoDMissionScenario(squad_size=2, swarm_size=2, sensor_count=2)
    # 10 peers, 9 at tier ≥1 → 90% = APPROACH_FRACTION_REQUIRED.
    tiers = {f"p{i}": 1 for i in range(9)}
    tiers["p9"] = 0
    sc._tier_view_provider = lambda: tiers
    assert APPROACH_FRACTION_REQUIRED == 0.9  # pin
    assert _advance(sc, 61) == "Approach"


def test_gate_reopens_after_clearing():
    """Once the gate clears and the phase advances, subsequent
    drops in tier coverage must NOT pull the scenario back to Setup —
    phase advance is monotonic. (advance_to is one-directional.)"""
    sc = DoDMissionScenario(squad_size=2, swarm_size=2, sensor_count=2)
    tiers = {f"p{i}": 1 for i in range(10)}
    sc._tier_view_provider = lambda: tiers
    assert _advance(sc, 61) == "Approach"
    # All peers regress to tier 0; phase already advanced.
    tiers.clear()
    tiers.update({f"p{i}": 0 for i in range(10)})
    assert _advance(sc, 65) == "Approach"


def test_gate_predicate_signature_directly():
    """_bootstrap_gate(scenario) is a pure function from scenario
    state to bool; smoke-test it in isolation so any future signature
    change shows up here, not just at advance_to call sites."""

    class _StubScenario:
        pass

    sc = _StubScenario()
    # No provider attribute → default open.
    assert _bootstrap_gate(sc) is True

    sc._tier_view_provider = lambda: {}
    assert _bootstrap_gate(sc) is False  # empty view → closed

    sc._tier_view_provider = lambda: {
        "a": APPROACH_TIER_THRESHOLD,
        "b": 0,
    }
    # 50% pass; below 90% → closed.
    assert _bootstrap_gate(sc) is False

    sc._tier_view_provider = lambda: {
        "a": APPROACH_TIER_THRESHOLD,
        "b": APPROACH_TIER_THRESHOLD,
    }
    # 100% pass → open.
    assert _bootstrap_gate(sc) is True
