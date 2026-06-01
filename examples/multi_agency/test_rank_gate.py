# ******************
#  Copyright 2026 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the multi-agency demo Negotiation-phase rank-gate.

Run from the repo root:
    pytest examples/multi_agency/test_rank_gate.py

Mirror of examples/dod_mission/test_rank_gate.py; multi-agency's
analogous gate fires on the Negotiation transition (T+90s) and the
predicate lives in coordinator.py (rather than scenario.py) because
the gate is installed at coordinator-init time — the shared
DisasterResponseScenario is consumed by multiple test contexts and
shouldn't carry coordinator-specific behaviour.
"""

from __future__ import annotations

from datetime import timedelta

from autonomous_trust.evaluation.scenarios.disaster_response import (
    DisasterResponseScenario,
)

from examples.multi_agency.coordinator import (
    NEGOTIATION_FRACTION_REQUIRED,
    NEGOTIATION_TIER_THRESHOLD,
    _bootstrap_gate,
)


def _build_gated_scenario() -> DisasterResponseScenario:
    """Construct a scenario with the gate manually installed on the
    Negotiation phase, mirroring what
    ``MultiAgencyCoordinator._install_negotiation_gate`` does at
    runtime. Avoids spinning up a real coordinator in unit tests.
    """
    sc = DisasterResponseScenario()
    for phase in sc.phases:
        if phase.name == "Negotiation":
            phase.gate = _bootstrap_gate
            break
    return sc


def _advance(sc: DisasterResponseScenario, seconds: float) -> str:
    sc.advance_to(timedelta(seconds=seconds))
    return sc.current_phase.name if sc.current_phase else ""


def test_gate_default_open_without_provider():
    """No tier_view_provider attached → gate clears so existing
    recordings and tests that don't install a provider replay
    unmodified."""
    sc = _build_gated_scenario()
    assert _advance(sc, 0) == "Formation"
    # past Negotiation start (T+90s) without a provider → gate open
    assert _advance(sc, 95) == "Negotiation"


def test_gate_holds_at_bootstrap_when_no_peers_yet():
    """Empty tier view: gate treats this as 'no peers formed yet'
    and stays closed, holding the scenario at Bootstrap (the phase
    before Negotiation)."""
    sc = _build_gated_scenario()
    sc._tier_view_provider = lambda: {}
    assert _advance(sc, 0) == "Formation"
    # T+30s steps Formation → Bootstrap normally (no gate on that one).
    assert _advance(sc, 31) == "Bootstrap"
    # T+95s would step into Negotiation, but the gate holds.
    assert _advance(sc, 95) == "Bootstrap"
    assert _advance(sc, 150) == "Bootstrap"


def test_gate_holds_when_below_fraction_threshold():
    """Less than NEGOTIATION_FRACTION_REQUIRED at tier ≥1 → gate
    closed → phase stays at Bootstrap."""
    sc = _build_gated_scenario()
    sc._tier_view_provider = lambda: {
        "p1": 0, "p2": 0, "p3": 0, "p4": 0, "p5": 1,
    }
    assert _advance(sc, 95) == "Bootstrap"


def test_gate_clears_at_or_above_threshold():
    """≥ NEGOTIATION_FRACTION_REQUIRED at tier ≥1 → gate open."""
    sc = _build_gated_scenario()
    sc._tier_view_provider = lambda: {f"p{i}": 1 for i in range(10)}
    assert _advance(sc, 95) == "Negotiation"


def test_gate_clears_exactly_at_threshold():
    """Boundary check at exactly 90%."""
    sc = _build_gated_scenario()
    tiers = {f"p{i}": 1 for i in range(9)}
    tiers["p9"] = 0
    sc._tier_view_provider = lambda: tiers
    assert NEGOTIATION_FRACTION_REQUIRED == 0.9
    assert _advance(sc, 95) == "Negotiation"


def test_gate_reopens_after_clearing():
    """Once the gate clears and the phase advances, a subsequent drop
    in tier coverage must NOT pull the scenario back to Bootstrap —
    phase advance is monotonic (advance_to is one-directional)."""
    sc = _build_gated_scenario()
    tiers = {f"p{i}": 1 for i in range(10)}
    sc._tier_view_provider = lambda: tiers
    assert _advance(sc, 95) == "Negotiation"
    # All peers regress to tier 0; phase already advanced.
    tiers.clear()
    tiers.update({f"p{i}": 0 for i in range(10)})
    assert _advance(sc, 100) == "Negotiation"


def test_gate_predicate_signature_directly():
    class _StubScenario:
        pass

    sc = _StubScenario()
    assert _bootstrap_gate(sc) is True
    sc._tier_view_provider = lambda: {}
    assert _bootstrap_gate(sc) is False
    sc._tier_view_provider = lambda: {
        "a": NEGOTIATION_TIER_THRESHOLD, "b": 0,
    }
    assert _bootstrap_gate(sc) is False  # 50% < 90%
    sc._tier_view_provider = lambda: {
        "a": NEGOTIATION_TIER_THRESHOLD,
        "b": NEGOTIATION_TIER_THRESHOLD,
    }
    assert _bootstrap_gate(sc) is True
