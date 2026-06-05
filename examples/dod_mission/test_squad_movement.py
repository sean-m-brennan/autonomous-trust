# ******************
#  Copyright 2026 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the DoD demo squad infil/exfil movement model.

The squad stages at the insertion LZ, infiltrates to the objective,
holds, then exfiltrates to a separate extraction point; microdrones stay
co-located as vanguard recon. Driven by DoDMissionScenario.advance_to.

Run from the repo root:
    pytest examples/dod_mission/test_squad_movement.py
"""

from __future__ import annotations

import math
from datetime import timedelta

import pytest

from examples.dod_mission.scenario import (
    DoDMissionScenario,
    GROUND_START,
    GROUND_MID,
    GROUND_EXFIL,
)


def _scenario() -> DoDMissionScenario:
    # Storyline baseline minus the optional joiners — movement only
    # concerns the squad + microdrones, which are always present.
    return DoDMissionScenario(squad_size=4, swarm_size=4,
                              include_mq800=False, include_jet=False,
                              include_command=False)


def _at(sc: DoDMissionScenario, minutes: float):
    sc.advance_to(timedelta(minutes=minutes))


def _horiz_m(a, b) -> float:
    dlat = (a.lat - b.lat) * 111320.0
    dlon = (a.lon - b.lon) * 111320.0 * math.cos(math.radians(a.lat))
    return math.hypot(dlat, dlon)


def _captain(sc):
    # squad-captain is index 0 -> zero lateral offset -> the centroid.
    return sc.peers["squad-captain"].position


def test_staged_at_lz_during_setup():
    sc = _scenario()
    _at(sc, 0.0)
    cap = _captain(sc)
    assert _horiz_m(cap, _Pt(*GROUND_START)) < 5.0
    _at(sc, 1.0)
    assert _horiz_m(_captain(sc), _Pt(*GROUND_START)) < 5.0


def test_infiltrates_to_objective():
    sc = _scenario()
    _at(sc, 2.0)
    midway = _captain(sc)
    # Partway between LZ and objective at T+2 (path spans T+1..T+3).
    assert _horiz_m(midway, _Pt(*GROUND_START)) > 100.0
    assert _horiz_m(midway, _Pt(*GROUND_MID)) > 100.0
    _at(sc, 3.0)
    assert _horiz_m(_captain(sc), _Pt(*GROUND_MID)) < 5.0


def test_holds_at_objective():
    sc = _scenario()
    _at(sc, 5.0)
    assert _horiz_m(_captain(sc), _Pt(*GROUND_MID)) < 5.0


def test_exfiltrates_to_separate_extraction():
    sc = _scenario()
    _at(sc, 8.0)
    cap = _captain(sc)
    assert _horiz_m(cap, _Pt(*GROUND_EXFIL)) < 5.0
    # Exfil point is genuinely distinct from the insertion LZ.
    assert _horiz_m(_Pt(*GROUND_EXFIL), _Pt(*GROUND_START)) > 500.0


def test_two_microdrones_drop_off_before_exfil():
    sc = _scenario()  # swarm_size=4
    names = [f"microdrone-{i}" for i in range(1, 5)]
    # Before the ECM losses, the whole swarm is active.
    assert all(sc.peer_active(n, 300.0) for n in names)
    # Staggered losses: microdrone-4 at T+5:20, microdrone-3 at T+5:40.
    assert not sc.peer_active("microdrone-4", 330.0)
    assert sc.peer_active("microdrone-3", 330.0)
    assert not sc.peer_active("microdrone-3", 345.0)
    # Exactly two survive into the exfil beat (T+7:00).
    survivors = [n for n in names if sc.peer_active(n, 450.0)]
    assert survivors == ["microdrone-1", "microdrone-2"]


def test_small_swarm_takes_no_casualties():
    # Scale-test safety: a swarm too small to spare two loses nobody.
    sc = DoDMissionScenario(squad_size=2, swarm_size=2, include_mq800=False,
                            include_jet=False, include_command=False)
    assert sc.peer_active("microdrone-1", 450.0)
    assert sc.peer_active("microdrone-2", 450.0)


@pytest.mark.parametrize("minutes", [0.0, 2.0, 5.0, 7.5, 8.0])
def test_microdrones_colocated_within_envelope(minutes):
    sc = _scenario()
    _at(sc, minutes)
    cap = _captain(sc)
    horiz = []
    for i in range(1, 5):
        drone = sc.peers[f"microdrone-{i}"].position
        d = _horiz_m(drone, cap)
        horiz.append(d)
        # Co-location envelope: never more than 200 m in any direction.
        assert d <= 200.0
        # Hover altitude averages 10-20 m; 200 m is the ceiling.
        assert 10.0 <= drone.alt <= 200.0
    # Average horizontal separation is small (~20 m), well inside 200 m.
    assert sum(horiz) / len(horiz) <= 50.0


def test_squad_keeps_formation_while_moving():
    sc = _scenario()
    _at(sc, 2.0)
    cap = _captain(sc)
    # All squad members stay tightly clustered around the centroid.
    for member in ("squad-warrant", "squad-intel", "squad-ops"):
        assert _horiz_m(sc.peers[member].position, cap) < 50.0


class _Pt:
    """Lightweight (lat, lon) stand-in for distance helpers."""
    def __init__(self, lat, lon, alt=0.0):
        self.lat, self.lon, self.alt = lat, lon, alt
