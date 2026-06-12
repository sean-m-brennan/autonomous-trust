# ******************
#  Copyright 2026 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for gating the fighter-jet strike on the MQ-800 rogue's exposure.

The jet must never overfly the objective before the rogue's reputation
collapses (the anomaly the strike is a response to). It flies a visible holding
loiter (on-map, east of the objective) until ``gate_jet_on_anomaly`` fires,
then breaks into the strike run >= JET_ANOMALY_HOLD_SEC later and never before
its authored time.

Run from the repo root:
    pytest examples/dod_mission/test_jet_anomaly_gating.py
"""

from __future__ import annotations

import math
from datetime import timedelta

from examples.dod_mission.scenario import (
    DoDMissionScenario,
    GROUND_MID,
    JET_LOITER,
    JET_LOITER_RADIUS_M,
    JET_LOITER_PERIOD_S,
    JET_LOITER_BASE_ANGLE,
    JET_LAUNCH_SEC,
    JET_STRIKE_SEC,
    JET_ANOMALY_HOLD_SEC,
    JET_HOLD_CEILING_SEC,
    _JET_INGRESS_RUN_SEC,
    _orbit_position,
    ROGUE_PEER_NAME,
)


def _scenario(include_mq800=True):
    return DoDMissionScenario(squad_size=4, swarm_size=4,
                              include_mq800=include_mq800, include_jet=True,
                              include_command=False)


def _jet_at(sc, secs):
    # Drive only the position model (no event firing needed for the gate test).
    sc._update_positions(timedelta(seconds=secs))  # noqa: SLF001
    return sc.peers["jet-1"].position


def _near(pos, latlonalt, tol_m=50.0):
    lat, lon, _ = latlonalt
    dlat = (pos.lat - lat) * 111320.0
    dlon = (pos.lon - lon) * 111320.0 * math.cos(math.radians(lat))
    return math.hypot(dlat, dlon) <= tol_m


def _target(sc, strike_sec):
    """The true (drifting) ISR target at the strike — where the jet now flies,
    rather than the static GROUND_MID squad-hold."""
    lat, lon = sc.true_target_latlon(strike_sec)
    return (lat, lon, GROUND_MID[2])


def _loiter_at(secs):
    """The exact point on the holding-loiter orbit at ``secs`` — the jet breaks
    from here into the strike run (so launch is continuous with the hold)."""
    return _orbit_position(JET_LOITER, JET_LOITER_RADIUS_M,
                           JET_LOITER_PERIOD_S, JET_LOITER_BASE_ANGLE, secs)


def _is_loitering(pos):
    """True if the jet is on its holding loiter: ~one radius from the loiter
    centre and clearly east of the objective (i.e. on-map, not overflying)."""
    dlat = (pos.lat - JET_LOITER[0]) * 111320.0
    dlon = ((pos.lon - JET_LOITER[1]) * 111320.0
            * math.cos(math.radians(JET_LOITER[0])))
    r = math.hypot(dlat, dlon)
    return abs(r - JET_LOITER_RADIUS_M) <= 50.0 and pos.lon > GROUND_MID[1]


def test_no_rogue_uses_authored_timing():
    # Without an MQ-800 there is nothing to gate on: the jet keeps its
    # authored strike (over the target at JET_STRIKE_SEC).
    sc = _scenario(include_mq800=False)
    assert _near(_jet_at(sc, JET_STRIKE_SEC), _target(sc, JET_STRIKE_SEC))


def test_loiters_until_anomaly():
    # Rogue present but not yet exposed -> jet flies a visible holding loiter
    # (on-map, east of the objective) even past its authored strike time,
    # instead of overflying early.
    sc = _scenario()
    assert _is_loitering(_jet_at(sc, JET_STRIKE_SEC))
    assert _is_loitering(_jet_at(sc, JET_STRIKE_SEC + 60))
    # ...and never over the target while holding.
    assert not _near(_jet_at(sc, JET_STRIKE_SEC), _target(sc, JET_STRIKE_SEC))


def test_strikes_after_late_anomaly_flies_in():
    sc = _scenario()
    collapse = 420.0  # rogue exposed well after the authored strike
    sc.gate_jet_on_anomaly(ROGUE_PEER_NAME, collapse)
    # Launches (begins ingress) at collapse + hold, then flies the authored
    # ingress run in; strike = launch + ingress run, no teleport.
    launch = collapse + JET_ANOMALY_HOLD_SEC
    strike = launch + _JET_INGRESS_RUN_SEC
    assert _near(_jet_at(sc, launch), _loiter_at(launch))  # breaking from the loiter
    assert not _near(_jet_at(sc, strike - 5), _target(sc, strike))  # still inbound
    assert _near(_jet_at(sc, strike), _target(sc, strike))          # over the target


def test_early_anomaly_never_pulls_strike_before_authored():
    sc = _scenario()
    sc.gate_jet_on_anomaly(ROGUE_PEER_NAME, 200.0)  # anomaly+hold = 210 < 375
    # Floor at the authored time: not over the target early...
    assert not _near(_jet_at(sc, 210.0), _target(sc, JET_STRIKE_SEC))
    # ...but on target at the authored strike.
    assert _near(_jet_at(sc, JET_STRIKE_SEC), _target(sc, JET_STRIKE_SEC))


def test_gate_ignores_non_rogue_and_is_first_wins():
    sc = _scenario()
    sc.gate_jet_on_anomaly("sensor-1", 300.0)   # not the rogue -> ignored
    assert _is_loitering(_jet_at(sc, JET_STRIKE_SEC))  # still holding (loiter)
    sc.gate_jet_on_anomaly(ROGUE_PEER_NAME, 420.0)  # first real collapse wins
    sc.gate_jet_on_anomaly(ROGUE_PEER_NAME, 999.0)  # later call cannot move it
    strike = 420.0 + JET_ANOMALY_HOLD_SEC + _JET_INGRESS_RUN_SEC
    assert _near(_jet_at(sc, strike), _target(sc, strike))


def test_early_anomaly_keeps_authored_launch_and_strike():
    sc = _scenario()
    sc.gate_jet_on_anomaly(ROGUE_PEER_NAME, 200.0)  # anomaly+hold = 210 < launch 290
    # Authored launch/strike preserved when the anomaly is early.
    strike = JET_LAUNCH_SEC + _JET_INGRESS_RUN_SEC
    assert _near(_jet_at(sc, strike), _target(sc, strike))


def test_ceiling_releases_a_never_exposed_rogue():
    # Degenerate run: rogue never collapses. The jet must still fly its run
    # rather than hold forever, once the clock passes the ceiling.
    sc = _scenario()
    strike = JET_HOLD_CEILING_SEC + _JET_INGRESS_RUN_SEC
    assert _near(_jet_at(sc, JET_HOLD_CEILING_SEC),
                 _loiter_at(JET_HOLD_CEILING_SEC))  # released, breaking from loiter
    assert _near(_jet_at(sc, strike), _target(sc, strike))  # flies in to the target
