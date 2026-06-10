# ******************
#  Copyright 2026 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for gating the fighter-jet strike on the MQ-800 rogue's exposure.

The jet must never overfly the objective before the rogue's reputation
collapses (the anomaly the strike is a response to). It holds off-map until
``gate_jet_on_anomaly`` fires, then strikes >= JET_ANOMALY_HOLD_SEC later and
never before its authored time.

Run from the repo root:
    pytest examples/dod_mission/test_jet_anomaly_gating.py
"""

from __future__ import annotations

import math
from datetime import timedelta

from examples.dod_mission.scenario import (
    DoDMissionScenario,
    GROUND_MID,
    JET_INGRESS,
    JET_LAUNCH_SEC,
    JET_STRIKE_SEC,
    JET_ANOMALY_HOLD_SEC,
    JET_HOLD_CEILING_SEC,
    _JET_INGRESS_RUN_SEC,
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


def _ingress(sc, strike_sec):
    """The jet's ingress hold during a flown pass: off-map east at the target's
    (strike-time) latitude, so the whole run is straight east-west on target."""
    lat, _ = sc.true_target_latlon(strike_sec)
    return (lat, JET_INGRESS[1], JET_INGRESS[2])


def test_no_rogue_uses_authored_timing():
    # Without an MQ-800 there is nothing to gate on: the jet keeps its
    # authored strike (over the target at JET_STRIKE_SEC).
    sc = _scenario(include_mq800=False)
    assert _near(_jet_at(sc, JET_STRIKE_SEC), _target(sc, JET_STRIKE_SEC))


def test_holds_offmap_until_anomaly():
    # Rogue present but not yet exposed -> jet holds at the ingress point even
    # past its authored strike time, instead of overflying early.
    sc = _scenario()
    assert _near(_jet_at(sc, JET_STRIKE_SEC), JET_INGRESS)
    assert _near(_jet_at(sc, JET_STRIKE_SEC + 60), JET_INGRESS)


def test_strikes_after_late_anomaly_flies_in():
    sc = _scenario()
    collapse = 420.0  # rogue exposed well after the authored strike
    sc.gate_jet_on_anomaly(ROGUE_PEER_NAME, collapse)
    # Launches (begins ingress) at collapse + hold, then flies the authored
    # ingress run in; strike = launch + ingress run, no teleport.
    launch = collapse + JET_ANOMALY_HOLD_SEC
    strike = launch + _JET_INGRESS_RUN_SEC
    assert _near(_jet_at(sc, launch), _ingress(sc, strike))  # at the hold, just launching
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
    assert _near(_jet_at(sc, JET_STRIKE_SEC), JET_INGRESS)  # still holding
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
                 _ingress(sc, strike))  # released, launching
    assert _near(_jet_at(sc, strike), _target(sc, strike))  # flies in to the target
