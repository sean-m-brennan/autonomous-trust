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

"""Regression tests for the dashboard Trust Network's warm-start behavior in
``DoDMissionCoordinator._build_trust_matrix``.

Two guarantees the bilateral graph must keep:

  1. The pre-established seeded cohort mesh (squad-/microdrone-/jet-) shows
     IMMEDIATELY — at t=0, with no peer discovered and no peer-pair query
     returned yet — instead of an edgeless graph until the first O(N^2) query
     round routes and returns (~tick 240). It is roster-driven and gated by
     the same ``peer_reputation_visible`` arrival gate the Reputations panel
     uses, so a late joiner (the jet) stays off the graph until it launches.

  2. A real earned reading always wins over the seed: a compromised cohort
     member's low score renders as a weak edge, an earned-high score is shown
     verbatim, and an un-queried pair keeps the seed as a fallback.

Drives the real method (bound to a lightweight stub, no live coordinator
process). Imports the coordinator, which needs the AT stack + networkx/plotly;
skips cleanly when those are absent.

Run: ``pytest examples/dod_mission/test_trust_matrix_warmstart.py``
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

coordinator = pytest.importorskip(
    "coordinator", reason="coordinator import needs the AT stack + networkx/plotly")
import reputation_warmstart as rw  # noqa: E402

_build = coordinator.DoDMissionCoordinator._build_trust_matrix


JET_LAUNCH = 300.0


def _peer(uuid, nick):
    return NS(uuid=uuid, nickname=f"{nick}@dod-demo", identity=None)


def _make_stub():
    """A stand-in exposing only what _build_trust_matrix touches. squad-captain
    + two microdrones are visible from t=0; jet-1 only after JET_LAUNCH; the
    rogue mq800 is not pre-trusted. Agencies match the DoD roster so the
    isolation policy (microdrones->ODA, command->rq86/ODA) can be exercised."""
    roster = {
        "squad-captain": NS(name="squad-captain", agency="ODA"),
        "microdrone-1":  NS(name="microdrone-1",  agency="ODA"),
        "microdrone-2":  NS(name="microdrone-2",  agency="ODA"),
        "jet-1":         NS(name="jet-1",          agency="Air-Support"),
        "rq86-1":        NS(name="rq86-1",         agency="Air-Support"),
        "command":       NS(name="command",        agency="Command"),
        "sensor-1":      NS(name="sensor-1",       agency="Leave-Behind"),
        "mq800-1":       NS(name="mq800-1",        agency="Unknown-Air"),
    }

    def visible(name, t):
        return t >= JET_LAUNCH if name == "jet-1" else True

    s = NS()
    s.scenario = NS(peers=roster, peer_reputation_visible=visible)
    s._warm_start_peers = {"squad-captain", "microdrone-1", "microdrone-2",
                           "jet-1", "coordinator"}
    s.peers = NS(all=[])              # nothing discovered yet
    s.latest_reputation_pairs = {}    # no query has returned
    return s


def _edges(stub, t):
    return {tuple(sorted((a, b))): round(v, 3)
            for a, b, v in _build(stub, t)}


def test_cohort_mesh_shows_at_t0_without_discovery_or_query():
    # THE fix: warm-start is pre-established, so the visible cohort is fully
    # meshed at 0.7 from t=0 even with zero discovered peers and zero query
    # replies. The not-yet-launched jet is absent.
    edges = _edges(_make_stub(), 0.0)
    assert edges == {
        ("microdrone-1", "squad-captain"): rw.SEED_REPUTATION,
        ("microdrone-2", "squad-captain"): rw.SEED_REPUTATION,
        ("microdrone-1", "microdrone-2"): rw.SEED_REPUTATION,
    }


def test_late_joiner_absent_until_visible_then_links_only_within_policy():
    stub = _make_stub()
    assert not any("jet-1" in k for k in _edges(stub, 0.0))
    jet_edges = {k: v for k, v in _edges(stub, JET_LAUNCH).items()
                 if "jet-1" in k}
    # The jet links to the squad (both unrestricted) but NOT to the microdrones
    # (microdrones are isolated to the ODA; the jet is Air-Support).
    assert jet_edges == {("jet-1", "squad-captain"): rw.SEED_REPUTATION}


def test_microdrones_isolated_to_oda():
    # No microdrone<->jet edge ever (jet is Air-Support), even though both are
    # seeded warm-start assets and the jet is visible.
    edges = _edges(_make_stub(), JET_LAUNCH)
    assert not any(
        ("microdrone" in a and "jet" in b) or ("jet" in a and "microdrone" in b)
        for a, b in edges)
    # The ODA-internal mesh (squad<->microdrone, microdrone<->microdrone) stays.
    assert edges[("microdrone-1", "squad-captain")] == rw.SEED_REPUTATION
    assert edges[("microdrone-1", "microdrone-2")] == rw.SEED_REPUTATION


def test_command_isolated_to_rq86_and_oda():
    stub = _make_stub()
    stub.peers = NS(all=[
        _peer("u-cmd", "command"), _peer("u-rq", "rq86-1"),
        _peer("u-jet", "jet-1"), _peer("u-sen", "sensor-1"),
        _peer("u-cap", "squad-captain"), _peer("u-m1", "microdrone-1"),
    ])

    def rep(v):
        return NS(score=v)

    # Command has (real) reputation readings toward everyone; the graph must
    # keep only its rq86 + ODA-soldier links.
    stub.latest_reputation_pairs = {
        ("u-cmd", "u-rq"): rep(0.7),    # -> allowed (rq86 gateway)
        ("u-cmd", "u-cap"): rep(0.7),   # -> allowed (ODA soldier)
        ("u-cmd", "u-jet"): rep(0.7),   # -> dropped (Air-Support)
        ("u-cmd", "u-sen"): rep(0.7),   # -> dropped (Leave-Behind)
        ("u-cmd", "u-m1"): rep(0.7),    # -> dropped (microdrone isolates to ODA)
    }
    cmd_edges = {k for k in _edges(stub, 0.0) if "command" in k}
    assert cmd_edges == {("command", "rq86-1"), ("command", "squad-captain")}


def test_non_pretrusted_peer_gets_no_seeded_edge():
    # mq800 is on the roster but cold-boots; it must not appear in the seeded
    # mesh (it earns/loses trust through real transactions only).
    edges = _edges(_make_stub(), 0.0)
    assert not any("mq800-1" in k for k in edges)


def test_real_reading_overrides_the_seed():
    stub = _make_stub()
    stub.peers = NS(all=[_peer("u-cap", "squad-captain"),
                         _peer("u-m1", "microdrone-1"),
                         _peer("u-m2", "microdrone-2")])

    def rep(v):
        return NS(score=v)

    stub.latest_reputation_pairs = {
        ("u-cap", "u-m1"): rep(0.3), ("u-m1", "u-cap"): rep(0.3),   # compromised
        ("u-cap", "u-m2"): rep(0.85), ("u-m2", "u-cap"): rep(0.85),  # earned high
    }
    edges = _edges(stub, 0.0)
    assert edges[("microdrone-1", "squad-captain")] == 0.3   # low earned wins
    assert edges[("microdrone-2", "squad-captain")] == 0.85  # high earned wins
    assert edges[("microdrone-1", "microdrone-2")] == rw.SEED_REPUTATION  # fallback


def test_cold_start_reading_for_cohort_subject_still_draws_edge():
    # A returned reading that is the cold-start neutral (0.0 CTFT or 0.5 pure)
    # is substituted to the seed rather than pruned, so a queried-but-unhistoried
    # cohort pair still shows an edge (not a disconnected node).
    stub = _make_stub()
    stub.peers = NS(all=[_peer("u-cap", "squad-captain"),
                         _peer("u-m1", "microdrone-1")])

    def rep(v):
        return NS(score=v)

    stub.latest_reputation_pairs = {
        ("u-cap", "u-m1"): rep(0.0),   # CTFT cold-start
        ("u-m1", "u-cap"): rep(0.5),   # pure-mode no-history
    }
    edges = _edges(stub, 0.0)
    assert edges[("microdrone-1", "squad-captain")] == rw.SEED_REPUTATION
