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

"""Unit tests for the dod-mission warm-start (pre-trusted) cohort logic.

Covers the pure decisions shared by tools/seed_dod_cohort.py (who gets a
seeded reputation.cfg.json) and coordinator.py (whose dashboard reputation is
warm-started): the pre-trusted membership test, the neutral-reading test, and
the per-cycle score reconciliation that keeps the short-lived fighter-jet from
reading untrusted. Dependency-free, so it runs without the AT/Dash stack.

Run: ``pytest examples/dod_mission/test_reputation_warmstart.py``
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reputation_warmstart as rw  # noqa: E402


# ---- is_pre_trusted -----------------------------------------------------

def test_squad_microdrone_jet_are_pre_trusted():
    for name in ("squad-1", "squad-captain", "microdrone-3", "jet-1"):
        assert rw.is_pre_trusted(name), name


def test_cold_bootstrap_peers_are_not_pre_trusted():
    # command is intentionally NOT pre-trusted: seeding it as a field member
    # churned the gateway-reputation tree, so it cold-bootstraps.
    for name in ("rq86-recon-1", "mq800-armed-1", "sensor-2", "coordinator",
                 "command"):
        assert not rw.is_pre_trusted(name), name


def test_jet_specifically_on_the_list():
    # The jet is the case this warm-start exists for (too-brief strike window).
    assert rw.is_pre_trusted("jet-1")


# ---- is_neutral_rep -----------------------------------------------------

def test_exact_half_is_neutral():
    assert rw.is_neutral_rep(0.5)
    assert rw.is_neutral_rep(0.5 + 1e-12)


def test_earned_scores_are_not_neutral():
    for s in (0.1, 0.3, 0.7, 0.8, 0.49, 0.51):
        assert not rw.is_neutral_rep(s), s


# ---- reconcile_rep_score ------------------------------------------------

def test_real_score_always_wins_over_neutral():
    vals = [(0.5, 0), (0.8, 2)]
    assert rw.reconcile_rep_score(vals, is_warm_start=True) == (0.8, 2)
    assert rw.reconcile_rep_score(vals, is_warm_start=False) == (0.8, 2)


def test_latest_real_score_wins_when_multiple():
    vals = [(0.8, 2), (0.3, 0)]
    assert rw.reconcile_rep_score(vals, is_warm_start=False) == (0.3, 0)


def test_warm_start_peer_with_only_neutral_gets_seeded_prior():
    # The fighter-jet case: present too briefly for any committed history,
    # so every reading is the cold-start 0.5 -> show the seeded prior.
    vals = [(0.5, 0)]
    assert rw.reconcile_rep_score(vals, is_warm_start=True) == (
        rw.SEED_REPUTATION, rw.SEED_TIER)


def test_cold_peer_with_only_neutral_stays_neutral():
    # A non-pre-trusted peer with no history reads the neutral placeholder.
    vals = [(0.5, 0)]
    assert rw.reconcile_rep_score(vals, is_warm_start=False) == (0.5, 0)


def test_build_up_preserved_for_warm_start_peer_once_real():
    # Squad/microdrone build-up: as soon as a real (non-neutral) EMA score
    # lands, it is used verbatim — the warm-start prior does NOT clamp or
    # override it, so the climbing curve is unaffected.
    assert rw.reconcile_rep_score([(0.62, 1)], is_warm_start=True) == (0.62, 1)
    assert rw.reconcile_rep_score([(0.55, 1)], is_warm_start=True) == (0.55, 1)


def test_seed_constants_are_consistent():
    # 0.7 prior maps to tier 2 per the band described in repprocess.py.
    assert rw.SEED_REPUTATION == 0.7
    assert rw.SEED_TIER == 2


# ---- is_warm_start_member ----------------------------------------------

def test_late_joiner_jet_is_warm_started():
    # The jet joins in the Strike phase — too brief to build history.
    assert rw.is_warm_start_member("jet-1", join_phase=6, kind="fighter-jet")


def test_consumer_only_soldier_is_warm_started():
    # Squad members run no data generator, so they never earn consensus and
    # must show their seeded prior rather than a permanent 0.5.
    for name in ("squad-captain", "squad-ops"):
        assert rw.is_warm_start_member(name, join_phase=0, kind="soldier")


def test_data_producing_microdrone_is_warm_started():
    # Microdrones are seeded in the persistent cohort (~0.7), but their earned
    # build-up does not reliably surface via the coordinator's consensus query
    # (data-light / group-churn-prone, more so since C-node interop widened the
    # field cohort), so without warm-start they read "forming…" indefinitely. A
    # real rising score still overrides the prior the moment one lands
    # (reconcile_rep_score), so the trust-dynamics build-up is unaffected when
    # it does surface. (Changed from "not warm-started" by the C-interop work;
    # see is_warm_start_member and coordinator._reputations_view.)
    assert rw.is_warm_start_member("microdrone-3", join_phase=0,
                                   kind="microdrone")


def test_command_and_coordinator_infra_are_warm_started():
    # Infrastructure: the command gateway and the coordinator's own AT node are
    # not field sensors that earn bilateral consensus, so they read trusted
    # from t=0 rather than sitting at a permanent cold-start 0.5.
    assert rw.is_warm_start_member("command", join_phase=0,
                                   kind="command-node")
    assert rw.is_warm_start_member("coordinator", join_phase=0,
                                   kind="coordinator")


def test_non_pretrusted_field_peers_never_warm_started():
    # Leave-behind sensors cold-bootstrap regardless of kind.
    assert not rw.is_warm_start_member("sensor-1", join_phase=2,
                                       kind="ground-sensor")
    # Even a (hypothetical) soldier-kind peer that isn't on the pre-trusted
    # roster stays cold — pre-trust is the gate.
    assert not rw.is_warm_start_member("intruder-1", join_phase=0,
                                       kind="soldier")
