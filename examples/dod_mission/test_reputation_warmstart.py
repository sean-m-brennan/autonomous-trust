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
import contextlib
import importlib
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reputation_warmstart as rw  # noqa: E402


@contextlib.contextmanager
def _reloaded_with_env(**env):
    """Reimport the module under a temporary environment, then put both the
    environment and the module back.

    The thresholds resolve at import, exactly as they do in repprocess.py, so an
    override is only observable across a reload. Restoring the module matters as
    much as restoring the environment: every other test in this file reads the
    module-level constants, so a leaked reload would silently retune them.
    """
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        yield importlib.reload(rw)
    finally:
        for key, was in saved.items():
            if was is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = was
        importlib.reload(rw)


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

def test_exact_neutral_is_neutral():
    # Neutral / cold-start on the [0, 1] scale is PREREP_NEUTRAL (0.2), a small
    # leeway above the COMM_CUTOFF (0.1). (Was 0.5 under the old scale.)
    assert rw.is_neutral_rep(0.2)
    assert rw.is_neutral_rep(0.2 + 1e-12)


def test_earned_scores_are_not_neutral():
    # 0.5 is no longer the neutral placeholder — it is an ordinary earned score.
    for s in (0.1, 0.3, 0.5, 0.7, 0.8, 0.49, 0.51):
        assert not rw.is_neutral_rep(s), s


# ---- reconcile_rep_score ------------------------------------------------

def test_real_score_always_wins_over_neutral():
    vals = [(0.2, 0), (0.8, 2)]
    assert rw.reconcile_rep_score(vals, is_warm_start=True) == (0.8, 2)
    assert rw.reconcile_rep_score(vals, is_warm_start=False) == (0.8, 2)


def test_latest_real_score_wins_when_multiple():
    vals = [(0.8, 2), (0.3, 0)]
    assert rw.reconcile_rep_score(vals, is_warm_start=False) == (0.3, 0)


def test_warm_start_peer_with_only_neutral_gets_seeded_prior():
    # The fighter-jet case: present too briefly for any committed history,
    # so every reading is the cold-start 0.2 -> show the seeded prior.
    vals = [(0.2, 0)]
    assert rw.reconcile_rep_score(vals, is_warm_start=True) == (
        rw.SEED_REPUTATION, rw.SEED_TIER)


def test_cold_peer_with_only_neutral_stays_neutral():
    # A non-pre-trusted peer with no history reads the neutral placeholder.
    vals = [(0.2, 0)]
    assert rw.reconcile_rep_score(vals, is_warm_start=False) == (0.2, 0)


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
    # Neutral / cold-start on the [0, 1] scale is 0.2, unified across the
    # consensus and bilateral query paths. The value is checked against the two
    # runtimes it mirrors in test_neutral_mirrors_both_runtimes below; here it is
    # only asserted that this module resolves ONE neutral for both paths.
    assert rw.PREREP_NEUTRAL == rw.NEUTRAL_REP
    assert rw.NEUTRAL_REP_DEFAULT == 0.2


# ---- the mirror against its two sources of truth ------------------------
#
# This module is the THIRD copy of AT's neutral threshold: repprocess.py and
# reputation.h are the other two, and both resolve AT_REP_NEUTRAL at runtime.
# Asserting a literal 0.2 here would pin the drift rather than catch it, which is
# what this test used to do. It reads the two declarations as TEXT rather than
# importing them, for two reasons: the module under test is deliberately
# dependency-free, and an import of the AT stack would skip on a missing dep in
# exactly the environments where this check matters. A skipped test is not a
# check, so an unreadable source is a FAILURE below, never a skip.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PY_SOURCE = (_REPO_ROOT / 'src' / 'autonomous-trust' / 'autonomous_trust' /
              'core' / '_python' / 'reputation' / 'repprocess.py')
_C_SOURCE = (_REPO_ROOT / 'src' / 'c' / 'autonomous_trust' / 'reputation' /
             'reputation.h')


def _declared(path, pattern, what):
    assert path.is_file(), (
        f"cannot read {what} at {path}: this test exists to compare the demo's "
        f"neutral against that source, so a missing source is a failure, not a skip"
    )
    match = re.search(pattern, path.read_text())
    assert match is not None, (
        f"{what} no longer declares its neutral in the form this test reads "
        f"({pattern!r} did not match {path}); the mirror is unchecked until the "
        f"pattern is updated"
    )
    return float(match.group(1))


def test_neutral_mirrors_both_runtimes():
    py_default = _declared(
        _PY_SOURCE,
        r"PREREP_NEUTRAL\s*=\s*_env_float\(\s*['\"]AT_REP_NEUTRAL['\"]\s*,\s*([0-9.]+)",
        'repprocess.py')
    c_default = _declared(
        _C_SOURCE,
        r"#define\s+PREREP_NEUTRAL_DEFAULT\s+([0-9.]+)",
        'reputation.h')
    assert rw.NEUTRAL_REP_DEFAULT == py_default, (
        f"demo default {rw.NEUTRAL_REP_DEFAULT} != repprocess.py {py_default}")
    assert rw.NEUTRAL_REP_DEFAULT == c_default, (
        f"demo default {rw.NEUTRAL_REP_DEFAULT} != reputation.h {c_default}")


def test_neutral_follows_the_operator_override():
    # Both runtimes honor AT_REP_NEUTRAL. If this module did not, a tuned
    # deployment would report no cold-start readings at all: every pre-trusted
    # asset would keep its unsubstituted neutral and draw a 0.0 edge that the
    # renderer prunes, dropping it off the Trust Network graph silently.
    with _reloaded_with_env(AT_REP_NEUTRAL='0.35') as mod:
        assert mod.NEUTRAL_REP == 0.35
        assert mod.PREREP_NEUTRAL == 0.35
        assert mod.is_cold_start_reading(0.35)
        assert mod.is_neutral_rep(0.35)
        # The compiled-in default is no longer the node's neutral, so it is an
        # ordinary score.
        assert not mod.is_cold_start_reading(0.2)
        assert mod.warm_start_edge_score(0.35, True) == mod.SEED_REPUTATION
        assert mod.warm_start_edge_score(0.2, True) == 0.2
    # Restored for every other test in this file.
    assert rw.NEUTRAL_REP == rw.NEUTRAL_REP_DEFAULT


def test_an_unparseable_override_falls_back_like_both_runtimes():
    for bad in ('', 'not-a-float'):
        with _reloaded_with_env(AT_REP_NEUTRAL=bad) as mod:
            assert mod.NEUTRAL_REP == mod.NEUTRAL_REP_DEFAULT, bad


# ---- is_cold_start_reading / warm_start_edge_score (bilateral graph) ----

def test_the_one_neutral_is_recognized_on_both_query_paths():
    # The consensus and bilateral paths are unified at PREREP_NEUTRAL (0.2) since
    # the signed-scale framing was reverted, so this is one value under two
    # names, not two neutrals. (The old name of this test claimed two.)
    assert rw.is_cold_start_reading(0.2)
    assert rw.is_cold_start_reading(rw.PREREP_NEUTRAL)
    assert rw.is_cold_start_reading(rw.NEUTRAL_REP)
    # is_cold_start_reading is the bilateral name for is_neutral_rep, and
    # delegates to it, so the two can no longer disagree.
    for s in (0.2, 0.0, 0.5, 0.35, 0.7):
        assert rw.is_cold_start_reading(s) == rw.is_neutral_rep(s), s
    # The old-scale neutrals (0.5 pure / 0.0 CTFT) are no longer cold-start.
    assert not rw.is_cold_start_reading(0.5)
    assert not rw.is_cold_start_reading(0.0)


def test_earned_bilateral_scores_are_not_cold_start():
    # CTFT pivots and computed pure scores are earned, never cold-start.
    for s in (0.49, 0.51, 0.3, 0.5, 0.7, 0.8, 0.62):
        assert not rw.is_cold_start_reading(s), s


def test_warm_start_edge_substitutes_prior_for_pretrusted_subject():
    # A pre-trusted subject with no earned bilateral history reads the cold-start
    # neutral (0.2, unified across the pure and CTFT paths) -> show the seeded
    # prior so it draws a trust edge instead of dropping off the graph.
    assert rw.warm_start_edge_score(0.2, True) == rw.SEED_REPUTATION
    assert rw.warm_start_edge_score(rw.PREREP_NEUTRAL, True) == rw.SEED_REPUTATION


def test_warm_start_edge_preserves_real_score_for_pretrusted_subject():
    # A real (earned) reading for a warm-start subject is NOT overridden, so the
    # skepticism-wins min-combine still lets genuine low trust win: a compromised
    # microdrone's earned 0.3 must survive to render as a weak/red edge.
    assert rw.warm_start_edge_score(0.3, True) == 0.3
    assert rw.warm_start_edge_score(0.8, True) == 0.8


def test_warm_start_edge_never_substitutes_cold_boot_subject():
    # A non-pre-trusted subject (rq86 gateway, mq800, ground sensor) is never
    # warm-started on the graph, even at the cold-start neutral -> stays at the
    # neutral and its edge is pruned unless it earns real bilateral trust.
    assert rw.warm_start_edge_score(0.2, False) == 0.2
    assert rw.warm_start_edge_score(0.5, False) == 0.5
    assert rw.warm_start_edge_score(0.3, False) == 0.3


# ---- reconcile_rep_score_sticky (cross-cycle timeline stickiness) -------

def test_sticky_retains_earned_value_on_all_neutral_cycle():
    # A re-key / churn cycle where the only candidate is the cold-start
    # baseline must NOT drop the earned 0.82 the peer showed before.
    score, tier = rw.reconcile_rep_score_sticky(
        [(0.2, 0)], is_warm_start=False, cached_score=0.82, cached_tier=3)
    assert (score, tier) == (0.82, 3)


def test_sticky_real_reading_still_wins():
    # A real (non-neutral) reading is never masked, even with a cache — genuine
    # movement (up or down) shows.
    assert rw.reconcile_rep_score_sticky(
        [(0.9, 3)], is_warm_start=False, cached_score=0.5, cached_tier=0) == (0.9, 3)


def test_sticky_earned_drop_and_slash_not_masked():
    # An earned drop and a slash floor are non-neutral -> shown, not held.
    assert rw.reconcile_rep_score_sticky(
        [(0.35, 0)], is_warm_start=False, cached_score=0.8, cached_tier=2) == (0.35, 0)
    assert rw.reconcile_rep_score_sticky(
        [(0.05, 0)], is_warm_start=True, cached_score=0.7, cached_tier=2) == (0.05, 0)


def test_sticky_no_cache_matches_plain_reconcile():
    # First appearance (no cache): identical to reconcile_rep_score, so a
    # warm-start peer still surfaces its seeded prior on an all-neutral cycle.
    assert rw.reconcile_rep_score_sticky(
        [(0.2, 0)], is_warm_start=True) == (rw.SEED_REPUTATION, rw.SEED_TIER)
    assert rw.reconcile_rep_score_sticky(
        [(0.2, 0)], is_warm_start=False) == (0.2, 0)


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
