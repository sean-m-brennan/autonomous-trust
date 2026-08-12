# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Single source of truth for the dod-mission warm-start (pre-trusted) cohort.

Kept dependency-free so the two consumers agree on WHO is pre-trusted and at
WHAT level without importing each other's heavy deps:

* ``tools/seed_dod_cohort.py`` seeds each pre-trusted peer's persistent
  ``reputation.cfg.json`` (mutual recognition + a 0.7 prior) at deploy time.
* ``examples/dod_mission/coordinator.py`` warm-starts its *dashboard*
  reputation view, so a pre-trusted peer that is present too briefly to build
  consensus history — the fighter-jet's ~15 s strike window — still reads
  trusted instead of the cold-start neutral.

The jet is on the list because its window is too short for consensus to climb.
NOTE: ``command`` was briefly added here too, but seeding it as a mutual-trust
field-group member churned the gateway-reputation tree (continuous group
re-keying), so it was reverted — the command node cold-bootstraps like the
other non-field roles. See [[project_sg2_followups]].
"""
from __future__ import annotations

import os


def _env_float(name, default):
    """Mirror of ``repprocess._env_float``, duplicated rather than imported so
    this module stays dependency-free (see the module docstring). A missing,
    empty or unparseable value uses the default, exactly as the two runtimes do.

    Both runtimes resolve the reputation thresholds from the environment --
    ``repprocess.py`` via this same logic, ``reputation.h`` via
    ``reputation_env_double`` -- so that "Python<->C stay byte-comparable under
    the SAME environment". This module is the third copy of those thresholds and
    has to resolve them the same way or it stops agreeing with the nodes it is
    reading.
    """
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


# Peers whose name starts with one of these are pre-trusted from t=0.
PRE_TRUSTED_PREFIXES = ("squad-", "microdrone-", "jet-")

# Seeded prior reputation + the trust tier it maps to. 0.7 sits clearly above
# the 0.5 rep-persist threshold but under 1.0, landing in the "trusted but
# earned" band; tier 2 ("affirmed") matches it per TIER_FLOORS in
# repprocess.py (0.65..0.80 -> tier 2).
SEED_REPUTATION = 0.7
SEED_TIER = 2

# Cold-start neutral placeholder a consensus query returns for a peer with no
# committed bilateral history yet. On the [0, 1] scale the neutral / cold-start
# reputation is PREREP_NEUTRAL (0.2) — a small leeway above the COMM_CUTOFF
# (0.1) communication cut-off — so _consensus_baseline returns the neutral for a
# peer with no committed history. A real EMA over the demo's transaction scores
# (0.3 anomalous / 0.8 clean) never lands exactly here, so an exact neutral
# reading means "no information yet", not an earned score.
#
# DEFAULT vs RESOLVED, the same split reputation.h draws between
# PREREP_NEUTRAL_DEFAULT and PREREP_NEUTRAL. The default mirrors
# repprocess.py's `_env_float('AT_REP_NEUTRAL', 0.2)` and reputation.h's
# PREREP_NEUTRAL_DEFAULT; test_neutral_mirrors_both_runtimes reads BOTH of those
# sources and fails if this number stops matching either, so the mirror is
# checked against what it mirrors rather than against a literal.
NEUTRAL_REP_DEFAULT = 0.2

# The operator override both runtimes honor. Without this the demo would keep
# testing for 0.2 while a node tuned by AT_REP_NEUTRAL returned something else:
# no reading would count as cold-start, no pre-trusted asset would get its prior
# substituted, and every one of them would draw a 0.0 edge the renderer prunes.
NEUTRAL_REP = _env_float('AT_REP_NEUTRAL', NEUTRAL_REP_DEFAULT)

# The bilateral (peer-pair / rep_req) query path that feeds the Trust Network
# graph returns the SAME neutral on the [0, 1] scale: an observer's rep_req of a
# subject it has no local history with returns ``ReputationProcess.PREREP_NEUTRAL``
# in both pure mode (a warm-start-seeded observer whose stored prior
# 0.7 > COOP_ENTER) and tit-for-tat mode (a cold observer). Both mean "no earned
# bilateral info yet". Since the earlier signed-scale framing was reverted, the
# consensus and bilateral neutrals are unified at PREREP_NEUTRAL; this name is
# kept for the two documented query paths and is an ALIAS, so there is one
# definition of the neutral here. If AT ever re-splits the two scales, this is
# the line that stops being an alias.
PREREP_NEUTRAL = NEUTRAL_REP


def is_pre_trusted(peer_name: str) -> bool:
    """True for a warm-start cohort member (name matches a pre-trusted prefix)."""
    return peer_name.startswith(PRE_TRUSTED_PREFIXES)


def is_warm_start_member(peer_name: str, join_phase: int, kind: str) -> bool:
    """True if a peer's DASHBOARD reputation should be warm-started — i.e.
    surface a seeded prior instead of "forming…"/the cold-start neutral for a
    peer that doesn't reliably earn committed consensus in the coordinator's view.

    Warm-started:

      * **Infrastructure** — the command node and the coordinator's own AT
        node (nickname "coordinator", see coordinator.py). Neither is a field
        sensor that earns bilateral consensus, so both read trusted from t=0.
      * **Pre-trusted field assets** — ``join_phase > 0`` (the fighter-jet's
        ~15 s strike window is too brief to build history); ``kind ==
        "soldier"`` (consumer-only squad members run no data generator, so
        they never appear as a scored counterparty); and ``kind ==
        "microdrone"``. Microdrones are seeded in the persistent cohort
        (~0.7) and their earned build-up does not reliably surface via the
        coordinator's consensus query, so they were reading "forming…"
        indefinitely — warm-start them to the seeded prior (a real rising
        score still overrides it the moment one lands; see reconcile_rep_score).

    Non-pre-trusted field peers (leave-behind sensors) are never warm-started —
    they cold-bootstrap. Pure.
    """
    if kind == "command-node" or peer_name in ("command", "coordinator"):
        return True
    if not is_pre_trusted(peer_name):
        return False
    return join_phase > 0 or kind in ("soldier", "microdrone")


def is_neutral_rep(score: float) -> bool:
    """True if a reputation reading is the exact cold-start neutral (the resolved
    ``NEUTRAL_REP``, which follows ``AT_REP_NEUTRAL`` when an operator sets it)."""
    return abs(score - NEUTRAL_REP) < 1e-9


def is_cold_start_reading(score: float) -> bool:
    """True if a *bilateral* (peer-pair) reputation reading is a cold-start
    neutral — i.e. carries no earned bilateral information.

    A ``rep_req`` returns the same neutral on both of its paths: pure mode (a
    warm-start-seeded observer) and tit-for-tat mode (a cold observer). Since the
    signed-scale framing was reverted they are one value on the [0, 1] scale, so
    this is ``is_neutral_rep`` under the name the bilateral call sites use, and
    it delegates rather than repeating the comparison. An earned score (CTFT
    pivots min(0.49)/max(0.51), or a computed pure score) is not cold-start.
    Pure."""
    return is_neutral_rep(score)


def warm_start_edge_score(score: float, is_warm_start_subject: bool) -> float:
    """Trust-Network (bilateral) analog of ``reconcile_rep_score`` for a single
    directional edge reading. Substitute the seeded prior when the SUBJECT of
    the reading is a warm-start asset AND the reading is a cold-start neutral
    (no earned bilateral history yet), so a pre-trusted peer draws a trust edge
    instead of dropping off the graph as a disconnected node (0.0-trust edges
    are pruned by the renderer).

    A real reading — including earned skepticism (a CTFT-floored low score) — is
    returned unchanged, so the skepticism-wins min-combine over a pair's two
    directions still lets genuine low trust override the prior. Non-warm-start
    subjects are never substituted. Pure."""
    if is_warm_start_subject and is_cold_start_reading(score):
        return SEED_REPUTATION
    return score


def reconcile_rep_score(vals, is_warm_start):
    """Pick a peer's representative ``(score, tier)`` from one cycle's readings.

    ``vals`` is this cycle's list of candidate ``(score, tier)`` tuples for a
    single peer (a re-keyed/rejoining peer can surface more than one). Prefer
    the latest real (non-neutral) score. For a warm-start peer with only the
    neutral cold-start placeholder — present too briefly to have committed any
    consensus history, like the fighter-jet at strike — return its seeded prior
    so a pre-trusted peer never reads untrusted while it's up. Real bilateral
    transactions override this the moment they land (they're non-neutral, so
    the squad/microdrone build-up is unaffected). Pure.
    """
    real = [v for v in vals if not is_neutral_rep(v[0])]
    if real:
        return real[-1]
    if is_warm_start:
        return (SEED_REPUTATION, SEED_TIER)
    return vals[-1]


def reconcile_rep_score_sticky(vals, is_warm_start,
                               cached_score=None, cached_tier=None):
    """``reconcile_rep_score`` with CROSS-CYCLE stickiness for the timeline.

    The name-keyed twin of the per-peer running consensus EMA: when NO reading
    this cycle carries real (non-neutral) evidence — every candidate is the
    cold-start baseline — and the peer has already earned a value on a prior
    cycle (``cached_score`` is not None), retain that value (and ``cached_tier``)
    rather than regressing to the placeholder. This bridges the gap when a
    peer's live identity uuid briefly drops out of the roster or a re-keyed /
    "forming" uuid surfaces alone for a cycle, which otherwise drew a per-peer
    timeline sawtooth (drop to baseline, then re-climb).

    A REAL reading always wins — an earned climb, an earned drop, or a slash
    floor are all non-neutral, so genuine trust movement is never masked. With
    no cache this is exactly ``reconcile_rep_score`` (warm-start peers still
    surface their seeded prior on a first all-neutral cycle). Pure.
    """
    has_real = any(not is_neutral_rep(s) for s, _ in vals)
    if not has_real and cached_score is not None:
        _, fallback_tier = reconcile_rep_score(vals, is_warm_start)
        return (cached_score,
                cached_tier if cached_tier is not None else fallback_tier)
    return reconcile_rep_score(vals, is_warm_start)
