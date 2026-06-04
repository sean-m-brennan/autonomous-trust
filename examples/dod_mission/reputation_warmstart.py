# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
  trusted instead of the cold-start 0.5.

The jet is on the list because its window is too short for consensus to climb.
NOTE: ``command`` was briefly added here too, but seeding it as a mutual-trust
field-group member churned the gateway-reputation tree (continuous group
re-keying), so it was reverted — the command node cold-bootstraps like the
other non-field roles. See [[project_sg2_followups]].
"""
from __future__ import annotations

# Peers whose name starts with one of these are pre-trusted from t=0.
PRE_TRUSTED_PREFIXES = ("squad-", "microdrone-", "jet-")

# Seeded prior reputation + the trust tier it maps to. 0.7 sits clearly above
# the 0.5 rep-persist threshold but under 1.0, landing in the "trusted but
# earned" band; tier 2 ("affirmed") matches it per TIER_FLOORS in
# repprocess.py (0.65..0.80 -> tier 2).
SEED_REPUTATION = 0.7
SEED_TIER = 2

# Cold-start neutral placeholder a consensus query returns for a peer with no
# committed bilateral history yet. A real EMA over the demo's transaction
# scores (0.3 anomalous / 0.8 clean) never lands exactly here, so an exact
# 0.5 reading means "no information yet", not an earned score.
NEUTRAL_REP = 0.5


def is_pre_trusted(peer_name: str) -> bool:
    """True for a warm-start cohort member (name matches a pre-trusted prefix)."""
    return peer_name.startswith(PRE_TRUSTED_PREFIXES)


def is_warm_start_member(peer_name: str, join_phase: int, kind: str) -> bool:
    """True if a peer's DASHBOARD reputation should be warm-started.

    A pre-trusted peer is warm-started only when it has no *earned* consensus
    to show, so the dashboard surfaces its seeded prior instead of the
    cold-start neutral 0.5:

      * ``join_phase > 0`` — joins too late to build any committed history
        (the fighter-jet's ~15 s strike window).
      * ``kind == "soldier"`` — consumer-only. Squad members run no data
        generator (see participant.py), so they never appear as a scored
        counterparty in a bilateral transaction and their consensus never
        leaves the neutral baseline. Their trust is pre-established/seeded,
        exactly as the narration states.

    Data-producing pre-trusted peers (the microdrones) are NOT warm-started:
    they earn real, rising consensus, which is the build-up the trust chart
    is meant to show. Non-pre-trusted peers (command gateway, sensors) are
    never warm-started — they cold-bootstrap. Pure.
    """
    if not is_pre_trusted(peer_name):
        return False
    return join_phase > 0 or kind == "soldier"


def is_neutral_rep(score: float) -> bool:
    """True if a reputation reading is the exact cold-start neutral default."""
    return abs(score - NEUTRAL_REP) < 1e-9


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
