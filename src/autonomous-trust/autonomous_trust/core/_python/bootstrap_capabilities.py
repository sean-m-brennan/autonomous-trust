# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""AT-core bootstrap capabilities.

A minimal corpus of tier-0 capabilities that AT ships by default so
peers can engage in low-stakes interactions immediately after admission.
Each capability is registered with ``required_tier=0`` and
``transaction_weight=1`` — they are exercised by the BootstrapWorker
(see doc/architecture/trust-tiers.md §6) to seed reputation from
bilateral pairs before any domain-specific operations begin.

The functions here are intentionally simple v1 sketches; the harder
integrity story (signed nonces, ZKP echo) is a deferred follow-up
(architecture doc §12). The defection surface remains real because the
verifier (BootstrapWorker, client side) checks each result against an
expected value: a misbehaving B can drop, tamper, or refuse, and A
scores 0.1 in any of those cases.

Each capability has the form:

    def at_<verb>(... task parameters ...) -> result_value

The BootstrapWorker injects the parameters via TaskParameters (kwargs)
and reads the result on the requestor side via TaskResult. See
``register_bootstrap_capabilities`` for the canonical registration.
"""

from __future__ import annotations

import os
import time
from typing import Any


# Tolerance (seconds) for at.time-attest. Wide enough to forgive
# routine network RTT and clock drift; narrow enough to catch a peer
# deliberately lying about its clock. Env-overridable via
# AT_TIME_ATTEST_TOLERANCE_SEC.
DEFAULT_TIME_ATTEST_TOLERANCE_SEC = 0.2


# ---------------------------------------------------------------
# Server-side capability functions (executed by the responder).
# ---------------------------------------------------------------

def at_handshake(nonce: int = 0) -> int:
    """Trivial challenge-response: receive an integer nonce, return
    nonce + 1. The verifier checks the increment. A misbehaving peer
    that returns the same nonce or an unrelated value fails the check.

    v1 sketch: real signing of the nonce + responder identity is a
    follow-up (architecture doc §6.1, §12).
    """
    try:
        return int(nonce) + 1
    except (TypeError, ValueError):
        return 0


def at_time_attest() -> float:
    """Return the responder's Unix timestamp. The verifier scores
    based on |result - own_now| vs. tolerance: within → 0.9, outside
    → 0.5, unreachable → 0.1.
    """
    return time.time()


def at_echo_challenge(payload: str = '') -> str:
    """Echo the payload verbatim. The verifier checks byte equality.
    A peer that drops, tampers, or truncates fails.

    v1 sketch: signing of the echoed bytes by the responder is a
    follow-up (architecture doc §6.3, §12).
    """
    return str(payload)


# ---------------------------------------------------------------
# Client-side verifiers (used by BootstrapWorker on the requestor).
# ---------------------------------------------------------------

def verify_handshake(result: Any, sent_nonce: int) -> float:
    """Return 0.9 if the result is exactly ``sent_nonce + 1``; 0.1
    otherwise. The 0.1 score is the canonical "peer defected on a
    low-stakes interaction" value — high enough to keep the round
    moving but low enough to register on the EMA."""
    try:
        return 0.9 if int(result) == int(sent_nonce) + 1 else 0.1
    except (TypeError, ValueError):
        return 0.1


def verify_time_attest(result: Any, requestor_now: float,
                       tolerance: float = DEFAULT_TIME_ATTEST_TOLERANCE_SEC
                       ) -> float:
    """Score the responder's reported time vs. the requestor's clock.
    Within tolerance → 0.9. Outside but parseable → 0.5 (could be
    routine drift; not a hard defection). Unparseable or no result
    → 0.1.
    """
    try:
        delta = abs(float(result) - float(requestor_now))
    except (TypeError, ValueError):
        return 0.1
    return 0.9 if delta < tolerance else 0.5


def verify_echo(result: Any, sent_payload: str) -> float:
    """Byte-equality on the echoed payload. Mismatch == defection."""
    return 0.9 if isinstance(result, str) and result == sent_payload else 0.1


# Name registry — BootstrapWorker walks this to pick a random verb.
BOOTSTRAP_CAPABILITY_NAMES: tuple[str, ...] = (
    'at.handshake',
    'at.time-attest',
    'at.echo-challenge',
)

# Map from capability name to (server function, client verifier). The
# verifier signature varies per cap; the BootstrapWorker dispatches by
# name and supplies the appropriate expected-value at call time.
BOOTSTRAP_FUNCTIONS: dict[str, Any] = {
    'at.handshake':       at_handshake,
    'at.time-attest':     at_time_attest,
    'at.echo-challenge':  at_echo_challenge,
}

BOOTSTRAP_VERIFIERS: dict[str, Any] = {
    'at.handshake':       verify_handshake,
    'at.time-attest':     verify_time_attest,
    'at.echo-challenge':  verify_echo,
}


def time_attest_tolerance() -> float:
    """Tolerance (seconds) for ``at.time-attest``, honoring
    ``AT_TIME_ATTEST_TOLERANCE_SEC``.

    The env override was documented at the top of this module from the start
    but never actually read, so the constant was the only value in play.

    Worth knowing when tuning it: the comparison happens on the REQUESTOR at
    scoring time, so the measured delta includes the round trip, not just the
    responder's clock error. A truthful peer one RTT away can exceed a tight
    tolerance through no fault of its own. That is survivable because
    :func:`verify_time_attest` scores an out-of-tolerance-but-parseable answer
    0.5 ("could be routine drift") rather than 0.1 ("defected") — but it is the
    reason this is tunable rather than compiled in.
    """
    raw = os.environ.get('AT_TIME_ATTEST_TOLERANCE_SEC')
    if raw is None:
        return DEFAULT_TIME_ATTEST_TOLERANCE_SEC
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_TIME_ATTEST_TOLERANCE_SEC
    return value if value > 0 else DEFAULT_TIME_ATTEST_TOLERANCE_SEC


def is_probe_capability(cap_name) -> bool:
    """True if ``cap_name`` is one of the known-answer probe capabilities."""
    return cap_name in BOOTSTRAP_VERIFIERS


def verify_bootstrap_result(cap_name, result, sent_kwargs=None,
                            requestor_now: float = None,
                            tolerance: float = None):
    """Score a probe result against the answer the requestor already knows.

    Returns a score in [0, 1], or ``None`` if ``cap_name`` is not a probe
    capability (the caller should then fall back to ordinary task scoring).

    This is the dispatcher the module's ``BOOTSTRAP_VERIFIERS`` comment always
    described — "the verifier dispatches by name and supplies the appropriate
    expected-value at call time" — and which nothing implemented, so every
    ``verify_*`` function here was dead outside its unit tests and a peer that
    tampered with an echo scored the same as one that echoed faithfully. The
    per-capability argument shapes live here so callers (and the C twin) have
    exactly one place to mirror.

    ``sent_kwargs`` MUST be the requestor's own record of the challenge, not
    the copy carried on the responder's reply — see
    :meth:`TaskResult.attach_requested_parameters`.
    """
    if cap_name not in BOOTSTRAP_VERIFIERS:
        return None
    sent = sent_kwargs or {}
    if cap_name == 'at.handshake':
        # A missing nonce defaults to 0, matching at_handshake's own default,
        # so an unstamped challenge still has a well-defined right answer (1)
        # rather than silently passing anything.
        return verify_handshake(result, sent.get('nonce', 0))
    if cap_name == 'at.time-attest':
        now_ = time.time() if requestor_now is None else requestor_now
        tol = time_attest_tolerance() if tolerance is None else tolerance
        return verify_time_attest(result, now_, tol)
    if cap_name == 'at.echo-challenge':
        return verify_echo(result, sent.get('payload', ''))
    return None


def register_bootstrap_capabilities(capabilities, ladder=None) -> None:
    """Register the three AT-core bootstrap capabilities on the given
    Capabilities mapping, each with required_tier=0 and
    transaction_weight=1 (the bootstrap-corpus signal: low-stakes,
    accumulates slowly, available to every admitted peer).

    When a trust ladder is supplied — a
    :class:`~autonomous_trust.core.trust_ladder.TrustLadder`, a path, or
    (with ``ladder=None``) one discovered via ``AT_TRUST_LADDER`` — the
    bootstrap caps take their ``required_tier`` / ``transaction_weight``
    from it instead of the tier-0 / weight-1 defaults, and any additional
    capabilities the ladder declares are registered metadata-only
    (``function=None``). With no ladder configured this is exactly the
    historical behavior: the three caps register at tier 0 / weight 1 and
    nothing else.

    Idempotent — calling twice replaces with identical entries.
    """
    from .trust_ladder import TrustLadder, load_trust_ladder
    if not isinstance(ladder, TrustLadder):
        ladder = load_trust_ladder(ladder)
    for name, function in BOOTSTRAP_FUNCTIONS.items():
        meta = ladder.capabilities.get(name)
        capabilities.register_ability(
            name, function, arg_names=None, keywords=None,
            required_tier=meta.required_tier if meta else 0,
            transaction_weight=meta.transaction_weight if meta else 1,
        )
    # Register any non-bootstrap capabilities the ladder declares as
    # metadata-only — domain caps are handled remotely, so they carry no
    # local server function.
    for name, meta in ladder.capabilities.items():
        if name in BOOTSTRAP_FUNCTIONS:
            continue
        capabilities.register_ability(
            name, None,
            required_tier=meta.required_tier,
            transaction_weight=meta.transaction_weight,
        )
