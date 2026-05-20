# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""MQ-800 contradictory ISR compromise.

The MQ-800 joins at T+4:00 (Phase 4, "Rogue").  Shortly after — once it's
exchanged identity messages with the RQ-86s and the squad — it begins
reporting target-position estimates that disagree with everyone else's.

Mechanism: each honest generator (`TargetPositionXGenerator`, etc.) is
wrapped in an `AbruptDeviation` from
`autonomous_trust.evaluation.redteam.compromise`.  Before activation,
readings pass through unchanged; after activation, a fixed offset is
applied.  This is the same wrapper the multi-agency demo uses for the
falsified NOAA temperature, and the cross-source position validators
in ../tasks/validation.py catch it the same way.

Two refinement notes:

  1. Gradual vs. abrupt.  We use AbruptDeviation by default — easier
     for an audience to see the divergence on the dashboard, and the
     whitepaper's framing ("begins feeding data that directly
     contradicts the other drones") matches an abrupt switch.  Pass
     `mode="gradual"` to use a slow drift instead.

  2. The electronic-noise compromise is *under-*reporting, not
     offset-up: the MQ-800 has reason to mask its own emissions.  We
     pass a negative offset for that generator so the divergence is
     "MQ-800 says 30 dB when everyone else says 55 dB."

Offsets are chosen large enough to trip the validator thresholds:
  POSITION_VALIDATOR_*:  threshold = 50 m → use offset 80 m
  ELECTRONIC_NOISE:      threshold = 15 dB → use offset -25 dB
"""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from autonomous_trust.evaluation.redteam.compromise import (
    AbruptDeviation, GradualDrift, CompromiseBehavior,
)
# Absolute import via the sibling-on-sys.path layout that participant.py
# sets up.  The relative form (``from ..generators.isr import ...``) only
# resolves when this module is imported as ``examples.dod_mission.compromise.
# contradictory_isr`` — but participant.py invokes it via a flat
# ``from contradictory_isr import ...`` after putting compromise/ on
# sys.path, which leaves ``__package__`` empty and breaks the relative form.
from isr import (  # noqa: E402
    TargetPositionXGenerator, TargetPositionYGenerator,
    ElectronicNoiseGenerator,
)


# Default activation: phase 4 starts at T+4:00; we delay 15s so the
# MQ-800 has time to actually join + exchange identity before it begins
# misbehaving.  This matches the COMPROMISE_START event timestamp in
# scenario.py (phase "Rogue").
DEFAULT_ACTIVATE_AT = timedelta(minutes=4, seconds=15)

# Offsets — sized to trip the validators in ../tasks/validation.py.
DEFAULT_POSITION_OFFSET_M = 80.0
DEFAULT_NOISE_OFFSET_DB = -25.0


def _wrap(honest, mode: str, activate_at: timedelta,
          offset: float, drift_rate: float) -> CompromiseBehavior:
    if mode == "gradual":
        return GradualDrift(
            honest_generator=honest,
            activate_at=activate_at,
            drift_rate=drift_rate,
            max_drift=abs(offset),
            direction=1.0 if offset >= 0 else -1.0,
        )
    return AbruptDeviation(
        honest_generator=honest,
        activate_at=activate_at,
        offset=offset,
    )


def create_compromised_mq800_position_x(
    peer_name: str = "mq800",
    activate_at: timedelta = DEFAULT_ACTIVATE_AT,
    mode: str = "abrupt",
    offset: float = DEFAULT_POSITION_OFFSET_M,
    seed: Optional[int] = None,
) -> CompromiseBehavior:
    honest = TargetPositionXGenerator(peer_name, seed=seed)
    return _wrap(honest, mode, activate_at, offset, drift_rate=8.0)


def create_compromised_mq800_position_y(
    peer_name: str = "mq800",
    activate_at: timedelta = DEFAULT_ACTIVATE_AT,
    mode: str = "abrupt",
    offset: float = DEFAULT_POSITION_OFFSET_M,
    seed: Optional[int] = None,
) -> CompromiseBehavior:
    honest = TargetPositionYGenerator(peer_name, seed=seed)
    return _wrap(honest, mode, activate_at, offset, drift_rate=8.0)


def create_compromised_mq800_electronic_noise(
    peer_name: str = "mq800",
    activate_at: timedelta = DEFAULT_ACTIVATE_AT,
    mode: str = "abrupt",
    offset: float = DEFAULT_NOISE_OFFSET_DB,
    seed: Optional[int] = None,
) -> CompromiseBehavior:
    honest = ElectronicNoiseGenerator(peer_name, seed=seed)
    return _wrap(honest, mode, activate_at, offset, drift_rate=3.0)


def create_all_mq800_compromised_generators(
    peer_name: str = "mq800",
    activate_at: timedelta = DEFAULT_ACTIVATE_AT,
    mode: str = "abrupt",
    seed: Optional[int] = None,
) -> list[CompromiseBehavior]:
    """Convenience: produce all three compromised generators for the MQ-800.

    Returns a list parallel to OverheadISRGenerators' generator list —
    callers can swap these in place of honest generators when
    instantiating the MQ-800 peer's data services.
    """
    base = seed if seed is not None else hash(peer_name) & 0xFFFF
    return [
        create_compromised_mq800_position_x(peer_name, activate_at, mode,
                                            seed=base),
        create_compromised_mq800_position_y(peer_name, activate_at, mode,
                                            seed=base + 1),
        create_compromised_mq800_electronic_noise(peer_name, activate_at, mode,
                                                  seed=base + 2),
    ]
