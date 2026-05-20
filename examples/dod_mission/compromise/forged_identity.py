# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Forged-identity compromise for hacked leave-behind sensors.

This is structurally different from the data-corruption compromises
(see contradictory_isr.py).  Hacked leave-behind sensors do not
necessarily lie about their readings — many of them produce
plausible seismic / acoustic numbers — but they cannot prove who they
claim to be.  The AT identity layer rejects them; data validation
never gets a chance to run.

What this module provides:

  * `ForgedIdentitySensor`: a marker class that bundles an honest
    ground-sensor generator with metadata signaling to the runtime
    that this peer's identity verification must fail.  The Phase 3
    participant runner reads this marker and either presents an
    unsigned identity, a self-signed identity not chained to the
    pre-mission roster, or a Sybil identity that collides with a
    known peer.

  * `create_forged_identity_sensor`: factory that wires the marker
    around the standard ground-sensor generator bundle.

We do NOT wrap the generators in a `CompromiseBehavior` — the data is
honest.  The compromise is in the credential the peer presents at
join time.  See ../tasks/validation.py for how the validators treat
these: they don't, because the readings never enter the trust graph.

Identity-attack mode is set via `forgery_mode`:

  * `"unsigned"`     — peer presents an identity record with no
                       signature at all (simplest case)
  * `"self_signed"`  — peer signs its own identity record without a
                       chain to the mission roster (rejected by the
                       roster validator)
  * `"sybil"`        — peer claims a UUID identical to an existing
                       peer in the roster.  Even noisier — the
                       network will see two claims to the same ID.

Default: `"self_signed"`.  Realistic and noisy enough to surface in
the event log without confusing the multi-peer flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading
# See contradictory_isr.py for why the relative form doesn't work here.
from ground_sensor import GroundSensorGenerators  # noqa: E402


@dataclass
class ForgedIdentitySensor:
    """A hacked leave-behind sensor.

    Carries honest generators (data is normal) plus a forgery-mode
    marker the AT participant runtime reads at peer-init to decide
    what malformed identity record to present.

    Attributes:
        peer_name:     Roster name of the peer (e.g. "sensor-2")
        generators:    The honest ground-sensor generators
        forgery_mode:  "unsigned" | "self_signed" | "sybil"
        sybil_target:  If forgery_mode=="sybil", whose identity to claim
        activate_at:   When the peer joins / attempts identity assertion;
                       matches the scenario's "Contact" phase
    """
    peer_name: str
    generators: GroundSensorGenerators
    forgery_mode: str = "self_signed"
    sybil_target: Optional[str] = None
    activate_at: timedelta = timedelta(minutes=2)
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.forgery_mode not in ("unsigned", "self_signed", "sybil"):
            raise ValueError(
                f"Unknown forgery_mode: {self.forgery_mode!r} "
                f"(want 'unsigned', 'self_signed', or 'sybil')"
            )
        if self.forgery_mode == "sybil" and not self.sybil_target:
            raise ValueError(
                "forgery_mode='sybil' requires sybil_target "
                "(the peer-name to impersonate)"
            )
        # Tag metadata so the dashboard / event log can surface the mode
        # alongside the rejection event.
        self.metadata.setdefault("forgery_mode", self.forgery_mode)
        if self.sybil_target:
            self.metadata.setdefault("sybil_target", self.sybil_target)

    def tick(self, t: timedelta) -> list[Reading]:
        """Produce honest readings.

        The compromise is in the identity layer, not the data layer.
        These readings will be discarded by the network because the
        peer's identity will be rejected — but if you sample them
        without the AT layer in play (e.g. in a unit test), they're
        indistinguishable from a clean sensor's readings.
        """
        return self.generators.tick(t)


def create_forged_identity_sensor(
    peer_name: str,
    forgery_mode: str = "self_signed",
    sybil_target: Optional[str] = None,
    activate_at: timedelta = timedelta(minutes=2),
    seed: Optional[int] = None,
) -> ForgedIdentitySensor:
    """Factory: create a hacked leave-behind sensor.

    Pair with the `metadata={"forged_identity": True}` flag that the
    scenario sets in ../scenario.py for these peers, so the Phase 3
    participant runner picks this up automatically.
    """
    return ForgedIdentitySensor(
        peer_name=peer_name,
        generators=GroundSensorGenerators(peer_name, seed=seed),
        forgery_mode=forgery_mode,
        sybil_target=sybil_target,
        activate_at=activate_at,
    )
