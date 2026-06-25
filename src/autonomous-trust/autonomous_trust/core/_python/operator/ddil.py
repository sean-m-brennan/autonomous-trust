# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
"""Operator DDIL posture (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.4 / §8).

When the agency CA/OCSP is unreachable from the console, operator posture is
**fail-safe** -- never fail-open, never a blunt hard-deny:

  1. **Preferred: hierarchical relay.** A connected higher-tier/gateway peer
     validates the PIV cert against DoD PKI and vouches via the existing
     quorum-gated, reputation-weighted delegated verification. On success the
     operator earns standing normally (subject to the warm-start floor, §3.3).
  2. **Absent any relay path** (fully partitioned from PKI): the console is
     **capped at presence/communication (tier 1), never denied outright**, and
     **origination of privileged requests** (elevated tier / data-bearing /
     safety-critical) is blocked until validation completes -- direct *or*
     relayed.

Two policy flags drive this (stricter than peer admission's
``allow_ddil_fallback`` / ``ddil_fallback_reputation_cap``):
  * ``operator_allow_ddil_relay`` -- sanction relayed PIV validation.
  * ``operator_privileged_requires_full_verify`` -- gate privileged origination
    on completed validation.

This module is pure decision logic (no node/I/O) so the §3.4 matrix is
unit-testable; the `OperatorNode` (P3) supplies the live validation state and
relay availability.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

#: Presence/communication tier -- the floor an unvalidated console is capped to.
PRESENCE_TIER = 1


class ValidationState(Enum):
    """How (and whether) the operator's PIV credential has been validated."""
    DIRECT = 'direct'    # validated directly against the agency PKI (CA/OCSP)
    RELAYED = 'relayed'  # validated via a gateway's delegated verification
    NONE = 'none'        # not validated -- partitioned from PKI, no relay path


@dataclass
class OperatorPosture:
    """The standing an operator console may exercise right now.

    ``tier_cap`` None means uncapped (full standing); an int caps the tier the
    operator may hold/invoke. ``privileged_allowed`` gates origination of
    privileged requests (elevated tier / data-bearing / safety-critical).
    """
    tier_cap: Optional[int]
    privileged_allowed: bool
    reason: str

    def may_originate(self, required_tier: int = 0,
                      privileged: bool = False) -> bool:
        """Whether a request at ``required_tier`` (privileged or not) may be
        originated under this posture."""
        if self.tier_cap is not None and required_tier > self.tier_cap:
            return False
        if privileged and not self.privileged_allowed:
            return False
        return True


def evaluate_operator_posture(
        validation_state: ValidationState,
        allow_ddil_relay: bool = True,
        privileged_requires_full_verify: bool = True) -> OperatorPosture:
    """Map (validation state, policy flags) to an `OperatorPosture` (§3.4)."""
    if validation_state is ValidationState.DIRECT:
        return OperatorPosture(tier_cap=None, privileged_allowed=True,
                               reason='direct PKI validation')
    if validation_state is ValidationState.RELAYED:
        if allow_ddil_relay:
            # Sanctioned relayed validation completes -> normal standing.
            return OperatorPosture(
                tier_cap=None, privileged_allowed=True,
                reason='relayed (delegated) PKI validation')
        # Relay not sanctioned by policy -> treat as unvalidated.
        return OperatorPosture(
            tier_cap=PRESENCE_TIER,
            privileged_allowed=not privileged_requires_full_verify,
            reason='relay not sanctioned (operator_allow_ddil_relay=False); '
                   'capped at presence/communication')
    # NONE: fully partitioned from PKI, no relay path. Fail-safe: cap, not deny.
    return OperatorPosture(
        tier_cap=PRESENCE_TIER,
        privileged_allowed=not privileged_requires_full_verify,
        reason='no PKI validation path (capped at presence/communication; '
               'privileged origination blocked until validation completes)')


def posture_from_policy(validation_state: ValidationState,
                        policy) -> OperatorPosture:
    """Convenience: read the operator DDIL flags off a `ZtaPolicy`."""
    return evaluate_operator_posture(
        validation_state,
        allow_ddil_relay=getattr(policy, 'operator_allow_ddil_relay', True),
        privileged_requires_full_verify=getattr(
            policy, 'operator_privileged_requires_full_verify', True))
