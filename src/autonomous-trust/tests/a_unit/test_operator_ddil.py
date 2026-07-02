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
"""Operator DDIL posture matrix (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.4)."""
from autonomous_trust.core.operator.ddil import (
    ValidationState, evaluate_operator_posture, posture_from_policy,
    PRESENCE_TIER)
from autonomous_trust.core.identity.zta import ZtaPolicy


class TestPostureMatrix:
    def test_direct_validation_full_standing(self):
        p = evaluate_operator_posture(ValidationState.DIRECT)
        assert p.tier_cap is None
        assert p.privileged_allowed is True
        assert p.may_originate(required_tier=4, privileged=True) is True

    def test_relayed_sanctioned_full_standing(self):
        p = evaluate_operator_posture(ValidationState.RELAYED,
                                      allow_ddil_relay=True)
        assert p.tier_cap is None
        assert p.privileged_allowed is True

    def test_relayed_not_sanctioned_capped(self):
        p = evaluate_operator_posture(ValidationState.RELAYED,
                                      allow_ddil_relay=False,
                                      privileged_requires_full_verify=True)
        assert p.tier_cap == PRESENCE_TIER
        assert p.privileged_allowed is False

    def test_no_validation_capped_not_denied(self):
        # Fail-safe: tier-1 presence still allowed (not a blunt hard-deny),
        # privileged origination blocked.
        p = evaluate_operator_posture(ValidationState.NONE,
                                      privileged_requires_full_verify=True)
        assert p.tier_cap == PRESENCE_TIER
        assert p.privileged_allowed is False
        assert p.may_originate(required_tier=1, privileged=False) is True   # presence ok
        assert p.may_originate(required_tier=2, privileged=False) is False  # above cap
        assert p.may_originate(required_tier=1, privileged=True) is False   # privileged blocked

    def test_no_validation_privileged_gate_relaxed(self):
        # If the privileged gate is disabled, privileged origination is no longer
        # blocked on validation -- but tier is still capped.
        p = evaluate_operator_posture(ValidationState.NONE,
                                      privileged_requires_full_verify=False)
        assert p.tier_cap == PRESENCE_TIER
        assert p.privileged_allowed is True
        assert p.may_originate(required_tier=1, privileged=True) is True
        assert p.may_originate(required_tier=3, privileged=True) is False   # still tier-capped


class TestPostureFromPolicy:
    def test_reads_operator_flags_off_policy(self):
        policy = ZtaPolicy(enabled=True, verifier_type='mfa',
                           operator_allow_ddil_relay=False,
                           operator_privileged_requires_full_verify=True)
        p = posture_from_policy(ValidationState.RELAYED, policy)
        # relay disabled -> capped despite a relayed validation
        assert p.tier_cap == PRESENCE_TIER
        assert p.privileged_allowed is False

    def test_defaults_when_flags_absent(self):
        class _Bare:
            pass
        p = posture_from_policy(ValidationState.NONE, _Bare())
        # getattr defaults: relay allowed, privileged gated.
        assert p.tier_cap == PRESENCE_TIER
        assert p.privileged_allowed is False
