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
"""The 'piv' MFA factor is this distribution's (FEATURE_SPLIT_PLAN Phase 6):
registered with ZTA's policy when the extension module loads, so an operator
policy (verifier_type "mfa", a PIV factor) builds a PivVerifier, and without
this distribution refuses to load (autonomous-trust-zta's test_zta_policy)."""
from autonomous_trust.core.extensions import all_extensions
from autonomous_trust.operator.piv.piv_verifier import PivVerifier
from autonomous_trust.zta import MfaChain, ZtaPolicy


def test_the_extension_is_found_and_registers_piv():
    assert 'operator' in {ext.name for ext in all_extensions()}


def test_an_mfa_piv_factor_builds_a_piv_verifier():
    v = ZtaPolicy(enabled=True, verifier_type='mfa',
                  ca_bundle_path='/etc/pki/agency.pem',
                  factors=[{'type': 'piv'}]).create_verifier()
    assert isinstance(v, MfaChain)
    assert isinstance(v.factors[0], PivVerifier)
