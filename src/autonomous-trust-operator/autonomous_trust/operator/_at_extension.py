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
"""How the core finds the operator distribution (see
``autonomous_trust.core.extensions``): named by the
``autonomous_trust.extensions`` entry point when installed, found by file name
in a source tree.

Importing it registers the PIV/CAC factor with ZTA's MFA chain
(``autonomous_trust.zta.zta_policy.register_factor``), so a zta_policy whose
``factors`` name 'piv' can be honoured. Without this distribution such a policy
refuses to load (FEATURE_SPLIT_PLAN Phase 6). It attaches no process handlers.
"""
from autonomous_trust.core.extensions import Extension
from autonomous_trust.zta.zta_policy import register_factor


def _piv_factor(policy, factor):
    # No live token here (admission-gate construction): chain-only for bare
    # peer certs; activation builds its own PivVerifier with a real token to
    # drive the challenge-response.
    from .piv.piv_verifier import PivVerifier
    return PivVerifier(factor.get('ca_bundle_path', policy.ca_bundle_path),
                       ocsp_url=factor.get('ocsp_url', policy.ocsp_url),
                       crl_path=factor.get('crl_path', policy.crl_path))


register_factor('piv', _piv_factor)


def _enabled() -> bool:
    return True


def _register_handlers(proc, proc_name: str) -> None:
    # The factor registration above is all; no core process needs a handler.
    return None


EXTENSION = Extension(name='operator', enabled=_enabled,
                      register_handlers=_register_handlers)
