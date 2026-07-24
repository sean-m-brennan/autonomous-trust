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
"""ZTA policy configuration (Python parity with src/c/autonomous_trust/zta/zta_policy).

Field names and defaults mirror the C `zta_policy_t` struct and the documented
`zta_policy.cfg.json` (doc/architecture/zta-integration.md §7). When the policy
file is absent the policy defaults to disabled, so existing deployments are
unaffected.
"""
from __future__ import annotations

import os
from typing import List, Optional

from ...config.configuration import Configuration
from .zta_verifier import Verifier, NullVerifier, OidcVerifier, X509Verifier
from .mfa import MfaChain, CombinePolicy


class ZtaPolicy(Configuration):
    """Runtime ZTA verification policy.

    Loaded from ``zta_policy.cfg.json`` via the standard Configuration machinery
    (``__init__`` accepts every serialized field as a keyword arg so
    ``config_json_decoder`` reconstructs it with ``cls(**kwargs)``).
    """

    CONFIG_KEY = 'zta_policy'  # the configurations-dict key, matching the C side

    def __init__(self,
                 enabled: bool = False,
                 require_at_admission: bool = True,
                 reverify_interval_sec: int = 3600,
                 revocation_reputation_penalty: float = 0.8,
                 allow_ddil_fallback: bool = True,
                 ddil_fallback_reputation_cap: float = 0.5,
                 audit_deferred_verifications: bool = True,
                 delegated_verification_min_reputation: float = 0.7,
                 delegated_verification_quorum: int = 1,
                 verifier_type: str = 'x509',
                 ca_bundle_path: str = '',
                 ocsp_url: str = '',
                 crl_path: str = '',
                 factors: Optional[List[dict]] = None,
                 operator_allow_ddil_relay: bool = True,
                 operator_privileged_requires_full_verify: bool = True,
                 operator_ca_bundle_path: str = ''):
        super().__init__()
        self.enabled = enabled
        self.require_at_admission = require_at_admission
        self.reverify_interval_sec = reverify_interval_sec
        self.revocation_reputation_penalty = revocation_reputation_penalty
        self.allow_ddil_fallback = allow_ddil_fallback
        self.ddil_fallback_reputation_cap = ddil_fallback_reputation_cap
        self.audit_deferred_verifications = audit_deferred_verifications
        self.delegated_verification_min_reputation = delegated_verification_min_reputation
        self.delegated_verification_quorum = delegated_verification_quorum
        self.verifier_type = verifier_type
        self.ca_bundle_path = ca_bundle_path
        self.ocsp_url = ocsp_url
        self.crl_path = crl_path
        # MFA / operator-console fields (Python-only; see mfa.py and
        # PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.2/§3.4). Additive + optional:
        # the C parser ignores unknown keys, so peer-admission policies are
        # unaffected.
        # Each factor dict: {"type": "piv"|"totp"|"x509"|"oidc"|"null", ...params}.
        self.factors = list(factors) if factors else []
        # DDIL posture for operator origination (stricter than peer admission's
        # allow_ddil_fallback): prefer relayed PIV validation; absent any relay,
        # cap at presence/communication and gate privileged origination.
        self.operator_allow_ddil_relay = operator_allow_ddil_relay
        self.operator_privileged_requires_full_verify = operator_privileged_requires_full_verify
        # Distinct trust anchor for OPERATOR (human-attended) credentials, used
        # by the admission gate to tell an operator credential from an ordinary
        # device/drone credential (ethne guardian edge, D8/Q9). A credential is
        # operator-class iff it chain-verifies against THIS bundle — a separate
        # CA from ca_bundle_path (mirrors real deployments where PIV/CAC CAs are
        # distinct from device CAs). Empty => no operator anchor => the node
        # cannot confirm any peer is human (operator_bound stays False, the
        # fail-safe). Non-forgeable: derived from the verified chain, never from
        # the peer-advertised operator_bound/zta_issuer. C parity: the same
        # bundle path in the C zta_policy. Additive/optional key so the C parser
        # (and older configs) ignore it safely.
        self.operator_ca_bundle_path = operator_ca_bundle_path

    @classmethod
    def defaults(cls) -> 'ZtaPolicy':
        """A disabled policy (all ZTA code paths become no-ops)."""
        return cls()

    @classmethod
    def load(cls, cfg_dir: Optional[str] = None) -> 'ZtaPolicy':
        """Load ``zta_policy.cfg.json`` from the config dir, or defaults if absent."""
        if cfg_dir is None:
            cfg_dir = cls.get_cfg_dir()
        path = os.path.join(cfg_dir, cls.CONFIG_KEY + cls.file_ext)
        if not os.path.isfile(path):
            return cls.defaults()
        try:
            return cls.from_file(path)
        except Exception:
            return cls.defaults()

    def create_verifier(self) -> Verifier:
        """Construct the configured verifier (mirror of C `zta_policy_create_verifier`).

        When disabled, returns a NullVerifier (always VERIFIED) regardless of
        ``verifier_type``.
        """
        if not self.enabled:
            return NullVerifier()
        vt = (self.verifier_type or 'null').lower()
        if vt == 'x509':
            return X509Verifier(self.ca_bundle_path, self.ocsp_url, self.crl_path)
        if vt == 'oidc':
            return OidcVerifier()
        if vt == 'mfa':
            return self._create_mfa_chain()
        return NullVerifier()

    def create_operator_verifier(self) -> Optional[Verifier]:
        """Construct the OPERATOR-anchor verifier (a chain-only X509Verifier over
        ``operator_ca_bundle_path``), or None when no operator anchor is
        configured. The admission gate uses it to classify a already-verified
        credential as operator-class (ethne D8/Q9); it is deliberately separate
        from ``create_verifier`` (the peer anchor). Mirror of the C
        ``zta_policy_create_operator_verifier``."""
        if not self.enabled or not self.operator_ca_bundle_path:
            return None
        return X509Verifier(self.operator_ca_bundle_path, self.ocsp_url, self.crl_path)

    def _create_mfa_chain(self) -> MfaChain:
        """Build an `MfaChain` from ``self.factors`` (AND-combined).

        With no factors configured the chain is a single `NullVerifier` (the P0
        no-op: enabled-in-code, verifies everything) so an ``mfa`` policy is
        always constructible. Unknown factor types fall back to `NullVerifier`,
        mirroring `create_verifier`'s fallback. PIV and TOTP factor types are
        registered in later phases (P1/P2).
        """
        verifiers = [self._build_factor(f) for f in self.factors]
        if not verifiers:
            verifiers = [NullVerifier()]
        return MfaChain(verifiers, combine=CombinePolicy.AND)

    def _build_factor(self, factor: dict) -> Verifier:
        ft = (factor.get('type') or 'null').lower()
        if ft == 'x509':
            return X509Verifier(factor.get('ca_bundle_path', self.ca_bundle_path),
                                factor.get('ocsp_url', self.ocsp_url),
                                factor.get('crl_path', self.crl_path))
        if ft == 'piv':
            # Imported lazily so the ZTA package loads without PKCS#11/PIV deps.
            # No live token here (admission-gate construction): chain-only for
            # bare peer certs; the activation helper builds its own PivVerifier
            # with a real token to drive the challenge-response.
            from .piv.piv_verifier import PivVerifier
            return PivVerifier(factor.get('ca_bundle_path', self.ca_bundle_path),
                               ocsp_url=factor.get('ocsp_url', self.ocsp_url),
                               crl_path=factor.get('crl_path', self.crl_path))
        if ft == 'totp':
            # Lazy import: pyotp need not be installed unless TOTP is configured.
            from .totp import TotpVerifier
            return TotpVerifier(factor.get('secret', ''),
                                valid_window=factor.get('valid_window', 1))
        if ft == 'oidc':
            return OidcVerifier()
        # 'fido2' is future work; for any unknown type fall back to no-op.
        return NullVerifier()
