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
"""ZTA policy configuration (Python parity with src/c/autonomous_trust/zta/zta_policy).

Field names and defaults mirror the C `zta_policy_t` struct and the documented
`zta_policy.cfg.json` (doc/architecture/zta-integration.md §7). When the policy
file is absent the policy defaults to disabled, so existing deployments are
unaffected.
"""
from __future__ import annotations

import os
from typing import Optional

from ...config.configuration import Configuration
from .zta_verifier import Verifier, NullVerifier, OidcVerifier, X509Verifier


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
                 crl_path: str = ''):
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
        return NullVerifier()
