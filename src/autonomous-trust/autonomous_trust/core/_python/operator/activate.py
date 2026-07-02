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
"""Operator activation: PIV (+MFA) -> credential binding -> policy.

The single human touchpoint (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.3). At P1 this
covers the PIV factor and the credential->identity binding; the TOTP second
factor and session lifecycle land in P2, and starting the discovery-capable
`OperatorNode` lands in P3.

Flow (`activate`):
  1. A `PivToken` is already open (PIN entered by the CLI, never stored).
  2. Issue a fresh, single-use challenge nonce; the token signs it.
  3. Verify chain + challenge-response via `PivVerifier` (the MFA second factor
     composes in at P2 via `MfaChain`).
  4. On VERIFIED, bind the PIV cert to the node's `Identity`
     (`zta_credential` / `zta_issuer` / `zta_credential_hash`), persist it, and
     write an operator `zta_policy.cfg.json` (verifier_type="mfa", PIV factor,
     agency CA bundle).

The binding and policy-writing steps are pure, file-level functions so they are
unit-testable without a node or a card.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

from ..identity.zta import ZtaStatus, ZtaPolicy
from ..identity.zta.piv.piv_verifier import PivVerifier, PivCredential
from ..identity.zta.piv.pkcs11 import PivToken


@dataclass
class ActivationResult:
    status: ZtaStatus
    reason: str = ''
    credential_hash: bytes = b''
    issuer: str = ''


def piv_issuer(cert_der: bytes) -> str:
    """Return a stable issuer string ``"PIV:<subject>"`` for the cert."""
    try:
        from cryptography.x509 import load_der_x509_certificate
        subject = load_der_x509_certificate(cert_der).subject.rfc4514_string()
    except Exception:
        return 'PIV:unknown'
    return 'PIV:' + subject


def bind_piv_credential(identity, cert_der: bytes):
    """Bind a verified PIV cert to ``identity`` (in place) and return it.

    Sets the three ZTA fields (identity.proto 6-8). These are excluded from
    `Identity.__eq__`, so binding/rotation never changes identity.
    """
    import hashlib
    identity.zta_credential = cert_der
    identity.zta_issuer = piv_issuer(cert_der)
    identity.zta_credential_hash = hashlib.sha256(cert_der).digest()
    return identity


def load_totp_secret(cfg_dir: str) -> str:
    """Return the enrolled TOTP secret from the operator policy, or ''."""
    policy = ZtaPolicy.load(cfg_dir)
    for factor in (policy.factors or []):
        if (factor.get('type') or '').lower() == 'totp' and factor.get('secret'):
            return factor['secret']
    return ''


def enroll_totp(account_name: str, issuer: str = 'AutonomousTrust'):
    """First-activation TOTP enrollment: return ``(secret, provisioning_uri)``.

    The operator scans the URI into an authenticator app; the secret is then
    persisted into the operator policy's TOTP factor by `write_operator_policy`.
    """
    from ..identity.zta import generate_totp_secret, totp_provisioning_uri
    secret = generate_totp_secret()
    return secret, totp_provisioning_uri(secret, account_name, issuer=issuer)


def write_operator_policy(cfg_dir: str, ca_bundle_path: str,
                          factors: Optional[List[dict]] = None,
                          crl_path: str = '', ocsp_url: str = '',
                          totp_secret: str = '') -> str:
    """Write the operator's ``zta_policy.cfg.json`` and return its path.

    Defaults to a PIV factor, plus a TOTP second factor when ``totp_secret`` is
    given. verifier_type="mfa" means peer admission verifies bare peer certs
    chain-only (the TOTP factor is a secondary factor, skipped for bare certs)
    while operator activation enforces PIV challenge-response + TOTP (see
    `PivVerifier`, `MfaChain`).
    """
    if factors is None:
        factors = [{'type': 'piv', 'ca_bundle_path': ca_bundle_path}]
        if totp_secret:
            factors.append({'type': 'totp', 'secret': totp_secret})
    policy = ZtaPolicy(
        enabled=True,
        require_at_admission=True,
        verifier_type='mfa',
        ca_bundle_path=ca_bundle_path,
        crl_path=crl_path,
        ocsp_url=ocsp_url,
        factors=factors,
    )
    path = os.path.join(cfg_dir, ZtaPolicy.CONFIG_KEY + ZtaPolicy.file_ext)
    policy.to_file(path)
    return path


def bind_identity_file(cfg_dir: str, cert_der: bytes) -> Optional[str]:
    """Load ``identity.cfg.json`` from ``cfg_dir``, bind the PIV cert, save.

    Returns the identity file path, or None if no identity file is present
    (mirrors examples/dod_mission/participant._attach_zta_credential).
    """
    from ..identity import Identity  # local: heavy import
    id_path = os.path.join(cfg_dir, 'identity' + Identity.file_ext)
    if not os.path.isfile(id_path):
        return None
    ident = Identity.from_file(id_path)
    bind_piv_credential(ident, cert_der)
    ident.to_file(id_path)
    return id_path


def activate(token: PivToken, ca_bundle_path: str,
             cfg_dir: Optional[str] = None,
             identity_id: str = '',
             factors: Optional[List[dict]] = None,
             crl_path: str = '', ocsp_url: str = '',
             totp_secret: str = '', totp_code: str = '') -> ActivationResult:
    """Run PIV challenge-response (+ TOTP, if enrolled) and, on success, bind.

    ``token`` is an already-open `PivToken` (the CLI opens it after PIN entry; a
    `SoftwareToken` stands in for dev/CI). When ``totp_secret`` is set, a TOTP
    code is **required**: the PIV envelope and the code are combined into one
    `MfaCredential` and AND-verified through an `MfaChain`, so a missing or
    invalid second factor blocks activation. When ``cfg_dir`` is given, the
    verified credential is bound to the identity file and the operator policy
    (incl. the TOTP factor) is written there.
    """
    cert_der = token.certificate_der()
    piv = PivVerifier(ca_bundle_path, token=token, crl_path=crl_path,
                      ocsp_url=ocsp_url)
    nonce = piv.issue_challenge(identity_id)
    signature = token.sign(nonce)
    envelope = PivCredential(cert_der=cert_der, nonce=nonce,
                             signature=signature).pack()

    if totp_secret:
        # Two-factor: PIV envelope + TOTP code, AND-combined. (The chain does
        # not thread identity_id to the PIV factor, so the nonce's identity
        # binding is not re-checked here; freshness + single-use + signature
        # still hold.)
        from ..identity.zta import MfaChain, MfaCredential
        from ..identity.zta.totp import TotpVerifier
        chain = MfaChain([piv, TotpVerifier(totp_secret)])
        composite = MfaCredential([envelope, (totp_code or '').encode()]).pack()
        result = chain.verify_credential(composite)
    else:
        result = piv.verify_credential(envelope, identity_id=identity_id)

    if result.status is not ZtaStatus.VERIFIED:
        return ActivationResult(status=result.status, reason=result.reason,
                                credential_hash=result.credential_hash)
    if cfg_dir is not None:
        bind_identity_file(cfg_dir, cert_der)
        write_operator_policy(cfg_dir, ca_bundle_path, factors=factors,
                              crl_path=crl_path, ocsp_url=ocsp_url,
                              totp_secret=totp_secret)
    return ActivationResult(status=ZtaStatus.VERIFIED,
                            reason='operator activated',
                            credential_hash=result.credential_hash,
                            issuer=piv_issuer(cert_der))
