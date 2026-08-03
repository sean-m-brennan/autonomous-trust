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
    # Durable operator-attended signal (ethne D8/Q9): this node now has a human
    # guardian. Persisted with the identity, so the identity process advertises
    # operator_bound=True across restarts. Excluded from Identity.__eq__, so it
    # never changes identity. (The live attended-now stamp is NOT set here — it
    # is runtime freshness produced by the live OperatorSession, never durable.)
    identity.operator_bound = True
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


def operator_key_path(keystore_dir: str = '') -> str:
    """Where the operator's ed25519 signing key lives.

    **Not in the node's config directory, deliberately.** One key per operator,
    stable across every node that human guards (ethne D24: per-node keys would let
    one person present as N guardians), which means a node that could read it could
    impersonate that human on all their other nodes. It belongs to the operator, so
    it lives with the operator: ``$AT_OPERATOR_KEYSTORE``, else
    ``$XDG_CONFIG_HOME/at-operator``, else ``~/.config/at-operator``.
    """
    base = (keystore_dir or os.environ.get('AT_OPERATOR_KEYSTORE', '')
            or os.path.join(os.environ.get(
                'XDG_CONFIG_HOME', os.path.expanduser('~/.config')),
                'at-operator'))
    return os.path.join(base, 'operator_ed25519.key')


def load_or_create_operator_key(keystore_dir: str = '') -> tuple:
    """Return ``(private_key_hex, public_key_bytes)`` for this operator, creating
    the key on first use.

    Stored 0600 in a 0700 directory, hex-encoded to match how every other key in
    this tree is persisted (`Signature.to_dict`). Created only when an operator
    asks to bind one — see `activate(bind_operator_key=True)`.
    """
    from nacl.encoding import HexEncoder
    from ..identity.sign import Signature  # local: heavy import
    path = operator_key_path(keystore_dir)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    if os.path.isfile(path):
        with open(path, 'rb') as fp:
            hex_seed = fp.read().strip()
        sig = Signature(hex_seed, public_only=False)
    else:
        sig = Signature.generate()
        hex_seed = sig.private.encode(encoder=HexEncoder)
        with open(path, 'wb') as fp:
            fp.write(hex_seed)
        os.chmod(path, 0o600)
    return hex_seed, bytes(sig.public)


def bind_operator_key_to_identity(identity, token: PivToken,
                                  keystore_dir: str = '') -> bytes:
    """Bind this operator's ed25519 key to ``identity`` and return the public key.

    The PIV signs
    ``OPERATOR_BINDING_TAG || uuid || node signing key || operator_pubkey``, so any
    peer holding the operator credential can check the claim offline and no node can
    lift the pair onto a different identity. Mutates ``identity`` in place; both
    fields are set together or not at all.

    OPT-IN ONLY. Nothing calls this unless an operator asked for it: publishing one
    key across that operator's nodes is a persistent pseudonym linking them, which
    is a real cost and not one AT may impose. A node that never binds is admitted
    identically and serializes byte-for-byte as before.
    """
    from ..identity.operator_binding import operator_binding_preimage
    _hex_seed, pubkey = load_or_create_operator_key(keystore_dir)
    binding = token.sign(operator_binding_preimage(identity, pubkey))
    identity.operator_pubkey = pubkey
    identity.operator_key_binding = binding
    return pubkey


def sign_with_operator_key(payload: bytes, keystore_dir: str = '') -> bytes:
    """Sign arbitrary bytes with this operator's ed25519 key; return the raw signature.

    The operator's half of an *out-of-band co-signature*: a governance tier above AT
    (ethne charters a node→guardian edge and requires the named guardian to co-sign it)
    exports the exact bytes of a record and needs this human's signature over them. The
    key stays here and only the signature travels back, which is the whole point of
    keeping it in the operator's own keystore rather than a node's config directory.

    Does **not** create a key. If this operator has never bound one there is nothing to
    sign with, and quietly generating a fresh key would produce a signature no node's
    binding attests to; the caller gets an error naming the file instead.

    Nothing in AT calls this — it exists for an operator to run deliberately, and it
    signs whatever it is handed, so the caller is responsible for showing the human what
    the bytes say before asking for a signature.
    """
    sig = _operator_signature(keystore_dir)
    return sig.private.sign(payload).signature


def operator_public_key(keystore_dir: str = '') -> bytes:
    """This operator's raw 32-byte ed25519 public key.

    Deliberately raw bytes rather than any particular identifier format: the tier above
    decides how to name a key (ethne derives a `did:key` from exactly these bytes), and
    AT has no business knowing that encoding.
    """
    return bytes(_operator_signature(keystore_dir).public)


def _operator_signature(keystore_dir: str = ''):
    """Load the operator's keypair, refusing to invent one."""
    from ..identity.sign import Signature  # local: heavy import
    path = operator_key_path(keystore_dir)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f'no operator key at {path}; bind one first with `--bind-operator-key` '
            '(binding is opt-in, and it is what creates the key)')
    with open(path, 'rb') as fp:
        hex_seed = fp.read().strip()
    return Signature(hex_seed, public_only=False)


def bind_identity_file(cfg_dir: str, cert_der: bytes,
                       token: Optional[PivToken] = None,
                       bind_operator_key: bool = False,
                       keystore_dir: str = '') -> Optional[str]:
    """Load ``identity.cfg.json`` from ``cfg_dir``, bind the PIV cert, save.

    With ``bind_operator_key`` (and the open token), also binds the operator's
    ed25519 key so this node can name *which* human guards it — off by default.

    Returns the identity file path, or None if no identity file is present
    (mirrors examples/dod_mission/participant._attach_zta_credential).
    """
    from ..identity import Identity  # local: heavy import
    id_path = os.path.join(cfg_dir, 'identity' + Identity.file_ext)
    if not os.path.isfile(id_path):
        return None
    ident = Identity.from_file(id_path)
    bind_piv_credential(ident, cert_der)
    if bind_operator_key and token is not None:
        bind_operator_key_to_identity(ident, token, keystore_dir)
    ident.to_file(id_path)
    return id_path


def activate(token: PivToken, ca_bundle_path: str,
             cfg_dir: Optional[str] = None,
             identity_id: str = '',
             factors: Optional[List[dict]] = None,
             crl_path: str = '', ocsp_url: str = '',
             totp_secret: str = '', totp_code: str = '',
             bind_operator_key: bool = False,
             operator_keystore: str = '') -> ActivationResult:
    """Run PIV challenge-response (+ TOTP, if enrolled) and, on success, bind.

    ``token`` is an already-open `PivToken` (the CLI opens it after PIN entry; a
    `SoftwareToken` stands in for dev/CI). When ``totp_secret`` is set, a TOTP
    code is **required**: the PIV envelope and the code are combined into one
    `MfaCredential` and AND-verified through an `MfaChain`, so a missing or
    invalid second factor blocks activation. When ``cfg_dir`` is given, the
    verified credential is bound to the identity file and the operator policy
    (incl. the TOTP factor) is written there.

    ``bind_operator_key`` — **off by default** — additionally binds this operator's
    ed25519 key to the node's identity, so the node can advertise *which* human
    guards it (ethne's chartered node->guardian edge, D15). It is opt-in because the
    key is stable across the operator's nodes and therefore links them; declining
    changes nothing about admission, and is the anonymous default.
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
        bind_identity_file(cfg_dir, cert_der, token=token,
                           bind_operator_key=bind_operator_key,
                           keystore_dir=operator_keystore)
        write_operator_policy(cfg_dir, ca_bundle_path, factors=factors,
                              crl_path=crl_path, ocsp_url=ocsp_url,
                              totp_secret=totp_secret)
    return ActivationResult(status=ZtaStatus.VERIFIED,
                            reason='operator activated',
                            credential_hash=result.credential_hash,
                            issuer=piv_issuer(cert_der))
