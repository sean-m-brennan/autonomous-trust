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
"""PIV/CAC verifier: X.509 chain + PKCS#11 challenge-response.

`PivVerifier` implements the ZTA `Verifier` interface for the operator console
(PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.1). It proves three things at activation:

  1. **Validity** -- the PIV authentication certificate chains to the agency
     root/intermediate bundle (and is unexpired). Delegated *verbatim* to the
     existing `X509Verifier`, so PIV reuses the audited chain logic.
  2. **Possession + PIN** -- the operator's PKCS#11 session signed a fresh,
     server-issued, single-use nonce with the PIV authentication private key
     (PIN-unlocked, key never leaves the card). Card + PIN = two factors before
     MFA even adds a third.
  3. **Binding** -- `credential_hash = SHA-256(cert DER)`, the value bound into
     `Identity.zta_credential_hash`, stable across second-factor rotation.

The challenge nonce is fresh, single-use, bound to the AT identity, and TTL'd
(replay defense, §8). `PivVerifier` is used **locally at activation**; the
credential that then propagates to peers is the bare cert DER, which peers
re-validate with their own `X509Verifier` (no challenge-response on the wire).
"""
from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional

from ..zta_verifier import Verifier, X509Verifier, ZtaResult, ZtaStatus

_NONCE_LEN = 32
_DEFAULT_CHALLENGE_TTL_SEC = 120


@dataclass
class PivCredential:
    """Activation-time PIV credential envelope: cert + signed challenge.

    Serialized with 4-byte big-endian length prefixes (local-only framing; the
    bare cert DER is what travels on the AT wire, not this envelope).
    """
    cert_der: bytes
    nonce: bytes
    signature: bytes

    def pack(self) -> bytes:
        out = bytearray()
        for part in (self.cert_der, self.nonce, self.signature):
            out += struct.pack('>I', len(part))
            out += part
        return bytes(out)

    @staticmethod
    def unpack(data: bytes) -> Optional['PivCredential']:
        parts = []
        off = 0
        try:
            for _ in range(3):
                (length,) = struct.unpack_from('>I', data, off)
                off += 4
                if off + length > len(data):
                    return None
                parts.append(data[off:off + length])
                off += length
        except struct.error:
            return None
        if off != len(data):
            return None
        return PivCredential(cert_der=parts[0], nonce=parts[1], signature=parts[2])


class PivVerifier(Verifier):
    """ZTA verifier for PIV cards: X.509 chain (delegated) + challenge-response.

    Args:
        ca_bundle_path: agency root/intermediate bundle for chain validation.
        token:          an optional `PivToken` (drives `is_available` and is the
                        signer used by an activation helper; verification itself
                        only needs the presented credential).
        ocsp_url/crl_path: passed through to the delegated `X509Verifier`.
        challenge_ttl_sec: lifetime of an issued challenge nonce.
    """

    def __init__(self, ca_bundle_path: str, token=None, ocsp_url: str = '',
                 crl_path: str = '',
                 challenge_ttl_sec: int = _DEFAULT_CHALLENGE_TTL_SEC):
        self._x509 = X509Verifier(ca_bundle_path, ocsp_url, crl_path)
        self._token = token
        self._challenge_ttl_sec = challenge_ttl_sec
        # nonce -> (identity_id, expiry_epoch); single-use, TTL'd.
        self._challenges: dict = {}

    # -- challenge management --------------------------------------------

    def issue_challenge(self, identity_id: str = '') -> bytes:
        """Issue a fresh, single-use, TTL'd nonce bound to ``identity_id``."""
        self._expire_challenges()
        nonce = os.urandom(_NONCE_LEN)
        self._challenges[nonce] = (identity_id, time.time() + self._challenge_ttl_sec)
        return nonce

    def _expire_challenges(self) -> None:
        now = time.time()
        stale = [n for n, (_, exp) in self._challenges.items() if exp < now]
        for n in stale:
            del self._challenges[n]

    def _consume_challenge(self, nonce: bytes, identity_id: str) -> Optional[str]:
        """Return None if the nonce is valid (and consume it), else a reason."""
        entry = self._challenges.pop(nonce, None)
        if entry is None:
            return 'unknown or already-used challenge nonce'
        bound_id, expiry = entry
        if expiry < time.time():
            return 'challenge nonce expired'
        if bound_id and identity_id and bound_id != identity_id:
            return 'challenge nonce bound to a different identity'
        return None

    # -- vtable -----------------------------------------------------------

    def verify_credential(self, cred_data: Optional[bytes],
                          identity_id: str = '') -> ZtaResult:
        if not cred_data:
            return ZtaResult.set(ZtaStatus.REJECTED, 'no credential data')
        cred = PivCredential.unpack(cred_data)
        if cred is None:
            # Not a PIV envelope -> a bare X.509 cert (the form an admitted
            # *peer* presents on the wire). PivVerifier is a strict superset of
            # X509Verifier: chain-only here, chain + challenge-response below.
            # This lets verifier_type="mfa" gate both peer admission (bare cert)
            # and operator activation (envelope) -- see §3.2 "no change to the
            # admission gate". (A DER cert begins 0x30 0x82..., never the
            # 0x0000.... length prefix of an envelope, so the two never alias.)
            return self._x509.verify_credential(cred_data)
        cred_hash = hashlib.sha256(cred.cert_der).digest()

        # 1. Chain/expiry/revocation -- delegated verbatim to X509Verifier.
        chain = self._x509.verify_credential(cred.cert_der)
        if chain.status is not ZtaStatus.VERIFIED:
            chain.credential_hash = cred_hash
            return chain

        # 2. Challenge-response: prove possession of the private key + PIN.
        if not cred.nonce or not cred.signature:
            return ZtaResult(status=ZtaStatus.REJECTED,
                             reason='missing challenge response',
                             credential_hash=cred_hash)
        reason = self._consume_challenge(cred.nonce, identity_id)
        if reason is not None:
            return ZtaResult(status=ZtaStatus.REJECTED, reason=reason,
                             credential_hash=cred_hash)
        if not self._verify_signature(cred.cert_der, cred.nonce, cred.signature):
            return ZtaResult(status=ZtaStatus.REJECTED,
                             reason='challenge signature verification failed',
                             credential_hash=cred_hash)
        return ZtaResult(status=ZtaStatus.VERIFIED,
                         reason='PIV chain + challenge-response verified',
                         credential_hash=cred_hash)

    @staticmethod
    def _verify_signature(cert_der: bytes, nonce: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.x509 import load_der_x509_certificate
        try:
            pub = load_der_x509_certificate(cert_der).public_key()
        except Exception:
            return False
        try:
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(signature, nonce, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
            else:
                return False
        except InvalidSignature:
            return False
        except Exception:
            return False
        return True

    def check_revocation(self, cred_hash: bytes) -> ZtaResult:
        return self._x509.check_revocation(cred_hash)

    def credential_hash(self, cred_data: bytes) -> bytes:
        cred = PivCredential.unpack(cred_data)
        if cred is not None:
            return hashlib.sha256(cred.cert_der).digest()
        return hashlib.sha256(cred_data).digest()

    def is_available(self) -> bool:
        """Available when the CA bundle is loaded and (if attached) the token
        is present -- card removal flips this false (session lifecycle §3.4)."""
        if not self._x509.is_available():
            return False
        if self._token is not None:
            return self._token.is_present()
        return True

    def destroy(self) -> None:
        if self._token is not None:
            self._token.close()
        self._challenges.clear()
