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
"""Pluggable ZTA credential verifiers (Python parity with src/c/autonomous_trust/zta).

Mirrors the C `zta_verifier_t` vtable (zta_verifier.h) and the OpenSSL-backed
`x509_verifier.c`. The decision order, statuses, and reason strings match the C
implementation so a peer presenting the same credential is admitted-or-rejected
identically by either side. See doc/architecture/zta-python-parity.md.
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

ZTA_HASH_LEN = 32  # SHA-256

# Hard cap on a ZTA credential blob carried on the wire. Real X.509 chains and
# JWTs comfortably fit; a larger value almost certainly indicates a hostile or
# corrupted peer and would let a remote cause an OOM / parse-time DoS. MUST stay
# in lockstep with C `ZTA_CRED_MAX` (identity.h). Enforced at the admission gate
# (idprocess._zta_admit) so an oversized credential is rejected before the
# verifier spends effort parsing it.
ZTA_CRED_MAX = 64 * 1024


class ZtaStatus(Enum):
    """Result status of a ZTA credential verification.

    Values mirror the C `zta_status_t` enum (zta_verifier.h) name-for-name.
    """
    VERIFIED = 'VERIFIED'        # Credential is valid and verified
    REJECTED = 'REJECTED'        # Invalid (bad signature, unknown issuer, malformed)
    DEFERRED = 'DEFERRED'        # Verification deferred (infrastructure unreachable, DDIL)
    EXPIRED = 'EXPIRED'          # Credential has expired
    REVOKED = 'REVOKED'          # Credential has been revoked
    UNAVAILABLE = 'UNAVAILABLE'  # Verifier cannot perform this operation


@dataclass
class ZtaResult:
    """Result of a credential verification (mirror of C `zta_result_t`)."""
    status: ZtaStatus
    reason: str = ''
    credential_hash: bytes = b''   # SHA-256 of the credential (identity binding)
    ttl_sec: int = 0               # 0 = use policy default

    @staticmethod
    def set(status: ZtaStatus, reason: str = '',
            credential_hash: bytes = b'') -> 'ZtaResult':
        """Convenience matching the C `zta_result_set` helper."""
        return ZtaResult(status=status, reason=reason,
                         credential_hash=credential_hash)


class Verifier(ABC):
    """Pluggable verifier interface (mirror of the C `zta_verifier_t` vtable).

    Unsupported operations return ZTA_UNAVAILABLE, matching the C contract that
    a NULL function pointer is treated as unavailable.
    """

    #: A *secondary factor* (TOTP/FIDO2/...) is meaningful only with explicit
    #: operator interaction at activation; it does not apply to a peer's bare
    #: wire credential. `MfaChain` runs secondary factors only when a composite
    #: (multi-factor) credential is presented, and skips them for the bare-cert
    #: peer-admission path. Primary verifiers (X.509/PIV) leave this False.
    secondary_factor: bool = False

    @abstractmethod
    def verify_credential(self, cred_data: Optional[bytes]) -> ZtaResult:
        """Validate a credential (signature chain, expiry, revocation status)."""

    def check_revocation(self, cred_hash: bytes) -> ZtaResult:
        """Check whether a previously verified credential has been revoked."""
        return ZtaResult.set(ZtaStatus.UNAVAILABLE,
                             'revocation check not supported', cred_hash)

    def is_available(self) -> bool:
        """Whether verification infrastructure is currently reachable."""
        return False

    def credential_hash(self, cred_data: bytes) -> bytes:
        """Deterministic SHA-256 of a credential for identity binding."""
        return hashlib.sha256(cred_data).digest()

    def destroy(self) -> None:
        """Free verifier resources (no-op in Python; here for vtable parity)."""
        return None


class NullVerifier(Verifier):
    """Always returns VERIFIED. Used when ZTA is enabled-in-code but disabled
    at runtime (mirror of the C null verifier)."""

    def verify_credential(self, cred_data: Optional[bytes]) -> ZtaResult:
        h = self.credential_hash(cred_data) if cred_data else b''
        return ZtaResult.set(ZtaStatus.VERIFIED, 'null verifier (ZTA disabled)', h)

    def is_available(self) -> bool:
        return True


class OidcVerifier(Verifier):
    """OIDC token verifier stub (mirror of the C oidc stub): returns UNAVAILABLE
    for all operations. Validates the interface; a real token backend is future
    work."""

    def verify_credential(self, cred_data: Optional[bytes]) -> ZtaResult:
        return ZtaResult.set(ZtaStatus.UNAVAILABLE, 'OIDC verifier not implemented')

    def is_available(self) -> bool:
        return False


class X509Verifier(Verifier):
    """OpenSSL-parity X.509 certificate verifier built on `cryptography` (pyca).

    Reproduces the decision order of C `x509_verify_credential`:
      no cred -> REJECTED; parse fail -> REJECTED; compute hash; expiry -> EXPIRED;
      chain validation against the CA bundle -> VERIFIED else REJECTED.

    Chain validation matches the OpenSSL X509_STORE model where every cert in the
    CA bundle (root and intermediate) is a trusted anchor: from the leaf, follow
    issuer links (verifying each signature + validity window) until an issuer that
    is itself in the store is reached. Depth-bounded.
    """

    _MAX_CHAIN_DEPTH = 8

    def __init__(self, ca_bundle_path: str, ocsp_url: str = '',
                 crl_path: str = '', connect_timeout_ms: int = 2000):
        self.ca_bundle_path = ca_bundle_path
        self.ocsp_url = ocsp_url or ''
        self.crl_path = crl_path or ''
        self.connect_timeout_ms = connect_timeout_ms or 2000
        # subject DER bytes -> certificate (every bundle cert is a trust anchor)
        self._store: dict = {}
        # credential_hash -> parsed cert, for check_revocation (mirror C cache)
        self._cert_cache: dict = {}
        self._x509 = None  # cryptography.x509 module, loaded lazily
        self._load_store()

    # -- helpers ----------------------------------------------------------

    def _ensure_x509(self):
        if self._x509 is None:
            from cryptography import x509  # lazy: only X509Verifier needs pyca
            self._x509 = x509
        return self._x509

    def _load_store(self):
        x509 = self._ensure_x509()
        try:
            with open(self.ca_bundle_path, 'rb') as fp:
                data = fp.read()
        except OSError:
            # No bundle -> empty store. verify_credential then rejects everything
            # with "unknown issuer", and is_available() reports False.
            self._store = {}
            return
        try:
            certs = x509.load_pem_x509_certificates(data)
        except Exception:
            certs = []
            try:
                certs = [x509.load_der_x509_certificate(data)]
            except Exception:
                certs = []
        self._store = {c.subject.public_bytes(): c for c in certs}

    @staticmethod
    def _parse_cert(x509, cred_data: bytes):
        try:
            return x509.load_der_x509_certificate(cred_data)
        except Exception:
            pass
        try:
            return x509.load_pem_x509_certificate(cred_data)
        except Exception:
            return None

    @staticmethod
    def _not_expired(cert, now: datetime) -> bool:
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc

    def _verify_chain(self, leaf) -> ZtaResult:
        """Walk leaf -> issuer -> ... -> a self-signed root anchor in the store.

        Each hop's validity window and issuer signature are verified. Only a
        self-signed certificate present in the store terminates the chain as a
        trust anchor; every cert strictly between the leaf and that root is an
        intermediate CA. The number of intermediates is bounded by
        ``_MAX_CHAIN_DEPTH`` -- the SAME quantity OpenSSL's
        ``X509_VERIFY_PARAM_set_depth`` bounds on the C side (the max number of
        intermediate CAs between the leaf and the trust anchor), so a chain that
        one implementation accepts the other does too. A chain with more
        intermediates than the bound is REJECTED ('certificate chain too long').

        (Previously this returned VERIFIED after the first hop -- treating every
        bundled cert as a terminal anchor -- so the depth bound was unreachable
        dead code and multi-hop chains were never actually walked.)
        """
        now = datetime.now(timezone.utc)
        cur = leaf
        intermediates = 0
        # Hard iteration bound also defends against a cycle in a malicious
        # bundle; _MAX_CHAIN_DEPTH + 2 is always enough for a legitimate chain.
        for _ in range(self._MAX_CHAIN_DEPTH + 2):
            if not self._not_expired(cur, now):
                return ZtaResult.set(ZtaStatus.EXPIRED, 'certificate has expired')
            issuer = self._store.get(cur.issuer.public_bytes())
            if issuer is None:
                return ZtaResult.set(ZtaStatus.REJECTED,
                                     'unable to get local issuer certificate')
            try:
                cur.verify_directly_issued_by(issuer)
            except Exception as err:
                return ZtaResult.set(ZtaStatus.REJECTED,
                                     'certificate signature failure: %s'
                                     % str(err)[:80])
            if issuer.subject.public_bytes() == issuer.issuer.public_bytes():
                # Reached a self-signed root anchor: chain complete.
                if intermediates > self._MAX_CHAIN_DEPTH:
                    return ZtaResult.set(ZtaStatus.REJECTED,
                                         'certificate chain too long')
                return ZtaResult.set(ZtaStatus.VERIFIED,
                                     'certificate chain verified')
            # issuer is an intermediate CA -> count it and keep walking.
            intermediates += 1
            if intermediates > self._MAX_CHAIN_DEPTH:
                return ZtaResult.set(ZtaStatus.REJECTED,
                                     'certificate chain too long')
            cur = issuer
        return ZtaResult.set(ZtaStatus.REJECTED, 'certificate chain too long')

    # -- vtable -----------------------------------------------------------

    def verify_credential(self, cred_data: Optional[bytes]) -> ZtaResult:
        if not cred_data:
            return ZtaResult.set(ZtaStatus.REJECTED, 'no credential data')
        x509 = self._ensure_x509()
        cert = self._parse_cert(x509, cred_data)
        if cert is None:
            return ZtaResult.set(ZtaStatus.REJECTED,
                                 'failed to parse X.509 certificate')
        cred_hash = hashlib.sha256(
            cert.public_bytes(self._der_encoding())).digest()
        # Expiry checked first, for a distinct status (mirrors C ordering).
        now = datetime.now(timezone.utc)
        if not self._not_expired(cert, now):
            return ZtaResult(status=ZtaStatus.EXPIRED,
                             reason='certificate has expired',
                             credential_hash=cred_hash)
        result = self._verify_chain(cert)
        result.credential_hash = cred_hash
        if result.status == ZtaStatus.VERIFIED:
            self._cert_cache[cred_hash] = cert
        return result

    def _der_encoding(self):
        from cryptography.hazmat.primitives.serialization import Encoding
        return Encoding.DER

    def check_revocation(self, cred_hash: bytes) -> ZtaResult:
        # CRL-based check, mirroring the C path (OCSP is best-effort / offline-
        # unavailable here; the admission gate calls only verify_credential).
        if self.crl_path:
            x509 = self._ensure_x509()
            try:
                with open(self.crl_path, 'rb') as fp:
                    crl = x509.load_pem_x509_crl(fp.read())
            except Exception:
                crl = None
            if crl is not None:
                cert = self._cert_cache.get(cred_hash)
                if cert is not None and crl.get_revoked_certificate_by_serial_number(
                        cert.serial_number) is not None:
                    return ZtaResult.set(ZtaStatus.REVOKED,
                                         'certificate revoked (CRL)', cred_hash)
                return ZtaResult.set(ZtaStatus.VERIFIED,
                                     'CRL loaded; not revoked', cred_hash)
        if self.ocsp_url:
            return ZtaResult.set(ZtaStatus.UNAVAILABLE,
                                 'OCSP responder unreachable', cred_hash)
        return ZtaResult.set(ZtaStatus.UNAVAILABLE,
                             'no revocation source configured', cred_hash)

    def is_available(self) -> bool:
        # Offline chain validation is available whenever a CA bundle is loaded.
        return len(self._store) > 0
