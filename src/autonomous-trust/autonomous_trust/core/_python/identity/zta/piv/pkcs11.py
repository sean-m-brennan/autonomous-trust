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
"""PKCS#11 token access for PIV/CAC smartcards (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.1).

A `PivToken` exposes the three operations the `PivVerifier` needs from a PIV
card, behind a tiny interface so the verifier never imports PKCS#11 directly:

  * `certificate_der()` -- the PIV **authentication** certificate (DER);
  * `sign(data)`        -- sign a server-issued challenge with the PIV auth
                           **private key** (PIN-unlocked; key never leaves the
                           card);
  * `is_present()`      -- whether the token/slot is currently readable (drives
                           card-removal session events, §3.4).

Two implementations:

  * `PyKcs11Token`   -- the real card, via **PyKCS11** (§6.5 decision). Lazy
                        import so the module loads without the binding present.
  * `SoftwareToken`  -- a `cryptography`-backed software token for dev/CI and
                        for SoftHSM2-less testing (plan §7 / §7.1 stage 1-2):
                        same challenge-response, zero hardware. The live card is
                        later just a swap of the module path + slot.

The PIV authentication key/cert live in **PIV slot 9A**, which OpenSC maps to
PKCS#11 object id ``0x01``; that is the default `PyKcs11Token` selects.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

# OpenSC's PKCS#11 object id for the PIV 9A "PIV Authentication" key/cert.
PIV_AUTH_CKA_ID = bytes([0x01])


class PivTokenError(Exception):
    """Raised when a PKCS#11 token operation fails (no token, bad PIN, etc.)."""


class PivToken(ABC):
    """Minimal PIV card interface used by `PivVerifier`."""

    @abstractmethod
    def certificate_der(self) -> bytes:
        """Return the PIV authentication certificate in DER encoding."""

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign ``data`` (a challenge nonce) with the PIV authentication key.

        The signature scheme is determined by the key type: RSA -> PKCS#1 v1.5
        over SHA-256; EC -> ECDSA over SHA-256. `PivVerifier` verifies with the
        scheme implied by the certificate's public key, so the two must agree.
        """

    def is_present(self) -> bool:
        """Whether the token/slot is currently present and readable."""
        return False

    def close(self) -> None:
        """Release the session and zeroize any PIN/secret state."""
        return None


class SoftwareToken(PivToken):
    """A software PIV token backed by `cryptography` (no hardware / PKCS#11).

    Holds a certificate and its matching private key in memory. Used for dev,
    CI, and the SoftHSM2-less test path; produces a signature byte-compatible
    with what `PivVerifier` expects from a real card (RSA PKCS#1 v1.5 / ECDSA,
    both over SHA-256).
    """

    def __init__(self, cert_der: bytes, private_key):
        self._cert_der = cert_der
        self._key = private_key
        self._present = True

    @classmethod
    def from_files(cls, cert_path: str, key_path: str,
                   key_password: Optional[bytes] = None) -> 'SoftwareToken':
        """Build a software token from a cert + private-key file (PEM or DER).

        The dev/CI activation hook (operator console ``--software-cert/-key``)
        and SoftHSM2-less tests use this to stand in for a PKCS#11 card -- plan
        §7.1 stage 1-2: same challenge-response, zero hardware.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import (
            load_der_private_key, load_pem_private_key)
        with open(cert_path, 'rb') as fp:
            cert_bytes = fp.read()
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes)
        except ValueError:
            cert = x509.load_der_x509_certificate(cert_bytes)
        with open(key_path, 'rb') as fp:
            key_bytes = fp.read()
        try:
            key = load_pem_private_key(key_bytes, password=key_password)
        except ValueError:
            key = load_der_private_key(key_bytes, password=key_password)
        from cryptography.hazmat.primitives.serialization import Encoding
        return cls(cert.public_bytes(Encoding.DER), key)

    def certificate_der(self) -> bytes:
        if not self._present:
            raise PivTokenError('software token removed')
        return self._cert_der

    def sign(self, data: bytes) -> bytes:
        if not self._present:
            raise PivTokenError('software token removed')
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        if isinstance(self._key, rsa.RSAPrivateKey):
            return self._key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            return self._key.sign(data, ec.ECDSA(hashes.SHA256()))
        raise PivTokenError('unsupported key type: %s' % type(self._key).__name__)

    def is_present(self) -> bool:
        return self._present

    def remove(self) -> None:
        """Test/dev hook: simulate card removal (see session lifecycle §3.4)."""
        self._present = False

    def close(self) -> None:
        self._key = None
        self._present = False


class PyKcs11Token(PivToken):
    """A real PIV/CAC token accessed through PyKCS11 (§6.5).

    PyKCS11 is imported lazily so this module -- and the rest of the ZTA package
    -- loads even where the binding or middleware is absent. Construction opens a
    read-only session, performs a user (PIN) login, and locates the auth cert +
    private key by `PIV_AUTH_CKA_ID`.
    """

    def __init__(self, module_path: str, pin: str,
                 slot: Optional[int] = None,
                 cka_id: bytes = PIV_AUTH_CKA_ID):
        self._module_path = module_path
        self._cka_id = cka_id
        self._pkcs11 = None
        self._session = None
        self._slot = slot
        self._cert_der: Optional[bytes] = None
        self._open(pin)

    def _load_lib(self):
        try:
            import PyKCS11  # lazy: only the real-card path needs the binding
        except ImportError as err:  # pragma: no cover - env-dependent
            raise PivTokenError(
                'PyKCS11 not installed; install it for live-card support '
                '(or use SoftwareToken for dev/test)') from err
        return PyKCS11

    def _open(self, pin: str) -> None:  # pragma: no cover - requires hardware
        pkcs11mod = self._load_lib()
        lib = pkcs11mod.PyKCS11Lib()
        try:
            lib.load(self._module_path)
        except pkcs11mod.PyKCS11Error as err:
            raise PivTokenError('failed to load PKCS#11 module %s: %s'
                                % (self._module_path, err)) from err
        slots = lib.getSlotList(tokenPresent=True)
        if not slots:
            raise PivTokenError('no PKCS#11 token present')
        slot = self._slot if self._slot is not None else slots[0]
        session = lib.openSession(slot, pkcs11mod.CKF_SERIAL_SESSION)
        try:
            session.login(pin)  # PIN unlocks the auth key; never persisted
        except pkcs11mod.PyKCS11Error as err:
            session.closeSession()
            raise PivTokenError('PIN login failed: %s' % err) from err
        self._pkcs11 = pkcs11mod
        self._session = session
        self._slot = slot
        self._cert_der = self._read_cert()

    def _read_cert(self) -> bytes:  # pragma: no cover - requires hardware
        pkcs11mod = self._pkcs11
        template = [(pkcs11mod.CKA_CLASS, pkcs11mod.CKO_CERTIFICATE),
                    (pkcs11mod.CKA_ID, self._cka_id)]
        objs = self._session.findObjects(template)
        if not objs:
            raise PivTokenError('PIV authentication certificate not found '
                                '(CKA_ID=%r)' % self._cka_id)
        value = self._session.getAttributeValue(objs[0], [pkcs11mod.CKA_VALUE])[0]
        return bytes(value)

    def certificate_der(self) -> bytes:  # pragma: no cover - requires hardware
        if self._cert_der is None:
            raise PivTokenError('token session not open')
        return self._cert_der

    def sign(self, data: bytes) -> bytes:  # pragma: no cover - requires hardware
        pkcs11mod = self._pkcs11
        if self._session is None:
            raise PivTokenError('token session not open')
        priv = self._session.findObjects([
            (pkcs11mod.CKA_CLASS, pkcs11mod.CKO_PRIVATE_KEY),
            (pkcs11mod.CKA_ID, self._cka_id)])
        if not priv:
            raise PivTokenError('PIV authentication private key not found')
        # Mechanism is chosen to match the cert's public key (RSA vs EC); the
        # *card* signs raw -- we hand it the pre-agreed SHA-256 mechanism.
        from cryptography.x509 import load_der_x509_certificate
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        pub = load_der_x509_certificate(self.certificate_der()).public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            mech = pkcs11mod.Mechanism(pkcs11mod.CKM_SHA256_RSA_PKCS, None)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            mech = pkcs11mod.Mechanism(pkcs11mod.CKM_ECDSA_SHA256, None)
        else:
            raise PivTokenError('unsupported PIV key type')
        sig = self._session.sign(priv[0], data, mech)
        sig = bytes(sig)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            sig = _ecdsa_raw_to_der(sig)
        return sig

    def is_present(self) -> bool:  # pragma: no cover - requires hardware
        if self._pkcs11 is None:
            return False
        try:
            lib = self._pkcs11.PyKCS11Lib()
            lib.load(self._module_path)
            return self._slot in lib.getSlotList(tokenPresent=True)
        except Exception:
            return False

    def close(self) -> None:  # pragma: no cover - requires hardware
        if self._session is not None:
            try:
                self._session.logout()
            except Exception:
                pass
            try:
                self._session.closeSession()
            except Exception:
                pass
        self._session = None
        self._cert_der = None


def _ecdsa_raw_to_der(raw: bytes) -> bytes:  # pragma: no cover - hardware path
    """Convert PKCS#11 raw r||s ECDSA output to the DER encoding pyca verifies."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    half = len(raw) // 2
    r = int.from_bytes(raw[:half], 'big')
    s = int.from_bytes(raw[half:], 'big')
    return encode_dss_signature(r, s)
