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
"""TOTP (RFC 6238) second factor for the operator console.

`TotpVerifier` is the recommended MFA second factor
(PIV_MFA_OPERATOR_ACCESS_PLAN.md §6.1): offline-capable (DDIL-friendly -- no IdP
round-trip), enrolled once at first activation. It is a **secondary factor**
(`secondary_factor = True`), so `MfaChain` consults it only when a composite
operator credential carries a code, and skips it on the bare-cert peer-admission
path (a peer neither has nor should present a TOTP code).

The shared secret is enrolled once (`generate_totp_secret` +
`totp_provisioning_uri` for an authenticator app) and stored in the operator's
``zta_policy`` TOTP factor config. NB: that secret sits in the local policy file
in plaintext; a production deployment would hold it in an OS keystore/TPM. The
PIV private key, by contrast, never leaves the card.

pyotp is imported lazily so the ZTA package loads where it is absent.
"""
from __future__ import annotations

from typing import Optional

from .zta_verifier import Verifier, ZtaResult, ZtaStatus


def generate_totp_secret() -> str:
    """Return a fresh base32 TOTP secret for enrollment."""
    import pyotp
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, account_name: str,
                          issuer: str = 'AutonomousTrust') -> str:
    """``otpauth://`` URI for enrolling the secret in an authenticator app."""
    import pyotp
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)


def totp_now(secret: str) -> str:
    """Current TOTP code for ``secret`` (test/CLI helper)."""
    import pyotp
    return pyotp.TOTP(secret).now()


class TotpVerifier(Verifier):
    """RFC 6238 TOTP second factor (pyotp-backed).

    ``valid_window`` permits +/- N 30s steps for clock skew (default 1).
    """

    secondary_factor = True

    def __init__(self, secret: str, valid_window: int = 1):
        self._secret = secret or ''
        self._valid_window = max(0, int(valid_window))

    def verify_credential(self, cred_data: Optional[bytes]) -> ZtaResult:
        if not self._secret:
            return ZtaResult.set(ZtaStatus.REJECTED, 'TOTP factor not enrolled')
        if not cred_data:
            return ZtaResult.set(ZtaStatus.REJECTED, 'no TOTP code presented')
        try:
            code = cred_data.decode('ascii').strip() if isinstance(
                cred_data, (bytes, bytearray)) else str(cred_data).strip()
        except Exception:
            return ZtaResult.set(ZtaStatus.REJECTED, 'malformed TOTP code')
        import pyotp
        if pyotp.TOTP(self._secret).verify(code, valid_window=self._valid_window):
            return ZtaResult.set(ZtaStatus.VERIFIED, 'TOTP code verified')
        return ZtaResult.set(ZtaStatus.REJECTED, 'invalid TOTP code')

    def is_available(self) -> bool:
        # TOTP is offline (no infrastructure); available whenever enrolled.
        return bool(self._secret)

    def credential_hash(self, cred_data: bytes) -> bytes:
        # A second factor contributes no identity binding; the primary (PIV)
        # factor owns the bound hash. Return empty so MfaChain uses the primary.
        return b''
