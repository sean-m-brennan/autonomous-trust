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
"""Multi-factor authentication chain over the ZTA `Verifier` interface.

`MfaChain` composes an ordered list of `Verifier`s and a policy combinator into
a single `Verifier`, so the existing admission gate
(`IdentityProcess._zta_admit`) and the `ZtaPolicy` factory consume it with no
change -- it *is* a `Verifier`.

This is a Python-only verifier: the operator console (PIV + MFA) is a Python
TUI/node, so there is no C parity requirement here. The C `zta_policy` parser
ignores unknown JSON keys and falls back to its null verifier for an
unrecognised `verifier_type`, so an ``mfa`` policy file is benign on the C side.

Combinator semantics (default AND), evaluated in factor order:
  * every factor must return VERIFIED for the chain to return VERIFIED;
  * the first factor returning a *hard failure* (REJECTED / EXPIRED / REVOKED)
    short-circuits the chain to that status -- no later factor is consulted;
  * a factor returning DEFERRED / UNAVAILABLE (e.g. DDIL: PKI unreachable) does
    not reject, but downgrades the chain result to DEFERRED so the higher
    layer's fail-safe DDIL handling (delegated/relayed validation, tier cap)
    can take over (see PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.4);
  * the combined `credential_hash` is always the **primary** (first) factor's
    hash, so identity binding stays stable across second-factor rotation
    (PIV cert is the primary factor; the TOTP/OIDC/FIDO2 second factor rotates).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from .zta_verifier import Verifier, ZtaResult, ZtaStatus

# Hard-failure statuses short-circuit an AND chain to that status, in order.
_HARD_FAIL = (ZtaStatus.REJECTED, ZtaStatus.EXPIRED, ZtaStatus.REVOKED)
# Statuses that mean "could not fully verify" rather than "is invalid".
_DEFER = (ZtaStatus.DEFERRED, ZtaStatus.UNAVAILABLE)

_MFA_MAGIC = b'MFA1'


class CombinePolicy(Enum):
    """How an `MfaChain` combines its factor results."""
    AND = 'and'   # all factors must verify (the only supported mode today)


@dataclass
class MfaCredential:
    """Composite multi-factor credential: one blob per chain factor, in order.

    Built at operator activation to carry every factor's credential together
    (e.g. the PIV challenge envelope as blob 0 + the TOTP code as blob 1). The
    ``MFA1`` magic prefix makes it unambiguously distinguishable from a bare
    X.509/PIV credential (a DER cert begins ``0x30 0x82...``; a PIV envelope
    begins with a length prefix) -- so a single `MfaChain` can serve both the
    composite activation path (all factors required) and the bare-cert
    peer-admission path (primary factors only). Local framing; never on the AT
    wire (peers only ever see the bare cert).
    """
    blobs: List[bytes]

    def pack(self) -> bytes:
        out = bytearray(_MFA_MAGIC)
        out += struct.pack('>I', len(self.blobs))
        for blob in self.blobs:
            out += struct.pack('>I', len(blob))
            out += blob
        return bytes(out)

    @staticmethod
    def unpack(data: Optional[bytes]) -> Optional['MfaCredential']:
        if (not data or len(data) < len(_MFA_MAGIC) + 4
                or data[:len(_MFA_MAGIC)] != _MFA_MAGIC):
            return None
        off = len(_MFA_MAGIC)
        blobs: List[bytes] = []
        try:
            (count,) = struct.unpack_from('>I', data, off)
            off += 4
            for _ in range(count):
                (length,) = struct.unpack_from('>I', data, off)
                off += 4
                if off + length > len(data):
                    return None
                blobs.append(data[off:off + length])
                off += length
        except struct.error:
            return None
        if off != len(data):
            return None
        return MfaCredential(blobs=blobs)


class MfaChain(Verifier):
    """An AND-combinator over an ordered list of `Verifier` factors.

    The first factor is the *primary* factor and supplies the combined
    credential hash for identity binding.
    """

    def __init__(self, factors: List[Verifier],
                 combine: CombinePolicy = CombinePolicy.AND):
        self.factors = list(factors)
        self.combine = combine

    # -- vtable -----------------------------------------------------------

    def verify_credential(self, cred_data: Optional[bytes]) -> ZtaResult:
        if not self.factors:
            return ZtaResult.set(ZtaStatus.REJECTED, 'no MFA factors configured')
        if self.combine is not CombinePolicy.AND:
            return ZtaResult.set(ZtaStatus.REJECTED,
                                 'unsupported MFA combine policy: %s'
                                 % self.combine)

        composite = MfaCredential.unpack(cred_data)
        if composite is not None:
            # Operator activation: one blob per factor, every factor required.
            if len(composite.blobs) != len(self.factors):
                return ZtaResult.set(
                    ZtaStatus.REJECTED,
                    'MFA credential carries %d blobs for %d factors'
                    % (len(composite.blobs), len(self.factors)))
            pairs = list(zip(self.factors, composite.blobs))
        else:
            # Bare credential (a peer's wire cert): only primary factors apply.
            # Secondary factors (TOTP/FIDO) need explicit operator interaction
            # and are skipped -- a peer can't and shouldn't supply one.
            pairs = [(f, cred_data) for f in self.factors
                     if not f.secondary_factor]
            if not pairs:
                return ZtaResult.set(ZtaStatus.REJECTED,
                                     'no primary factor for bare credential')
        return self._combine_and(pairs)

    def _combine_and(self, pairs) -> ZtaResult:
        """AND-combine (factor, blob) pairs; blob 0's factor is primary."""
        primary_hash = b''
        deferred = False
        deferred_reason = ''
        for idx, (factor, blob) in enumerate(pairs):
            result = factor.verify_credential(blob)
            if idx == 0:
                primary_hash = result.credential_hash
            if result.status in _HARD_FAIL:
                # Short-circuit: rebind to the primary hash so the rejected
                # identity is still identifiable for audit/binding.
                result.credential_hash = primary_hash or result.credential_hash
                return result
            if result.status in _DEFER:
                deferred = True
                deferred_reason = result.reason or str(result.status)

        if deferred:
            return ZtaResult(status=ZtaStatus.DEFERRED,
                             reason='factor verification deferred: %s'
                                    % deferred_reason,
                             credential_hash=primary_hash)
        return ZtaResult(status=ZtaStatus.VERIFIED,
                         reason='all %d factor(s) verified' % len(pairs),
                         credential_hash=primary_hash)

    def check_revocation(self, cred_hash: bytes) -> ZtaResult:
        """Delegate revocation to the primary factor (it owns the bound hash)."""
        if not self.factors:
            return ZtaResult.set(ZtaStatus.UNAVAILABLE,
                                 'no MFA factors configured', cred_hash)
        return self.factors[0].check_revocation(cred_hash)

    def is_available(self) -> bool:
        """Available only when every factor is available (AND)."""
        return bool(self.factors) and all(f.is_available() for f in self.factors)

    def credential_hash(self, cred_data: bytes) -> bytes:
        """Identity-binding hash = the primary factor's credential hash."""
        if not self.factors:
            return super().credential_hash(cred_data)
        composite = MfaCredential.unpack(cred_data)
        if composite is not None and composite.blobs:
            return self.factors[0].credential_hash(composite.blobs[0])
        return self.factors[0].credential_hash(cred_data)

    def destroy(self) -> None:
        for factor in self.factors:
            factor.destroy()
