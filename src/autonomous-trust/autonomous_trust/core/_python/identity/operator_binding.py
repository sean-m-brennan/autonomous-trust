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
"""The operator-key binding: which human guards this node, and the proof.

`operator_bound` says a node has a human guardian and `operator_attested_at` says
when one was last verified present. Neither names the human, because the operator
credential is a PIV/CAC X.509 with no ed25519 key to become a `did:key` — so a
consumer that charters a node->guardian edge and wants that guardian to *co-sign*
(ethne D15) has nothing to point at.

A node MAY therefore advertise `operator_pubkey`, the guardian's ed25519 public
key, together with `operator_key_binding`: a signature by the operator's **PIV
private key** over the pre-image below. Verifying it needs only the operator
credential the node already carries, so any peer can check the claim offline, and
the claim chains to the distinct operator trust anchor exactly as `operator_bound`
does. A node signing its own operator key would prove nothing — the same reason
`operator-bound-lying-rejected` exists.

**Strictly opt-in, and absence costs nothing.** AT never requires a guardian
identity: a node that declines is admitted identically, keeps its anonymity, and
serializes byte-for-byte as it did before these fields existed. Requiring a
guardian is a *consumer's* rule. The reason to keep it optional is that publishing
one key per operator across that operator's nodes is a persistent pseudonym linking
them — a real cost, and not one AT may impose.

**The pre-image names the node**, which is what makes a guardian count mean
anything: without it, a `(key, binding)` pair lifted from another node's announce
would let any node claim that human. It also means node key rotation invalidates a
binding — re-binding is an operator act, and the failure mode is losing a guardian
edge, never losing admission.

Keep this byte-identical to C `identity.h::OPERATOR_BINDING_TAG` /
`identity.c::operator_binding_preimage`. Two hand-written builders are exactly the
thing that drifts unnoticed, which is why a conformance vector pins the bytes.
"""
from __future__ import annotations

from typing import Optional
from uuid import UUID

#: Domain separation, versioned in the tag itself so a v2 pre-image can never be
#: verified as a v1 one.
OPERATOR_BINDING_TAG = b'at-operator-binding-v1'

#: An ed25519 public key. A key of any other length is dropped whole rather than
#: padded or truncated: a truncated key is a different key.
OPERATOR_PUBKEY_LEN = 32

#: Cap on a binding signature carried on the wire. RSA-4096 PKCS#1 is 512 bytes
#: and ECDSA P-384 DER well under 128, so this fits every credential a PIV holds;
#: more is hostile or corrupt. Mirrors C OPERATOR_BINDING_MAX, and the same
#: reasoning as ZTA_CRED_MAX three orders of magnitude up.
OPERATOR_BINDING_MAX = 1024

OPERATOR_BINDING_PREIMAGE_LEN = len(OPERATOR_BINDING_TAG) + 16 + 32 + 32


def _uuid_bytes(identity) -> bytes:
    """The node's uuid as the 16 raw bytes C binds (C holds a `uuid_t`; Python
    keeps the string form, so the two must agree here rather than at the caller)."""
    u = getattr(identity, 'uuid', None)
    if isinstance(u, UUID):
        return u.bytes
    return UUID(str(u)).bytes


def node_signing_pubkey(identity) -> bytes:
    """The node's 32-byte ed25519 public signing key, raw.

    Not `signature.publish()`, which is the hex encoding carried on the wire as
    `Signature.hex_seed`; the binding covers the raw key, matching C
    `signature.public`.
    """
    return bytes(identity.signature.public)


def operator_binding_preimage(identity, operator_pubkey: bytes) -> bytes:
    """Build the bytes an operator's PIV signs to bind `operator_pubkey` to
    `identity`:

        OPERATOR_BINDING_TAG || uuid (16) || node signing key (32)
                             || operator_pubkey (32)

    Raises ValueError on a key of the wrong length — a caller that got that wrong
    must hear about it rather than produce a binding nothing can verify.
    """
    if len(operator_pubkey) != OPERATOR_PUBKEY_LEN:
        raise ValueError('operator_pubkey must be %d bytes, got %d'
                         % (OPERATOR_PUBKEY_LEN, len(operator_pubkey)))
    pre = (OPERATOR_BINDING_TAG + _uuid_bytes(identity)
           + node_signing_pubkey(identity) + bytes(operator_pubkey))
    assert len(pre) == OPERATOR_BINDING_PREIMAGE_LEN
    return pre


def verify_operator_binding(identity, cert_der: bytes,
                            operator_pubkey: Optional[bytes] = None,
                            binding: Optional[bytes] = None) -> bool:
    """Whether `identity`'s advertised guardian key is bound to it by the holder
    of `cert_der`'s private key.

    The caller must already have established that `cert_der` is **operator-class**
    (chains to the distinct operator anchor) — this answers only "did that
    credential's holder sign *this* node's key". Both are required: a chain without
    a binding names no human, and a binding whose credential is not operator-class
    is a human with no standing to name one.

    Returns False (never raises) for a missing key or binding, a wrong-length key,
    an oversized binding, or a signature that does not verify. Absence and forgery
    are distinguished by the *caller's* logging, not by the return value: for the
    guardian edge both mean "no guardian recorded".
    """
    key = operator_pubkey if operator_pubkey is not None else getattr(
        identity, 'operator_pubkey', b'') or b''
    sig = binding if binding is not None else getattr(
        identity, 'operator_key_binding', b'') or b''
    if len(key) != OPERATOR_PUBKEY_LEN:
        return False
    if not sig or len(sig) > OPERATOR_BINDING_MAX:
        return False
    if not cert_der:
        return False
    try:
        pre = operator_binding_preimage(identity, key)
    except (ValueError, AttributeError, TypeError):
        return False
    # Reuse the PIV challenge-response verifier: it is already generic over
    # RSA/PKCS#1v15 and ECDSA and takes (cert, data, signature). Imported lazily,
    # like the rest of the `cryptography` uses in this tree, so a non-ZTA
    # deployment does not need the dependency at import time.
    from .zta.piv.piv_verifier import PivVerifier
    return PivVerifier._verify_signature(cert_der, pre, sig)
