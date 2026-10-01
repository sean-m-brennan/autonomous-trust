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
"""What the core keeps of ZTA (FEATURE_SPLIT_PLAN Phase 6, D3): the bounds on
the credential fields every Identity carries, and the binding pre-image a node
signs over its own credential. Pure bytes and hashing; no `cryptography`.

The fields exist in every build -- a node without ZTA carries and relays a
peer's credentials -- and only VERIFICATION is the ZTA extension's
(``autonomous_trust.zta``: the verifiers, the admission gate, binding
verification). The C twin keeps the same split: ``identity.h`` and
``identity.c::zta_binding_preimage`` in the core, the rest in ``libat_zta``.
"""
import hashlib
from uuid import UUID

#: The configuration section that turns ZTA on (``zta_policy.cfg.json``). Named
#: here so the core can refuse a node whose policy enables ZTA without the
#: extension (extensions.check_config) -- an absent feature cannot name itself.
ZTA_POLICY_SECTION = 'zta_policy'

ZTA_HASH_LEN = 32  # SHA-256

#: Hard cap on a ZTA credential blob carried on the wire. Real X.509 chains and
#: JWTs comfortably fit; a larger value almost certainly indicates a hostile or
#: corrupt input. Kept in lockstep with C `ZTA_CRED_MAX` (identity.h).
ZTA_CRED_MAX = 64 * 1024

#: Domain separation, versioned in the tag itself so a v2 pre-image can never be
#: verified as a v1 one. Distinct from OPERATOR_BINDING_TAG: that one binds the
#: *operator's* ed25519 key to the node (WHICH human), this one binds the
#: *credential* to the node (WHO may present it). A signature over one must never
#: verify as the other.
ZTA_BINDING_TAG = b'at-zta-binding-v1'

#: SHA-256 over the raw credential bytes. Recomputed from what arrived, never read
#: from the announcer-controlled `zta_credential_hash` -- the whole gate turns on
#: that distinction.
ZTA_FINGERPRINT_LEN = 32

#: Cap on a binding signature carried on the wire. RSA-4096 PKCS#1 is 512 bytes and
#: ECDSA P-384 DER well under 128, so this fits any credential an agency issues;
#: more is hostile or corrupt. Same value and reasoning as OPERATOR_BINDING_MAX.
ZTA_BINDING_MAX = 1024

#: Default URI SAN naming the node, `str.format`-ed with ``uuid``.
ZTA_SAN_URI_TEMPLATE = 'at://{uuid}'

ZTA_BINDING_PREIMAGE_LEN = len(ZTA_BINDING_TAG) + 16 + 32 + ZTA_FINGERPRINT_LEN


def _uuid_bytes(identity) -> bytes:
    """The node's uuid as the 16 raw bytes C binds (C holds a `uuid_t`; Python keeps
    the string form, so the two must agree here rather than at each caller)."""
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


def credential_fingerprint(cred_der: bytes) -> bytes:
    """SHA-256 over the credential's actual bytes."""
    return hashlib.sha256(bytes(cred_der)).digest()


def zta_binding_preimage(identity, cred_der: bytes) -> bytes:
    """Build the bytes a credential's private key signs to authorize `identity` to
    present it:

        ZTA_BINDING_TAG || uuid (16) || node signing key (32)
                        || credential fingerprint (32)

    Raises ValueError on an empty credential -- a caller that got that wrong must
    hear about it rather than produce a binding nothing can verify.
    """
    if not cred_der:
        raise ValueError('cannot bind an empty credential')
    pre = (ZTA_BINDING_TAG + _uuid_bytes(identity)
           + node_signing_pubkey(identity) + credential_fingerprint(cred_der))
    assert len(pre) == ZTA_BINDING_PREIMAGE_LEN
    return pre
