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
"""The ZTA credential binding: which node this credential authorizes, and the proof.

A chain-valid certificate says nothing about *who may present it*. That is the whole
of ISSUES §1.5: a credential lifted from another peer's clear-text `announce` chains
to the agency CA exactly as well under a different uuid, so the admission gate had
no way to tell holder from thief and fell back on first-use-wins (TOFU). TOFU is not
a weakness of ZTA; it is what is left when the credential↔identity binding is
*inferred* rather than *asserted*. Assert it and the ambiguity is gone.

Two mechanisms assert it, and this module implements both:

**Holder-asserted (the general case).** The credential's own private key signs

    ZTA_BINDING_TAG || uuid (16) || node signing key (32) || cred fingerprint (32)

Because the node is named inside the signed bytes, a harvested `(credential,
binding)` pair cannot be re-presented under another identity -- the signature simply
will not verify there, and the attacker cannot produce a fresh one without the
credential's private key. This needs **nothing from the issuer**, which is why it is
the mechanism that makes bridging foreign agency CAs possible at all: AT cannot ask
another agency to mint certificates on its terms, only to be presented by a holder
who can prove possession. Precedents for the shape: TLS 1.3 `CertificateVerify`,
DPoP (RFC 9449), ACME key authorization, WebAuthn.

**CA-asserted (stronger, where AT controls issuance).** The certificate itself names
the node in a URI SAN (`at://<uuid>` by default). The issuer vouches for the binding
at issuance, so there is nothing for the presenter to assert and no binding blob to
carry. Precedents: SPIFFE/SVID, IEEE 802.1AR IDevID, ordinary mTLS service identity.
`san_binds_identity` accepts this as an alternative proof, which is what keeps
`binding_mode: require` from being a flag day for credentials AT issues itself.

The two are not quite equal and the difference is worth stating rather than glossing.
The signature covers the uuid **and** the node's signing key; a SAN names only the
uuid. So a SAN match alone does not bind the key, and it leans on the existing Sybil
uuid/key-collision checks to stop a peer announcing a victim's uuid under its own
key. Both, however, fully close the §1.5 threat, which is a credential moving to a
*different* identity.

**Durable, not a live challenge-response.** There is no nonce, deliberately, and for
the same reason operator attestation is consumer-pull: a binding must verify offline
and through a relay under DDIL, with no round trip to the peer or the CA. A
nonce-free pre-image is replayable in *time*, which costs nothing here -- it
authorizes exactly one identity, forever, which is precisely what it is for.
Liveness is a separate question (see `operator-attended.md`) and belongs to
privileged operations, not admission.

Keep this byte-identical to the C twin (`identity.h::ZTA_BINDING_TAG` /
`identity.c::zta_binding_preimage`) when C parity lands. Two hand-written builders are
exactly the thing that drifts unnoticed, which is why a conformance vector pins the
bytes -- the same reasoning as `operator_binding.py`, whose shape this deliberately
mirrors so the two read alike.
"""
from __future__ import annotations

import hashlib
from typing import Optional
from uuid import UUID

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


def verify_zta_binding(identity, cred_der: bytes,
                       binding: Optional[bytes] = None) -> bool:
    """Whether the holder of `cred_der`'s private key authorized `identity` to
    present it.

    Answers only that one question. The caller must separately establish that the
    credential chains to a configured anchor and is unrevoked -- a binding by a
    credential that chains nowhere authorizes nothing.

    Returns False (never raises) for a missing or oversized binding, an empty or
    unparseable credential, an unusable uuid/signing key, or a signature that does
    not verify. Absence and forgery are deliberately *not* distinguished by the
    return value; they differ enormously in meaning, so the admission gate
    distinguishes them by asking `bool(binding)` itself (unbound is a provisioning
    state, a bad binding is evidence of forgery, and they get different verdicts).
    """
    sig = binding if binding is not None else getattr(
        identity, 'zta_credential_binding', b'') or b''
    if not sig or len(sig) > ZTA_BINDING_MAX:
        return False
    if not cred_der:
        return False
    try:
        pre = zta_binding_preimage(identity, cred_der)
    except (ValueError, AttributeError, TypeError):
        return False
    # Reuse the PIV challenge-response verifier: already generic over RSA/PKCS#1v15
    # and ECDSA and takes (cert, data, signature). Imported lazily, like the rest of
    # the `cryptography` uses in this tree, so a non-ZTA deployment does not need
    # the dependency at import time.
    from .zta.piv.piv_verifier import PivVerifier
    return PivVerifier._verify_signature(bytes(cred_der), pre, bytes(sig))


def san_binds_identity(cred_der: bytes, identity,
                       template: str = ZTA_SAN_URI_TEMPLATE) -> bool:
    """Whether `cred_der` itself names `identity` in a URI SAN -- the CA-asserted
    binding, accepted as an alternative to a holder-asserted signature.

    Matches the rendered `template` against every URI SAN entry, uuid compared
    case-insensitively (uuids are hex and canonically lower-case, but a CA that
    upper-cases one has not issued a different certificate). An empty template
    disables the check.

    Returns False (never raises) on an unparseable certificate, an absent SAN
    extension, an unusable uuid, or no match -- a certificate that cannot be read
    binds nothing.
    """
    if not cred_der or not template:
        return False
    try:
        uuid_str = str(UUID(str(getattr(identity, 'uuid', None))))
    except (ValueError, AttributeError, TypeError):
        return False
    try:
        expect = template.format(uuid=uuid_str).lower()
    except (KeyError, IndexError):
        return False
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
        cert = x509.load_der_x509_certificate(bytes(cred_der))
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    except Exception:
        return False
    return any((u or '').lower() == expect for u in uris)


def operator_binding_binds_identity(identity, cred_der: bytes,
                                    operator_pubkey: Optional[bytes] = None,
                                    binding: Optional[bytes] = None) -> bool:
    """Whether an *operator-key* binding also serves as this credential's binding.

    It does, and not by coincidence. `operator_binding.py`'s pre-image is

        OPERATOR_BINDING_TAG || uuid || node signing key || operator_pubkey

    signed by the **credential's** private key. The question this module asks -- did
    the credential's holder authorize this node to present it -- is answered by any
    signature from that key over bytes naming this node, and those bytes name it.
    A node that already carries a verifying operator-key binding has therefore
    already proven entitlement, and requiring a second signature would demand
    another operator session for nothing. (ISSUES §1.5 credits the operator binding
    with closing the replay case for exactly this reason.)

    Narrower than it looks, so worth being plain: it only helps a node that opted in
    to publishing a guardian key. Opting in is a persistent pseudonym linking that
    operator's nodes, which AT will not require, so most nodes will still need a
    credential binding of their own.

    Returns False (never raises) when either half of the claim is missing.
    """
    key = operator_pubkey if operator_pubkey is not None else getattr(
        identity, 'operator_pubkey', b'') or b''
    sig = binding if binding is not None else getattr(
        identity, 'operator_key_binding', b'') or b''
    if not key or not sig or not cred_der:
        return False
    from .operator_binding import verify_operator_binding
    return verify_operator_binding(identity, bytes(cred_der), bytes(key), bytes(sig))


def identity_is_bound(identity, cred_der: bytes, binding: Optional[bytes] = None,
                      san_template: str = ZTA_SAN_URI_TEMPLATE,
                      operator_pubkey: Optional[bytes] = None,
                      operator_key_binding: Optional[bytes] = None) -> bool:
    """Whether `cred_der` is bound to `identity` by *any* accepted mechanism.

    Ordered cheapest-and-strongest first: the holder-asserted signature covers the
    node's signing key as well as its uuid and is a single local verify; the SAN path
    parses the certificate again; the operator-key route parses it and builds a second
    pre-image, and applies only to a node that opted in to publishing a guardian key.

    The operator arguments are explicit because the admission gate clears
    ``identity.operator_pubkey`` on entry (the advertised claim is neutralized before
    anything is verified), so by the time this runs the peer's own copy is already
    gone and the caller must hand over what it moved aside.
    """
    if verify_zta_binding(identity, cred_der, binding):
        return True
    if san_binds_identity(cred_der, identity, san_template):
        return True
    return operator_binding_binds_identity(identity, cred_der, operator_pubkey,
                                           operator_key_binding)
