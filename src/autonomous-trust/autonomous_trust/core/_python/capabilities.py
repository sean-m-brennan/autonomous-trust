# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

from collections.abc import Mapping
import multiprocessing

from .config import Configuration
from autonomous_trust.core.protobuf.processes import capabilities_pb2

# Strict bounds on capability-descriptor fields received over the wire
# (caps_response). A descriptor is untrusted peer input, so cap every string
# and collection to keep a malicious or buggy peer from inflating memory /
# slowing parsing / overwhelming a UI. Oversized values are truncated/dropped
# rather than rejecting the whole descriptor (the name + required_tier still
# carry useful directory info). See PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.5/§8.
MAX_DESCRIPTION_LEN = 256
MAX_KIND_LEN = 32
MAX_ARG_SCHEMA_ENTRIES = 32
MAX_ARG_KEY_LEN = 64
MAX_ARG_VALUE_LEN = 64


def sanitize_descriptor(descriptor: dict) -> dict:
    """Clamp an untrusted capability descriptor to the size bounds above.

    Returns a new dict with only the recognized keys, each bounded. Unknown
    keys are dropped. ``name`` is intentionally not included (the caller keys
    by it).
    """
    clean: dict = {}
    if not isinstance(descriptor, dict):
        return clean
    rt = descriptor.get('required_tier')
    if isinstance(rt, bool):
        rt = None  # don't accept bools-as-ints
    if isinstance(rt, int):
        clean['required_tier'] = rt
    desc = descriptor.get('description')
    if isinstance(desc, str) and desc:
        clean['description'] = desc[:MAX_DESCRIPTION_LEN]
    kind = descriptor.get('kind')
    if isinstance(kind, str) and kind:
        clean['kind'] = kind[:MAX_KIND_LEN]
    schema = descriptor.get('arg_schema')
    if isinstance(schema, dict) and schema:
        bounded = {}
        for k, v in list(schema.items())[:MAX_ARG_SCHEMA_ENTRIES]:
            if not isinstance(k, str):
                continue
            bounded[k[:MAX_ARG_KEY_LEN]] = (
                v[:MAX_ARG_VALUE_LEN] if isinstance(v, str) else v)
        if bounded:
            clean['arg_schema'] = bounded
    return clean


# --- agora.profile (with-distance Increment 3) ------------------------------ #
# A profile is a small set of OPTIONAL, operator-set fields a node shares with
# admitted peers on request, over the signed peer_profile_query/response
# exchange (idprocess.py). Bounds are in BYTES (not codepoints) so the receiver's
# bound-check unit matches the signer's clamp unit across the Python and C
# runtimes. MUST stay in lockstep with C identity/profile.h (AT_PROFILE_MAX_*)
# and the app-boundary caps in app_events.h.
import re as _re
from nacl.signing import SigningKey as _SigningKey, VerifyKey as _VerifyKey

PROFILE_MAX_DISPLAY_NAME = 64
PROFILE_MAX_HANDLE = 32
PROFILE_MAX_BIO = 256
PROFILE_MAX_AVATAR_REF = 128
PROFILE_MAX_LINK = 128
PROFILE_MAX_LINKS = 4
_PROFILE_HANDLE_RE = _re.compile(r'^[A-Za-z0-9_.\-]*$')
# Fixed field order — load-bearing for the canonical signing bytes below.
_PROFILE_STR_FIELDS = (
    ('display_name', PROFILE_MAX_DISPLAY_NAME),
    ('handle', PROFILE_MAX_HANDLE),
    ('bio', PROFILE_MAX_BIO),
    ('avatar_ref', PROFILE_MAX_AVATAR_REF),
)


def _clamp_bytes(s: str, bound: int) -> str:
    """Truncate `s` to at most `bound` UTF-8 bytes without splitting a char."""
    b = s.encode('utf-8')
    if len(b) <= bound:
        return s
    return b[:bound].decode('utf-8', 'ignore')


def _has_control(s: str) -> bool:
    """ASCII control chars (< 0x20) are forbidden in profile fields — unbounded,
    their JSON escaping would inflate the fixed app-boundary buffer. Mirrors C
    has_control_chars in identity/profile.c."""
    return any(ord(c) < 0x20 for c in s)


def sanitize_profile(profile: dict) -> dict:
    """Clamp an operator-set profile to the byte bounds above (SIGNER side).

    Returns a new dict with only the recognized, non-empty fields, each
    truncated (UTF-8-safe) to its bound; a `handle` with any char outside
    [A-Za-z0-9_.-] is dropped; `links` is capped to PROFILE_MAX_LINKS entries
    each clamped to PROFILE_MAX_LINK bytes. Mirrors C at_profile_from_json
    (validate=false).
    """
    clean: dict = {}
    if not isinstance(profile, dict):
        return clean
    for key, bound in _PROFILE_STR_FIELDS:
        v = profile.get(key)
        if isinstance(v, str) and v:
            v = _clamp_bytes(v, bound)
            if _has_control(v):
                continue  # drop a field with control chars, keep the rest
            if key == 'handle' and not _PROFILE_HANDLE_RE.match(v):
                continue  # drop a bad-charset handle, keep the rest
            if v:
                clean[key] = v
    links = profile.get('links')
    if isinstance(links, list) and links:
        out = []
        for item in links:
            if len(out) >= PROFILE_MAX_LINKS:
                break
            if isinstance(item, str) and item:
                clamped = _clamp_bytes(item, PROFILE_MAX_LINK)
                if not _has_control(clamped):
                    out.append(clamped)
        if out:
            clean['links'] = out
    return clean


def profile_valid_bounded(profile: dict) -> bool:
    """True iff every present field is within its byte bound, `handle` is
    charset-clean, and links count/length are within bounds (RECEIVE side —
    a misbehaving peer's over-bound profile is rejected, like an invalid
    geohash). Mirrors C at_profile_from_json (validate=true) acceptance.
    """
    if not isinstance(profile, dict):
        return False
    for key, bound in _PROFILE_STR_FIELDS:
        v = profile.get(key)
        if v is None:
            continue
        if not isinstance(v, str) or len(v.encode('utf-8')) > bound:
            return False
        if _has_control(v):
            return False
        if key == 'handle' and v and not _PROFILE_HANDLE_RE.match(v):
            return False
    links = profile.get('links')
    if links is not None:
        if not isinstance(links, list) or len(links) > PROFILE_MAX_LINKS:
            return False
        for item in links:
            if not isinstance(item, str) or len(item.encode('utf-8')) > PROFILE_MAX_LINK:
                return False
            if _has_control(item):
                return False
    return True


import uuid as _uuidmod


def _uuid16(u) -> bytes:
    """Normalize a uuid (str / uuid.UUID / 16 raw bytes) to the same 16-byte
    form C signs over (uuid_t). Identity.uuid is a STRING in this runtime, so
    callers pass it directly and this converts to UUID(...).bytes — byte-for-byte
    identical to libuuid's uuid_t and to a raw-bytes vector."""
    if isinstance(u, (bytes, bytearray)):
        return bytes(u[:16])
    if isinstance(u, _uuidmod.UUID):
        return u.bytes
    return _uuidmod.UUID(str(u)).bytes


def _u32le(n: int) -> bytes:
    return int(n).to_bytes(4, 'little')


def _canon_field(s) -> bytes:
    b = s.encode('utf-8') if isinstance(s, str) else b''
    return _u32le(len(b)) + b


def profile_canonical(uuid_bytes: bytes, profile: dict) -> bytes:
    """THE cross-language signing contract (see C identity/profile.h):
      signer_uuid[16] || field(display_name) || field(handle) || field(bio)
      || field(avatar_ref) || u32le(num_links) || field(link)*
    where field(s) = u32le(byte_len) || utf8_bytes. Absent field => len 0.
    Built from the profile's values AS-IS so a receiver reproduces the signer's
    bytes exactly. MUST stay byte-identical to C at_profile_canonical.
    """
    out = bytearray(_uuid16(uuid_bytes))
    for key, _bound in _PROFILE_STR_FIELDS:
        out += _canon_field(profile.get(key, ''))
    links = profile.get('links') or []
    if not isinstance(links, list):
        links = []
    out += _u32le(len(links))
    for item in links:
        out += _canon_field(item)
    return bytes(out)


def profile_sign(signing_key: '_SigningKey', uuid_bytes: bytes, profile: dict) -> str:
    """Detached Ed25519 signature over profile_canonical, lowercase hex."""
    sig = signing_key.sign(profile_canonical(uuid_bytes, profile)).signature
    return sig.hex()


def profile_verify(verify_key: '_VerifyKey', uuid_bytes: bytes, profile: dict,
                   sig_hex: str) -> bool:
    """Verify a detached signature (lowercase hex) over profile_canonical."""
    try:
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64:
        return False
    from nacl.exceptions import BadSignatureError
    try:
        verify_key.verify(profile_canonical(uuid_bytes, profile), sig)
        return True
    except BadSignatureError:
        return False


# --- explicit connections (with-distance Increment 5) ----------------------- #
# A connection is an EXPLICIT, revocable, bilateral edge kept SEPARATE from
# reputation. Edge states (this node's local viewpoint): none=0, pending_out=1,
# pending_in=2, connected=3, declined=4. Only the RESPONSE is signed — it carries
# a detached Ed25519 signature over the canonical (requester, accepter, decision,
# seq) form, so the requester verifies it against the accepter's signing key
# before acting. MUST stay byte-identical to C at_connection_canonical.
CONN_NONE = 0
CONN_PENDING_OUT = 1
CONN_PENDING_IN = 2
CONN_CONNECTED = 3
CONN_DECLINED = 4


# Direct message body bound (Increment 6). MUST match C AT_DM_TEXT_LEN
# (msg_types.h) / AT_DM_TEXT_MAX (identity/dm.h) and AT_APP_DM_TEXT_LEN
# (app_events.h). A DM carries NO signature (crypto_box authenticates the
# sender), so there is no canonical form here — only the body bound.
DM_TEXT_MAX = 1024


def bound_dm_text(text: str) -> str:
    """Truncate a DM body to DM_TEXT_MAX UTF-8 bytes. Twin of C
    at_dm_bound_text (the app-boundary buffer clamp)."""
    if not isinstance(text, str):
        return ''
    return _clamp_bytes(text, DM_TEXT_MAX)


def connection_canonical(requester_uuid, accepter_uuid, decision: int,
                         seq: int) -> bytes:
    """THE cross-language signing contract (see C identity/connection.h):
      requester_uuid[16] || accepter_uuid[16] || u8(decision) || u64le(seq)
    where decision = 1 (accept) or 0 (decline). MUST stay byte-identical to C
    at_connection_canonical."""
    out = bytearray(_uuid16(requester_uuid))
    out += _uuid16(accepter_uuid)
    out += bytes((1 if decision else 0,))
    out += int(seq).to_bytes(8, 'little')
    return bytes(out)


def connection_sign(signing_key: '_SigningKey', requester_uuid, accepter_uuid,
                    decision: int, seq: int) -> str:
    """Detached Ed25519 signature over connection_canonical, lowercase hex."""
    sig = signing_key.sign(
        connection_canonical(requester_uuid, accepter_uuid, decision, seq)
    ).signature
    return sig.hex()


def connection_verify(verify_key: '_VerifyKey', requester_uuid, accepter_uuid,
                      decision: int, seq: int, sig_hex: str) -> bool:
    """Verify a detached signature (lowercase hex) over connection_canonical."""
    try:
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64:
        return False
    from nacl.exceptions import BadSignatureError
    try:
        verify_key.verify(
            connection_canonical(requester_uuid, accepter_uuid, decision, seq),
            sig)
        return True
    except BadSignatureError:
        return False


# --- feed posts (with-distance Increment 7) --------------------------------- #
# A post is a signed, content-addressed feed item distributed by encrypted group
# multicast and gossip-forwarded a bounded number of hops. UNLIKE a DM, whose
# crypto_box envelope authenticates the sender, a post is relayed by peers other
# than its author, so authorship comes from a detached Ed25519 signature over the
# canonical (author, seq, ts, required_tier, body) form — verified before acting.
# The blake2b-256 of the canonical is the content id (dedup/merge key). MUST stay
# byte-identical to C identity/post.c (at_post_canonical / at_post_content_id).
import struct as _struct

# Post body bound (bytes). MUST match C AT_POST_BODY_LEN / AT_POST_BODY_MAX and
# AT_APP_POST_BODY_LEN.
POST_BODY_MAX = 4096
# Content id length (blake2b-256 lowercase hex). MUST match C AT_POST_ID_LEN.
POST_ID_HEX_LEN = 64
# Feed gossip reach: highest hop_count a post carries on the wire (active network
# + one hop). MUST match C POST_MAX_HOPS.
POST_MAX_HOPS = 1
POST_TIER_MIN = 0
POST_TIER_MAX = 4


def bound_post_body(text: str) -> str:
    """Truncate a post body to POST_BODY_MAX UTF-8 bytes. Twin of C
    at_post_bound_body (the app-boundary buffer clamp)."""
    if not isinstance(text, str):
        return ''
    return _clamp_bytes(text, POST_BODY_MAX)


def post_canonical(author_uuid, seq: int, ts: float, required_tier: int,
                   body: str) -> bytes:
    """THE cross-language signing/hash contract (see C identity/post.h):
      author_uuid[16] || u64le(seq) || f64le(ts) || u8(required_tier)
      || u32le(body_len) || utf8_body
    where ts is the raw IEEE-754 little-endian double (struct '<d'). The body is
    bound-truncated first, so the canonical matches what crosses the wire. MUST
    stay byte-identical to C at_post_canonical."""
    out = bytearray(_uuid16(author_uuid))
    out += int(seq).to_bytes(8, 'little')
    out += _struct.pack('<d', float(ts))
    out += bytes((int(required_tier) & 0xFF,))
    b = bound_post_body(body).encode('utf-8')
    out += _u32le(len(b))
    out += b
    return bytes(out)


def post_content_id(author_uuid, seq: int, ts: float, required_tier: int,
                    body: str) -> str:
    """blake2b-256 of the canonical bytes, lowercase hex (POST_ID_HEX_LEN chars).
    Same primitive as libsodium crypto_generichash (BLAKE2b-256). Twin of C
    at_post_content_id."""
    import hashlib
    return hashlib.blake2b(
        post_canonical(author_uuid, seq, ts, required_tier, body),
        digest_size=32).hexdigest()


# --- business ads (Phase 3 P3.2, "businesses near me") ---------------------- #
# A business ad carries one business page — an opaque, SELF-VERIFYING Ethne
# bundle — together with the signed statement of the node advertising it.
#
# THE STRUCTURAL DIFFERENCE FROM A POST: a post is relayed by any peer and so
# carries a hop count. A business ad is NEVER relayed. Only a CUSTOMER carries a
# business's page, and a customer does not forward someone else's ad — it
# RE-ADVERTISES from its own cache, in the first person, with its own key and its
# own satisfaction. A business's reach is therefore exactly the sum of its
# customers' voices, and distribution and reputation are the same fact.
#
# TWO TRUST LAYERS meet and must not be confused: this canonical is the AT layer
# (who vouched, how happy, for which exact page bytes). The Ethne layer — the
# bundle proving polity-root -> envoy -> page — is OPAQUE to the runtime and is
# verified by the app. MUST stay byte-identical to C identity/business_ad.c
# (at_business_ad_canonical / at_business_ad_content_id).

# Opaque Ethne page-bundle bound (bytes). MUST match C AT_BUSINESS_BUNDLE_MAX /
# AT_BUSINESS_BUNDLE_LEN / AT_APP_BUSINESS_BUNDLE_LEN.
BUSINESS_BUNDLE_MAX = 3072
# Polity DID bound (bytes). MUST match C AT_BUSINESS_DID_MAX / AT_BUSINESS_DID_LEN.
BUSINESS_DID_MAX = 95
# Ad content id length (blake2b-256 lowercase hex). MUST match C
# AT_BUSINESS_AD_ID_HEX_LEN / AT_BUSINESS_AD_ID_LEN.
BUSINESS_AD_ID_HEX_LEN = 64
# Declarable customer satisfaction range.
BUSINESS_SAT_MIN = 0
BUSINESS_SAT_MAX = 4
# A business advertising its OWN page rather than a customer rating it. Excluded
# from the vouch term app-side, because self-vouching is free.
BUSINESS_SAT_SELF = 0xFF


def bound_business_bundle(text: str) -> str:
    """Truncate an Ethne page bundle to BUSINESS_BUNDLE_MAX UTF-8 bytes. Twin of
    C at_business_bound_bundle."""
    if not isinstance(text, str):
        return ''
    return _clamp_bytes(text, BUSINESS_BUNDLE_MAX)


def bound_business_did(text: str) -> str:
    """Truncate a polity DID to BUSINESS_DID_MAX UTF-8 bytes. Twin of C
    at_business_bound_did."""
    if not isinstance(text, str):
        return ''
    return _clamp_bytes(text, BUSINESS_DID_MAX)


def business_sat_valid(sat: int) -> bool:
    """True iff sat is a declarable customer satisfaction (0..4) or the
    business's own BUSINESS_SAT_SELF marker. Twin of C at_business_sat_valid."""
    try:
        sat = int(sat)
    except (ValueError, TypeError):
        return False
    return sat == BUSINESS_SAT_SELF or BUSINESS_SAT_MIN <= sat <= BUSINESS_SAT_MAX


def business_ad_canonical(advertiser_uuid, polity_did: str, satisfaction: int,
                          page_seq: int, ts: float, bundle: str) -> bytes:
    """THE cross-language signing/hash contract (see C identity/business_ad.h):
      advertiser_uuid[16] || u32le(did_len) || did || u8(satisfaction)
      || u64le(page_seq) || f64le(ts) || u32le(bundle_len) || utf8_bundle
    where ts is the raw IEEE-754 little-endian double (struct '<d'). The did and
    bundle are bound-truncated first, so the canonical matches what crosses the
    wire. Because the bundle BYTES are inside the canonical, an endorsement
    cannot be lifted off one page and re-attached to another. MUST stay
    byte-identical to C at_business_ad_canonical."""
    out = bytearray(_uuid16(advertiser_uuid))
    d = bound_business_did(polity_did).encode('utf-8')
    out += _u32le(len(d))
    out += d
    out += bytes((int(satisfaction) & 0xFF,))
    out += int(page_seq).to_bytes(8, 'little')
    out += _struct.pack('<d', float(ts))
    b = bound_business_bundle(bundle).encode('utf-8')
    out += _u32le(len(b))
    out += b
    return bytes(out)


def business_ad_id(advertiser_uuid, polity_did: str, satisfaction: int,
                   page_seq: int, ts: float, bundle: str) -> str:
    """blake2b-256 of the canonical bytes, lowercase hex
    (BUSINESS_AD_ID_HEX_LEN chars) — the dedup/merge key, and what forecloses
    replay. Twin of C at_business_ad_content_id."""
    import hashlib
    return hashlib.blake2b(
        business_ad_canonical(advertiser_uuid, polity_did, satisfaction,
                              page_seq, ts, bundle),
        digest_size=32).hexdigest()


def business_ad_sign(signing_key: '_SigningKey', advertiser_uuid,
                     polity_did: str, satisfaction: int, page_seq: int,
                     ts: float, bundle: str) -> str:
    """Detached Ed25519 signature over business_ad_canonical, lowercase hex."""
    sig = signing_key.sign(
        business_ad_canonical(advertiser_uuid, polity_did, satisfaction,
                              page_seq, ts, bundle)).signature
    return sig.hex()


def business_ad_verify(verify_key: '_VerifyKey', advertiser_uuid,
                       polity_did: str, satisfaction: int, page_seq: int,
                       ts: float, bundle: str, sig_hex: str) -> bool:
    """Verify a detached signature (lowercase hex) over business_ad_canonical."""
    try:
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64:
        return False
    from nacl.exceptions import BadSignatureError
    try:
        verify_key.verify(
            business_ad_canonical(advertiser_uuid, polity_did, satisfaction,
                                  page_seq, ts, bundle), sig)
        return True
    except BadSignatureError:
        return False


# --- business posts (Phase 3 P3.4, "the polity speaking, in the feed") ------ #
# A page is what the business IS; a post is what it SAYS. The post carries an
# opaque, SELF-VERIFYING Ethne {post,delegation} bundle — the ENVOY's signature
# over the body, plus the polity-root-signed delegation that proves the signer
# is the envoy — together with the signed statement of whoever put those bytes
# on the wire.
#
# THE STRUCTURAL DIFFERENCE FROM AN AD: a post IS relayed, and so carries a hop
# count, because its authority comes from inside the bundle rather than from who
# passed it along. Nobody can launder a post by relaying it, and nobody can
# alter a word of one without breaking two signatures at once. An ad, being a
# first-person recommendation, is re-advertised instead and has no hops.
#
# HOPS ARE NOT IN THE CANONICAL, exactly as for a feed post: a relay increments
# them, and signing over them would invalidate the signature at the first
# forward. MUST stay byte-identical to C identity/business_post.c
# (at_business_post_canonical / at_business_post_content_id).

# Opaque Ethne {post,delegation} bundle bound (bytes). LARGER than the page
# bundle's 3072 because the body rides inside it; MEASURED worst case 3550 (see
# ethne_ffi's the_worst_case_post_bundle_fits_the_wire_bound). MUST match C
# AT_BUSINESS_POST_BUNDLE_MAX / AT_BUSINESS_POST_BUNDLE_LEN /
# AT_APP_BUSINESS_POST_BUNDLE_LEN.
BUSINESS_POST_BUNDLE_MAX = 4096
# Post content id length (blake2b-256 lowercase hex). MUST match C
# AT_BUSINESS_POST_ID_HEX_LEN / AT_BUSINESS_POST_ID_LEN.
BUSINESS_POST_ID_HEX_LEN = 64
# Relay bound. A business post travels the same "active network + one hop" the
# feed does — how far anything travels on this channel is not a statement about
# who said it. MUST match C POST_MAX_HOPS.
BUSINESS_POST_MAX_HOPS = POST_MAX_HOPS


def bound_business_post_bundle(text: str) -> str:
    """Truncate an Ethne post bundle to BUSINESS_POST_BUNDLE_MAX UTF-8 bytes.
    Twin of C at_business_post_bound_bundle."""
    if not isinstance(text, str):
        return ''
    return _clamp_bytes(text, BUSINESS_POST_BUNDLE_MAX)


def business_post_canonical(author_uuid, polity_did: str, seq: int, ts: float,
                            bundle: str) -> bytes:
    """THE cross-language signing/hash contract (see C identity/business_post.h):
      author_uuid[16] || u32le(did_len) || did || u64le(seq) || f64le(ts)
      || u32le(bundle_len) || utf8_bundle
    where ts is the raw IEEE-754 little-endian double (struct '<d'). NO HOP
    BYTE — see the section note. The did and bundle are bound-truncated first,
    so the canonical matches what crosses the wire. MUST stay byte-identical to
    C at_business_post_canonical."""
    out = bytearray(_uuid16(author_uuid))
    d = bound_business_did(polity_did).encode('utf-8')
    out += _u32le(len(d))
    out += d
    out += int(seq).to_bytes(8, 'little')
    out += _struct.pack('<d', float(ts))
    b = bound_business_post_bundle(bundle).encode('utf-8')
    out += _u32le(len(b))
    out += b
    return bytes(out)


def business_post_id(author_uuid, polity_did: str, seq: int, ts: float,
                     bundle: str) -> str:
    """blake2b-256 of the canonical bytes, lowercase hex
    (BUSINESS_POST_ID_HEX_LEN chars) — the dedup key that makes gossip converge
    instead of echoing, and what forecloses replay. Twin of C
    at_business_post_content_id."""
    import hashlib
    return hashlib.blake2b(
        business_post_canonical(author_uuid, polity_did, seq, ts, bundle),
        digest_size=32).hexdigest()


def business_post_sign(signing_key: '_SigningKey', author_uuid,
                       polity_did: str, seq: int, ts: float,
                       bundle: str) -> str:
    """Detached Ed25519 signature over business_post_canonical, lowercase hex.
    This signs WHO SENT THIS COPY, not who may speak for the business — a relay
    re-signs what it forwards, and the envoy signature inside the bundle is
    untouched by either of them."""
    sig = signing_key.sign(
        business_post_canonical(author_uuid, polity_did, seq, ts,
                                bundle)).signature
    return sig.hex()


def business_post_verify(verify_key: '_VerifyKey', author_uuid,
                         polity_did: str, seq: int, ts: float, bundle: str,
                         sig_hex: str) -> bool:
    """Verify a detached signature (lowercase hex) over
    business_post_canonical."""
    try:
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64:
        return False
    from nacl.exceptions import BadSignatureError
    try:
        verify_key.verify(
            business_post_canonical(author_uuid, polity_did, seq, ts, bundle),
            sig)
        return True
    except BadSignatureError:
        return False


# --- detached co-signing (Phase 3 P3.3) ------------------------------------- #
# A staff roll act — admitting, expelling, designating a machine, moving or
# releasing its guardian — is decided by several people who are not at the same
# keyboard. The record travels; the KEYS DO NOT. One node exports the canonical
# bytes, every required signer signs those bytes on its own node, and the
# authoring node reassembles the signatures onto the payload.
#
# Both messages are directed and ENCRYPTED, like a DM: crypto_box authenticates
# each end, so neither carries a signature of its own and neither has a canonical
# byte form. There is therefore NO signing contract here — only the bounds and
# the shape checks, which MUST stay identical to C identity/cosign.c
# (at_cosign_bound / at_cosign_bytes_ok / at_cosign_op_ok / the two
# to_json/from_json pairs), because a message one runtime builds is parsed by the
# other.
#
# `bytes` is opaque Ethne canonical CBOR carried as hex. This runtime holds no
# Ethne and cannot tell what it means, exactly as it cannot read a business page
# bundle. What it does is bound and shape-check, so a malformed ask is refused
# here rather than surfacing as a payload that reproduces to nothing.
#
# WHAT DELIBERATELY DOES NOT CROSS: THE DESCRIPTION. The wording of what a record
# commits to is derived on the SIGNER's node from the bytes it is about to sign.
# If the asking node supplied the sentence as well as the payload it would choose
# both what you sign and what you are told you are signing — a friendly wording
# over hostile bytes, with a real signature on the end. That is the exact failure
# the detached seam exists to prevent, moved one layer up, so it is never carried
# and there is no field for it.

# Max hex characters of the exported canonical bytes. MUST match C
# AT_COSIGN_BYTES_MAX (identity/cosign.h), AT_COSIGN_BYTES_LEN (msg_types.h),
# AT_APP_COSIGN_BYTES_LEN (app_events.h), COSIGN_BYTES_HEX_MAX in the agora
# ethne_ffi crate and AGORA_COSIGN_BYTES_MAX in the shim / cohort ctypes.
COSIGN_BYTES_MAX = 6144
# Polity DID / signer did:key bound (bytes). MUST match C AT_COSIGN_DID_MAX.
COSIGN_DID_MAX = 95
# Exchange content id as Ethne prints it: "b3:" + 64 lowercase hex.
COSIGN_CID_MAX = 67
# An Ed25519 signature as lowercase hex (64 bytes -> 128 chars).
COSIGN_SIG_MAX = 128
# A record-class or op token ("membership", "guardian", "designate", ...).
COSIGN_TOKEN_MAX = 15

# The exchanges this build understands. A voluntary departure is self-signed by
# the one person leaving, so it is never exchanged and is deliberately absent.
COSIGN_OPS = {
    'membership': ('admit', 'expel'),
    'guardian': ('designate', 'rotate', 'release'),
}

_COSIGN_HEX = frozenset('0123456789abcdef')


def cosign_bound(value, bound: int) -> str:
    """Truncate one co-signing field to ``bound`` UTF-8 bytes. Twin of C
    ``at_cosign_bound`` (the app-boundary buffer clamp); a non-string — the C
    NULL case — yields ''."""
    if not isinstance(value, str):
        return ''
    return _clamp_bytes(value, bound)


def cosign_bytes_ok(value) -> bool:
    """Whether ``value`` is a plausible exported payload: non-empty, at most
    COSIGN_BYTES_MAX characters, an EVEN number of them, and all lowercase hex.
    An odd or non-hex string never came from an exporter, and a truncated one
    reproduces to nothing, so both are refused rather than carried. Twin of C
    ``at_cosign_bytes_ok``."""
    if not isinstance(value, str):
        return False
    n = len(value)
    if n == 0 or n > COSIGN_BYTES_MAX or (n % 2) != 0:
        return False
    return all(c in _COSIGN_HEX for c in value)


def cosign_op_ok(record, op) -> bool:
    """Whether (``record``, ``op``) name an exchange this build understands.
    Twin of C ``at_cosign_op_ok``."""
    if not isinstance(record, str) or not isinstance(op, str):
        return False
    return op in COSIGN_OPS.get(record, ())


def cosign_request_to_json(record, op, polity, cid, bytes_hex, seq: int,
                           ts: float):
    """The peer_cosign_request body {record, op, polity, cid, bytes, seq, ts},
    each field bound-truncated, or None when the op is unknown, the payload is
    not well formed, or the cid is empty. Twin of C
    ``at_cosign_request_to_json``."""
    r = cosign_bound(record, COSIGN_TOKEN_MAX)
    o = cosign_bound(op, COSIGN_TOKEN_MAX)
    p = cosign_bound(polity, COSIGN_DID_MAX)
    c = cosign_bound(cid, COSIGN_CID_MAX)
    if not cosign_op_ok(r, o) or not cosign_bytes_ok(bytes_hex) or not c:
        return None
    return {'record': r, 'op': o, 'polity': p, 'cid': c, 'bytes': bytes_hex,
            'seq': int(seq), 'ts': float(ts)}


def cosign_request_from_json(body):
    """Parse a peer_cosign_request body. Returns the same dict shape as
    ``cosign_request_to_json`` (fields bound-truncated) or None on a malformed
    payload: a missing or mistyped field, an unknown (record, op), bytes no
    exporter produced, or an empty cid. Unknown keys are ignored. Twin of C
    ``at_cosign_request_from_json``."""
    if not isinstance(body, dict):
        return None
    record = body.get('record')
    op = body.get('op')
    polity = body.get('polity')
    cid = body.get('cid')
    bytes_hex = body.get('bytes')
    seq = body.get('seq')
    ts = body.get('ts')
    if not isinstance(record, str) or not isinstance(op, str) \
            or not isinstance(polity, str) or not isinstance(cid, str) \
            or not isinstance(bytes_hex, str):
        return None
    # bool is an int subclass in Python; C's json_is_integer would refuse the
    # JSON `true` that produces it, so refuse it here too.
    if not isinstance(seq, int) or isinstance(seq, bool):
        return None
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return None
    # Shape-checked here rather than only app-side: an unknown op or a payload
    # that is not even hex cannot become a record anywhere downstream, and the
    # app should not have to distinguish a hostile ask from a truncated one.
    if not cosign_op_ok(record, op) or not cosign_bytes_ok(bytes_hex) or not cid:
        return None
    return {'record': cosign_bound(record, COSIGN_TOKEN_MAX),
            'op': cosign_bound(op, COSIGN_TOKEN_MAX),
            'polity': cosign_bound(polity, COSIGN_DID_MAX),
            'cid': cosign_bound(cid, COSIGN_CID_MAX),
            'bytes': cosign_bound(bytes_hex, COSIGN_BYTES_MAX),
            'seq': int(seq), 'ts': float(ts)}


def cosign_sig_to_json(cid, signer, sig, seq: int, ts: float):
    """The peer_cosign_sig body {cid, signer, sig, seq, ts}, or None when any of
    the three strings is empty. ``signer`` is the signer's did:key, which EMBEDS
    its public key — so the assembling node needs no registry to check the
    signature, and this runtime needs none to carry it. Twin of C
    ``at_cosign_sig_to_json``."""
    c = cosign_bound(cid, COSIGN_CID_MAX)
    d = cosign_bound(signer, COSIGN_DID_MAX)
    s = cosign_bound(sig, COSIGN_SIG_MAX)
    if not c or not d or not s:
        return None
    return {'cid': c, 'signer': d, 'sig': s, 'seq': int(seq), 'ts': float(ts)}


def cosign_sig_from_json(body):
    """Parse a peer_cosign_sig body {cid, signer, sig, seq, ts}. Returns the
    bound-truncated dict or None on a malformed payload. Twin of C
    ``at_cosign_sig_from_json``."""
    if not isinstance(body, dict):
        return None
    cid = body.get('cid')
    signer = body.get('signer')
    sig = body.get('sig')
    seq = body.get('seq')
    ts = body.get('ts')
    if not isinstance(cid, str) or not isinstance(signer, str) \
            or not isinstance(sig, str):
        return None
    if not isinstance(seq, int) or isinstance(seq, bool):
        return None
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return None
    if not cid or not signer or not sig:
        return None
    return {'cid': cosign_bound(cid, COSIGN_CID_MAX),
            'signer': cosign_bound(signer, COSIGN_DID_MAX),
            'sig': cosign_bound(sig, COSIGN_SIG_MAX),
            'seq': int(seq), 'ts': float(ts)}


# Increment 8: social-interaction reputation accrual. Both peers of an
# interaction derive the SAME task id independently and must agree byte-for-byte,
# or their two scores never pair into one bilateral transaction. MUST stay in
# lockstep with C identity/social_tx.h.
SOCIAL_DOMAIN_CONN = b'agora-conn'
SOCIAL_DOMAIN_DM = b'agora-dm'
SOCIAL_DOMAIN_POST = b'agora-post'

SOCIAL_POS_BASELINE = 0.65
SOCIAL_POS_DELTA = 0.25
SOCIAL_NEG_SCORE = 0.30
SOCIAL_RECENCY_WINDOW = 604800.0
SOCIAL_PER_EDGE_DAILY_CAP = 3
SOCIAL_GLOBAL_DAILY_CAP = 20
SOCIAL_DM_BUCKET_SECONDS = 3600
SOCIAL_DAY_SECONDS = 86400


def social_task_uuid(domain, a_uuid, b_uuid, tail: bytes = b'') -> str:
    """The shared bilateral task id for a social interaction. Canonical bytes:
      domain || 0x00 || uuid_min(a,b)[16] || uuid_max(a,b)[16] || tail
    blake2b-256, first 16 bytes as a UUID string (lowercase). Order-independent in
    a,b (both peers converge). Twin of C at_social_task_uuid."""
    import hashlib
    if isinstance(domain, str):
        domain = domain.encode('ascii')
    a = _uuid16(a_uuid)
    b = _uuid16(b_uuid)
    lo, hi = (a, b) if a <= b else (b, a)   # byte compare == libuuid uuid_compare
    canon = bytes(domain) + b'\x00' + lo + hi + bytes(tail)
    digest = hashlib.blake2b(canon, digest_size=32).digest()
    return str(_uuidmod.UUID(bytes=digest[:16]))


def social_pos_score(count: int) -> float:
    """Diminishing-returns positive score S_pos(count) = 0.65 + 0.25/count, clamped
    to the TX [0,1] scale. count <= 0 is treated as 1. Twin of C at_social_pos_score."""
    if count < 1:
        count = 1
    s = SOCIAL_POS_BASELINE + SOCIAL_POS_DELTA / float(count)
    return max(0.0, min(1.0, s))


def post_sign(signing_key: '_SigningKey', author_uuid, seq: int, ts: float,
              required_tier: int, body: str) -> str:
    """Detached Ed25519 signature over post_canonical, lowercase hex."""
    sig = signing_key.sign(
        post_canonical(author_uuid, seq, ts, required_tier, body)).signature
    return sig.hex()


def post_verify(verify_key: '_VerifyKey', author_uuid, seq: int, ts: float,
                required_tier: int, body: str, sig_hex: str) -> bool:
    """Verify a detached signature (lowercase hex) over post_canonical."""
    try:
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64:
        return False
    from nacl.exceptions import BadSignatureError
    try:
        verify_key.verify(
            post_canonical(author_uuid, seq, ts, required_tier, body), sig)
        return True
    except BadSignatureError:
        return False


class Capability(Configuration):
    """Name and function"""
    _msg_class = capabilities_pb2.Capability

    def __init__(self, name, function=None, arg_names=None, keywords=None,
                 required_tier: int = 0, transaction_weight: int = 1,
                 description: str = '', kind: str = '', arg_schema=None):
        super().__init__(capabilities_pb2.Capability)
        self.name = name
        self.function = function  # this will be None for remote handling
        self.arg_names = arg_names
        self.keywords = keywords
        # Trust-tier metadata. See doc/architecture/trust-tiers.md §4.
        # required_tier is the minimum peer._tier needed to invoke this
        # capability (0 = any admitted peer). transaction_weight is the
        # multiplier applied in _pure_reputation to TSs from tasks using
        # this capability (1 = no boost).
        self.required_tier = required_tier
        self.transaction_weight = transaction_weight
        # Operator-console descriptor metadata (PIV_MFA_OPERATOR_ACCESS_PLAN.md
        #). Runtime-only and NOT serialized -- like arg_names/keywords,
        # these are cleared by sync_from_message and have no wire form, so they
        # don't touch the Python<->C conformance corpus. The operator's local
        # registry carries them so its resource directory is self-describing;
        # broadcasting them on caps_response is a separate, conformance-gated
        # follow-up. kind is a ResourceKind value (compute/data_stream/service).
        self.description = description
        self.kind = kind
        self.arg_schema = arg_schema

    def execute(self, task, pid_q):
        pid_q.put_nowait(multiprocessing.current_process().pid)
        try:
            return self.function(*task.parameters.args, **task.parameters.kwargs)
        except Exception as e:
            raise RuntimeError('Capability %r execution failed for task %s: %s' % (self.name, task.uuid, e)) from e

    def __eq__(self, other):
        return self.name == other.name

    def to_dict(self):
        # Intentionally minimal — `to_dict` is for log/repr surfaces; the
        # cross-impl wire form is the protobuf `Capability` message
        # (capabilities.proto / sync_to_message). `arg_names` and
        # `keywords` are runtime-only fields cleared by sync_from_message,
        # so they have no meaningful serialized representation. See
        # divergence.md H15 (re-audit) for the unified C-side equivalent
        # via `capability_t.arguments`.
        return dict(name=self.name,
                    required_tier=self.required_tier,
                    transaction_weight=self.transaction_weight)

    def sync_to_message(self):
        self.message.name = self.name
        self.message.category = ''
        self.message.required_tier = self.required_tier
        self.message.transaction_weight = self.transaction_weight

    def sync_from_message(self):
        self.name = self.message.name
        self.function = None
        self.arg_names = None
        self.keywords = None
        # Descriptor metadata is runtime-only / not on the wire (see __init__).
        self.description = ''
        self.kind = ''
        self.arg_schema = None
        self.required_tier = int(self.message.required_tier)
        # proto3 can't distinguish "not set" from 0; treat 0 as the
        # default weight (1) so peers without the field interoperate.
        w = int(self.message.transaction_weight)
        self.transaction_weight = w if w > 0 else 1


class Capabilities(Mapping):
    """Mapping of name to Capability"""
    def __init__(self):
        self._listing = {}

    def __len__(self):
        return len(self._listing)

    def __iter__(self):
        return self._listing.__iter__()

    def __getitem__(self, key):
        return self._listing[key]

    def __contains__(self, item):
        return item in self._listing.values()

    def to_list(self) -> list[str]:
        return [cap.name for cap in self._listing.values()]

    def register_ability(self, name, function, arg_names=None, keywords=None,
                         required_tier: int = 0, transaction_weight: int = 1,
                         description: str = '', kind: str = '', arg_schema=None):
        self._listing[name] = Capability(name, function, arg_names, keywords,
                                         required_tier=required_tier,
                                         transaction_weight=transaction_weight,
                                         description=description, kind=kind,
                                         arg_schema=arg_schema)


class PeerCapabilities(Mapping, Configuration):
    """Mapping of capability names to peer ids"""
    _msg_class = capabilities_pb2.PeerCapabilities

    def __init__(self, _listing=None):
        super().__init__(capabilities_pb2.PeerCapabilities)
        self._listing = _listing
        if _listing is None:
            self._listing = {}
        # Optional per-capability descriptors {cap_name: {required_tier,
        # description, kind, arg_schema}} learned from caps_response. Runtime-
        # only and NOT serialized (excluded from sync_to/from_message and from
        # the persisted peer-capabilities.cfg.json), so the protobuf/persist
        # wire form is unchanged. It rides the intra-node pickle hop
        # (idprocess -> main) for free; inter-node, descriptors travel in the
        # JSON caps_response payload (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.5).
        self.descriptors: dict = {}

    def __len__(self):
        return len(self._listing)

    def __iter__(self):
        return self._listing.__iter__()

    def __getitem__(self, key):
        return self._listing[key]

    def register(self, peer_id, caps: list[str]):
        for name in caps:
            if name not in self._listing:
                self._listing[name] = []
            self._listing[name].append(peer_id)

    def register_descriptor(self, name: str, descriptor: dict):
        """Record an optional capability descriptor learned from caps_response.

        The descriptor is **untrusted peer input**, so it is size-bounded via
        `sanitize_descriptor` before storage. Idempotent / last-writer-wins (the
        descriptor is a property of the capability, not the provider). An empty
        descriptor (or one that sanitizes to nothing) is ignored so a legacy
        name-only advertisement never clobbers a known descriptor.
        """
        if not descriptor:
            return
        clean = sanitize_descriptor(descriptor)
        if clean:
            self.descriptors[name] = clean

    def filtered_for_persist(self, keep_uuids):
        """Return a copy with peer-ids not in keep_uuids removed.

        Capability names with no remaining peers after the filter are
        dropped entirely. Used by the persistent-cohort save path so
        untrusted (rep<=0.5) peers' capability advertisements don't
        survive a process restart.
        """
        keep = {str(u) for u in keep_uuids}
        new_listing = {}
        for cap_name, peer_ids in self._listing.items():
            kept = [pid for pid in peer_ids if str(pid) in keep]
            if kept:
                new_listing[cap_name] = kept
        return PeerCapabilities(_listing=new_listing)

    def to_dict(self):
        # `descriptors` is runtime-only metadata learned from caps_response; it
        # is intentionally absent from both the protobuf wire form and the
        # persisted peer-capabilities.cfg.json. Drop it here so the JSON persist
        # path (ConfigJSONEncoder -> to_dict) and the reload path (cls(**kwargs),
        # which only accepts `_listing`) stay symmetric.
        d = super().to_dict()
        d.pop('descriptors', None)
        return d

    def sync_to_message(self):
        # Invert Python's {cap_name: [peer_ids]} to proto's {peer: [capabilities]}
        peer_caps = {}
        for cap_name, peer_ids in self._listing.items():
            for pid in peer_ids:
                peer_key = str(pid)
                if peer_key not in peer_caps:
                    peer_caps[peer_key] = []
                peer_caps[peer_key].append(cap_name)
        del self.message.listing[:]
        for peer, cap_names in peer_caps.items():
            entry = self.message.listing.add()
            entry.peer = peer
            for cn in cap_names:
                cap = entry.capability.add()
                cap.name = cn
                cap.category = ''

    def sync_from_message(self):
        # Invert proto's {peer: [capabilities]} back to Python's {cap_name: [peer_ids]}
        self._listing = {}
        # Descriptors are runtime-only (not on the wire); ensure the attribute
        # exists on objects reconstructed via from_wire_bytes (which bypasses
        # __init__).
        self.descriptors = {}
        for entry in self.message.listing:
            for cap in entry.capability:
                if cap.name not in self._listing:
                    self._listing[cap.name] = []
                self._listing[cap.name].append(entry.peer)
