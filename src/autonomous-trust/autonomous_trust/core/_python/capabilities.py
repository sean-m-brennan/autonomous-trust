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
