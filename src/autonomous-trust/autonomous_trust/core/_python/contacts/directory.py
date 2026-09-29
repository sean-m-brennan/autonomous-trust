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
"""Directory entries and the attestations behind them (FIRST_CONTACT_PLAN
§4.3, Phase 3).

A directory maps a handle to an identity, so it is where squatting and
harvesting live. Two signed objects bound it:

    Attestation := sign_Issuer("at-dir-attest-v1|" + body)
    body        := {v, typename: "at-dir-attest", handle, key, issuer, expiry}

    Entry       := sign_Alice("at-dir-entry-v1|" + body)
    body        := {v, typename: "at-dir-entry", handle, uuid, key,
                    visibility, seq, expiry, identity, attestation: {body, sig}}

``identity`` is the holder's public identity in the cross-runtime canonical
form, with the address left blank (whoever finds the entry reaches the holder
through the registry's relay, and a handle is not a reason to hand out an
address); it is what a finder addresses its contact request to.

An issuer is whoever a registry trusts to have checked that Alice controls the
handle (an email or SMS verification service, an organization's operator key);
the attestation is that issuer's word, bound to Alice's KEY, so it cannot be
lifted onto anyone else's entry. The entry is Alice's own opt-in: which handle,
who may find it (``anyone`` who asks, or only clients who are ``published``
themselves), numbered so a newer one replaces an older one, and dated.

Neither grants trust. A lookup answer still becomes only an unverified contact,
and only after Alice accepts Bob's request (first_contact.py); the safety
number is what verifies. Signatures cover the EXACT transmitted body string,
behind a domain prefix, as invitations and reachability records do. Same
formats and rules as C's ``contacts/directory.{h,c}``.
"""
import json
import time

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

ATTEST_DOMAIN = 'at-dir-attest-v1|'
ENTRY_DOMAIN = 'at-dir-entry-v1|'
ATTEST_TYPENAME = 'at-dir-attest'
ENTRY_TYPENAME = 'at-dir-entry'
VERSION = 1

VISIBILITY_ANYONE = 'anyone'
VISIBILITY_PUBLISHED = 'published'
VISIBILITIES = (VISIBILITY_ANYONE, VISIBILITY_PUBLISHED)

#: Longest handle, in bytes. Same as C's AT_DIR_HANDLE_MAX.
HANDLE_MAX = 128
_HANDLE_CHARS = frozenset('abcdefghijklmnopqrstuvwxyz0123456789._@+-')

#: An entry's default lifetime (30 days); an attestation's is the issuer's call.
DEFAULT_TTL_SECONDS = 30 * 24 * 3600


#: Why an entry or attestation was refused. Index = C's -at_dir_status_t.
REASONS = ('', 'malformed', 'bad_signature', 'expired', 'untrusted', 'mismatch')


class InvalidEntry(ValueError):
    """An attestation or directory entry that is malformed, forged, expired,
    from an untrusted issuer, or bound to another handle or key. ``reason`` is
    one of :data:`REASONS`."""

    def __init__(self, message, reason='malformed'):
        super().__init__(message)
        self.reason = reason


def normalize_handle(handle):
    """``handle`` folded to lower case, or None if it is not a handle: ASCII
    ``[a-z0-9._@+-]``, 1 to :data:`HANDLE_MAX` bytes. Unicode folding is left
    out on purpose: C has no exact equivalent of Python's."""
    if not isinstance(handle, str):
        return None
    try:
        handle.encode('ascii')
    except UnicodeEncodeError:
        return None
    folded = handle.lower()
    if not 0 < len(folded) <= HANDLE_MAX or any(c not in _HANDLE_CHARS for c in folded):
        return None
    return folded


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_hex_key(v):
    return isinstance(v, str) and len(v) == 64 \
        and all(c in '0123456789abcdef' for c in v)


def _split(obj):
    try:
        if isinstance(obj, (str, bytes)):
            obj = json.loads(obj)
        body_str, sig_hex = obj['body'], obj['sig']
        if not isinstance(body_str, str) or not isinstance(sig_hex, str):
            raise TypeError('body and sig must be strings')
        body = json.loads(body_str)
    except (ValueError, TypeError, KeyError) as exc:
        raise InvalidEntry('malformed signed object') from exc
    if not isinstance(body, dict):
        raise InvalidEntry('body is not an object')
    return body, body_str, sig_hex


def _check_sig(key_hex, domain, body_str, sig_hex):
    try:
        VerifyKey(HexEncoder.decode(key_hex.encode('ascii'))).verify(
            (domain + body_str).encode('utf-8'),
            HexEncoder.decode(sig_hex.encode('ascii')))
    except (BadSignatureError, ValueError, TypeError) as exc:
        raise InvalidEntry('signature does not match the key', 'bad_signature') from exc


def _sign(signing_key, domain, body):
    body_str = json.dumps(body, separators=(',', ':'), ensure_ascii=True)
    sig = signing_key.sign((domain + body_str).encode('utf-8')).signature
    return {'body': body_str, 'sig': HexEncoder.encode(sig).decode('ascii')}


def _signing_key(identity):
    if getattr(identity, '_public_only', True) or identity.signature.private is None:
        raise InvalidEntry('a directory entry needs your own (signable) identity')
    return identity.signature.private


def _public_hex(signing_key):
    return signing_key.verify_key.encode(HexEncoder).decode('ascii')


class Attestation:
    """An issuer's word that ``handle`` belongs to ``key``."""

    def __init__(self, body, body_str, sig_hex):
        self.body, self.body_str, self.sig_hex = body, body_str, sig_hex

    handle = property(lambda self: self.body.get('handle'))
    key = property(lambda self: self.body.get('key'))
    issuer = property(lambda self: self.body.get('issuer'))
    expiry = property(lambda self: self.body.get('expiry'))

    @classmethod
    def from_wire(cls, obj):
        body, body_str, sig_hex = _split(obj)
        return cls(body, body_str, sig_hex)

    def to_wire(self):
        return {'body': self.body_str, 'sig': self.sig_hex}

    def verify(self, trusted_issuers=None, now=None):
        """Raise :class:`InvalidEntry` unless well formed, signed by its
        issuer, unexpired, and (when ``trusted_issuers`` is given) from one of
        them. Returns self."""
        b = self.body
        if b.get('typename') != ATTEST_TYPENAME or not _is_int(b.get('v')) \
                or b['v'] != VERSION:
            raise InvalidEntry('not a version-%d AT attestation' % VERSION)
        if normalize_handle(b.get('handle')) != b.get('handle'):
            raise InvalidEntry('attestation handle is not a normalized handle')
        if not _is_hex_key(b.get('key')) or not _is_hex_key(b.get('issuer')):
            raise InvalidEntry('attestation key or issuer is not a hex key')
        if not _is_int(b.get('expiry')) or b['expiry'] <= 0:
            raise InvalidEntry('attestation has no expiry')
        _check_sig(b['issuer'], ATTEST_DOMAIN, self.body_str, self.sig_hex)
        if (now if now is not None else time.time()) >= b['expiry']:
            raise InvalidEntry('attestation has expired', 'expired')
        if trusted_issuers is not None and b['issuer'] not in trusted_issuers:
            raise InvalidEntry('attestation is from an issuer this registry does not trust',
                               'untrusted')
        return self


def attest(issuer_signing_key, handle, key_hex, expiry) -> Attestation:
    """The attestation ``issuer_signing_key`` (a nacl SigningKey) gives that
    ``handle`` belongs to ``key_hex``. For an issuer's tooling."""
    folded = normalize_handle(handle)
    if folded is None:
        raise InvalidEntry('%r is not a handle' % (handle,))
    if not _is_hex_key(str(key_hex).lower()):
        raise InvalidEntry('key is not a hex ed25519 key')
    wire = _sign(issuer_signing_key, ATTEST_DOMAIN,
                 {'v': VERSION, 'typename': ATTEST_TYPENAME, 'handle': folded,
                  'key': str(key_hex).lower(),
                  'issuer': _public_hex(issuer_signing_key), 'expiry': int(expiry)})
    return Attestation.from_wire(wire)


class DirectoryEntry:
    """Alice's opt-in: find me by ``handle``."""

    def __init__(self, body, body_str, sig_hex):
        self.body, self.body_str, self.sig_hex = body, body_str, sig_hex

    handle = property(lambda self: self.body.get('handle'))
    uuid = property(lambda self: str(self.body.get('uuid', '')).lower())
    identity_json = property(lambda self: self.body.get('identity'))
    key = property(lambda self: self.body.get('key'))
    visibility = property(lambda self: self.body.get('visibility'))
    seq = property(lambda self: self.body.get('seq'))
    expiry = property(lambda self: self.body.get('expiry'))

    @property
    def attestation(self):
        return Attestation.from_wire(self.body.get('attestation'))

    def is_expired(self, now=None):
        exp = self.expiry
        return not _is_int(exp) or (now if now is not None else time.time()) >= exp

    @classmethod
    def from_wire(cls, obj):
        body, body_str, sig_hex = _split(obj)
        return cls(body, body_str, sig_hex)

    def to_wire(self):
        return {'body': self.body_str, 'sig': self.sig_hex}

    def to_json(self):
        return json.dumps(self.to_wire(), separators=(',', ':'), ensure_ascii=True)

    def verify(self, trusted_issuers=None, now=None):
        """Raise :class:`InvalidEntry` unless the entry is well formed, signed
        by its own key, unexpired, and carries a valid attestation (from one
        of ``trusted_issuers`` when given) for the SAME handle and key.
        Returns self."""
        b = self.body
        if b.get('typename') != ENTRY_TYPENAME or not _is_int(b.get('v')) \
                or b['v'] != VERSION:
            raise InvalidEntry('not a version-%d AT directory entry' % VERSION)
        if normalize_handle(b.get('handle')) != b.get('handle'):
            raise InvalidEntry('entry handle is not a normalized handle')
        if not _is_hex_key(b.get('key')) or not isinstance(b.get('uuid'), str):
            raise InvalidEntry('entry key or uuid is malformed')
        ident = b.get('identity')
        if not isinstance(ident, dict) or ident.get('typename') != 'identity' \
                or not isinstance(ident.get('uuid'), str) \
                or not isinstance(ident.get('signature'), dict) \
                or not isinstance(ident['signature'].get('hex_seed'), str):
            raise InvalidEntry('entry identity is malformed')
        if b.get('visibility') not in VISIBILITIES:
            raise InvalidEntry('entry visibility is not one of %s' % (VISIBILITIES,))
        if not _is_int(b.get('seq')) or b['seq'] < 1 \
                or not _is_int(b.get('expiry')) or b['expiry'] <= 0:
            raise InvalidEntry('entry seq or expiry is malformed')
        _check_sig(b['key'], ENTRY_DOMAIN, self.body_str, self.sig_hex)
        if (now if now is not None else time.time()) >= b['expiry']:
            raise InvalidEntry('entry has expired', 'expired')
        if ident['uuid'].lower() != b['uuid'].lower() \
                or ident['signature']['hex_seed'].lower() != b['key']:
            raise InvalidEntry('entry identity is not the holder', 'mismatch')
        att = self.attestation.verify(trusted_issuers, now)
        if att.handle != b['handle'] or att.key != b['key']:
            raise InvalidEntry('attestation is for another handle or key', 'mismatch')
        return self


def create_entry(identity, attestation, seq, visibility=VISIBILITY_ANYONE,
                 expiry=None, now=None) -> DirectoryEntry:
    """Alice's entry for the handle ``attestation`` vouches for, signed by
    ``identity``. Raises :class:`InvalidEntry` if the attestation is not for
    her key (a registry would refuse it anyway)."""
    signing = _signing_key(identity)
    key = _public_hex(signing)
    if attestation.key != key:
        raise InvalidEntry('the attestation is for another key', 'mismatch')
    if visibility not in VISIBILITIES:
        raise InvalidEntry('visibility is not one of %s' % (VISIBILITIES,))
    now = now if now is not None else time.time()
    if expiry is None:
        expiry = int(now) + DEFAULT_TTL_SECONDS
    if _is_int(attestation.expiry):
        expiry = min(int(expiry), attestation.expiry)
    from ..identity.identity import public_identity_to_canonical
    ident = public_identity_to_canonical(identity)
    ident['address'] = ''
    wire = _sign(signing, ENTRY_DOMAIN,
                 {'v': VERSION, 'typename': ENTRY_TYPENAME,
                  'handle': attestation.handle, 'uuid': str(identity.uuid).lower(),
                  'key': key, 'visibility': visibility, 'seq': int(seq),
                  'expiry': int(expiry), 'identity': ident,
                  'attestation': attestation.to_wire()})
    return DirectoryEntry.from_wire(wire)


# -- the contact request a finder sends ----------------------------------------
REQUEST_DOMAIN = 'at-contact-request-v1|'
REQUEST_TYPENAME = 'at-contact-request'
#: How long a request stands, by default: long enough for a person to answer.
#: Same as C's AT_DIR_REQUEST_TTL_SECONDS.
REQUEST_TTL_SECONDS = 3600
#: Most relay hints a request names. Same as C's.
REQUEST_MAX_RELAYS = 4
_NONCE_HEX = 32


class ContactRequest:
    """Bob, having found Alice by ``handle``, asks to become her contact.

    body := {v, typename: "at-contact-request", from, key, to, handle, nonce,
             expiry, relays: [relay hint, ...]}

    Signed by Bob's key (``key``) over ``at-contact-request-v1|`` + body. It
    names ``to`` (Alice's uuid), so it cannot be replayed at anyone else, and
    the ``handle`` Bob found her by, which must be one Alice published."""

    def __init__(self, body, body_str, sig_hex):
        self.body, self.body_str, self.sig_hex = body, body_str, sig_hex

    sender = property(lambda self: str(self.body.get('from', '')).lower())
    key = property(lambda self: self.body.get('key'))
    to = property(lambda self: str(self.body.get('to', '')).lower())
    handle = property(lambda self: self.body.get('handle'))
    nonce = property(lambda self: self.body.get('nonce'))
    expiry = property(lambda self: self.body.get('expiry'))
    relays = property(lambda self: list(self.body.get('relays') or []))

    @classmethod
    def from_wire(cls, obj):
        body, body_str, sig_hex = _split(obj)
        return cls(body, body_str, sig_hex)

    def to_wire(self):
        return {'body': self.body_str, 'sig': self.sig_hex}

    def to_json(self):
        return json.dumps(self.to_wire(), separators=(',', ':'), ensure_ascii=True)

    def verify(self, now=None):
        """Raise :class:`InvalidEntry` unless well formed, signed by its own
        ``key``, and unexpired. Returns self. Whether it is addressed to US,
        for a handle we published, from the sender the envelope names, is the
        receiver's check."""
        from ..network import relay as _relay
        b = self.body
        nonce = b.get('nonce')
        relays = b.get('relays')
        if b.get('typename') != REQUEST_TYPENAME or not _is_int(b.get('v')) \
                or b['v'] != VERSION:
            raise InvalidEntry('not a version-%d AT contact request' % VERSION)
        if not isinstance(b.get('from'), str) or not isinstance(b.get('to'), str) \
                or not _is_hex_key(b.get('key')) \
                or normalize_handle(b.get('handle')) != b.get('handle') \
                or not isinstance(nonce, str) or len(nonce) != _NONCE_HEX \
                or any(c not in '0123456789abcdef' for c in nonce) \
                or not _is_int(b.get('expiry')) or b['expiry'] <= 0 \
                or not isinstance(relays, list) or len(relays) > REQUEST_MAX_RELAYS \
                or any(not isinstance(h, str) or _relay.parse_hint(h)[0] is None
                       for h in relays):
            raise InvalidEntry('contact request is malformed')
        _check_sig(b['key'], REQUEST_DOMAIN, self.body_str, self.sig_hex)
        if (now if now is not None else time.time()) >= b['expiry']:
            raise InvalidEntry('contact request has expired', 'expired')
        return self


def create_request(identity, entry, relays=(), expiry=None, nonce=None,
                   now=None) -> ContactRequest:
    """Bob's request to the holder of ``entry`` (a verified DirectoryEntry)."""
    import secrets
    signing = _signing_key(identity)
    now = now if now is not None else time.time()
    wire = _sign(signing, REQUEST_DOMAIN,
                 {'v': VERSION, 'typename': REQUEST_TYPENAME,
                  'from': str(identity.uuid).lower(), 'key': _public_hex(signing),
                  'to': entry.uuid, 'handle': entry.handle,
                  'nonce': nonce or secrets.token_hex(_NONCE_HEX // 2),
                  'expiry': int(expiry if expiry is not None else now + REQUEST_TTL_SECONDS),
                  'relays': list(relays)[:REQUEST_MAX_RELAYS]})
    return ContactRequest.from_wire(wire)
