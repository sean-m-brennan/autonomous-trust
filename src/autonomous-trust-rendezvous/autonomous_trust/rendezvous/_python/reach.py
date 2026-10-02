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
"""Signed reachability records (FIRST_CONTACT_PLAN §4.2).

A node's own statement of how to reach it now -- its relays (pinned hints) and
any direct endpoints -- signed by its identity key, numbered, and dated:

    ReachRecord := sign_Alice("at-reach-v1|" + body)
    body        := {v, typename: "at-reach", uuid, key, seq, expiry,
                    relays: [relay://<uuid>:<fp>@host:port, ...],
                    endpoints: [host, ...]}

The signature covers the EXACT body bytes transmitted, as an invitation's does
(no re-serialization, so nothing to canonicalize), behind a domain prefix so a
record's signature can never verify as anything else Alice signs.

A record is addressed by :func:`record_id`: the fingerprint of the signing key
(the same one a relay pin carries), so a relay holding records cannot list
whose they are without already knowing the keys. It travels two ways: PUSHED to
each contact while that contact can still reach us, and PUBLISHED at our relays
for a contact who lost us to look up.

Which record wins: the highest ``seq`` that has not expired. A receiver refuses
a ``seq`` at or below the one it already applied, so an old record cannot be
replayed over a newer one; the ``seq`` is the holder's, persisted across
restarts (identity's ``reach.cfg.json``). What makes a record authoritative
for a CONTACT is the key: it is applied only when its key is the key that
contact already has on record.
"""
import json
import time

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from . import relay as _relay

#: Domain separation for the record signature. Same as C's AT_REACH_DOMAIN.
REACH_DOMAIN = 'at-reach-v1|'
REACH_TYPENAME = 'at-reach'
REACH_VERSION = 1
#: A record's default lifetime (a week, as an invitation's). Same as C's.
DEFAULT_TTL_SECONDS = 7 * 24 * 3600
#: Most endpoints one record carries (relays are capped at relay.MAX_RELAYS).
MAX_ENDPOINTS = 4


class InvalidRecord(ValueError):
    """A reachability record that is malformed, forged, or expired."""


class ReachRecord:
    """A signed reachability record: the exact signed body plus its signature."""

    def __init__(self, body: dict, body_str: str, sig_hex: str):
        self.body = body
        self.body_str = body_str
        self.sig_hex = sig_hex

    @property
    def uuid(self):
        return str(self.body.get('uuid', '')).lower()

    @property
    def key(self):
        return str(self.body.get('key', '')).lower()

    @property
    def seq(self):
        return int(self.body.get('seq', 0) or 0)

    @property
    def expiry(self):
        return int(self.body.get('expiry', 0) or 0)

    @property
    def relays(self):
        return [str(h) for h in self.body.get('relays', []) or []]

    @property
    def endpoints(self):
        return [str(h) for h in self.body.get('endpoints', []) or []]

    @property
    def record_id(self):
        return record_id(self.key)

    def is_expired(self, now=None):
        exp = self.expiry
        return bool(exp) and (now if now is not None else time.time()) >= exp

    def verify(self, now=None):
        """Raise :class:`InvalidRecord` unless the signature is the key's own
        over the body, and the record is unexpired. Returns self."""
        try:
            VerifyKey(HexEncoder.decode(self.key.encode('ascii'))).verify(
                (REACH_DOMAIN + self.body_str).encode('utf-8'),
                HexEncoder.decode(self.sig_hex.encode('ascii')))
        except (BadSignatureError, ValueError, TypeError) as exc:
            raise InvalidRecord('signature does not match the record key') from exc
        if self.is_expired(now):
            raise InvalidRecord('record has expired')
        return self

    def to_wire(self) -> dict:
        return {'body': self.body_str, 'sig': self.sig_hex}

    def to_json(self) -> str:
        return json.dumps(self.to_wire(), separators=(',', ':'), ensure_ascii=True)

    @classmethod
    def from_wire(cls, obj) -> 'ReachRecord':
        """Parse ``{body, sig}`` (a dict or its JSON). Does NOT verify."""
        try:
            if isinstance(obj, (str, bytes)):
                obj = json.loads(obj)
            body_str, sig_hex = obj['body'], obj['sig']
            if not isinstance(body_str, str) or not isinstance(sig_hex, str):
                raise TypeError('body and sig must be strings')
            body = json.loads(body_str)
        except (ValueError, TypeError, KeyError) as exc:
            raise InvalidRecord('malformed reachability record') from exc
        if not isinstance(body, dict) or body.get('typename') != REACH_TYPENAME:
            raise InvalidRecord('not an AT reachability record')
        return cls(body, body_str, sig_hex)

    def __repr__(self):
        return 'ReachRecord(%s seq=%d relays=%d)' % (self.uuid[:8], self.seq,
                                                    len(self.relays))


def record_id(key_hex) -> str:
    """Where a record is filed: the fingerprint of its signing key."""
    return _relay.key_fingerprint(key_hex)


def create_record(identity, seq, relays=(), endpoints=(), expiry=None,
                  ttl_seconds=DEFAULT_TTL_SECONDS) -> ReachRecord:
    """Sign a reachability record for *my* ``identity``."""
    if getattr(identity, '_public_only', True):
        raise ValueError('create_record needs your own (signable) identity')
    if expiry is None:
        expiry = int(time.time()) + int(ttl_seconds) if ttl_seconds else 0
    body = {
        'v': REACH_VERSION,
        'typename': REACH_TYPENAME,
        'uuid': str(identity.uuid).lower(),
        'key': _relay._signing_hex(identity).lower(),
        'seq': int(seq),
        'expiry': int(expiry),
        'relays': list(relays)[:_relay.MAX_RELAYS],
        'endpoints': list(endpoints)[:MAX_ENDPOINTS],
    }
    body_str = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    signed = identity.sign((REACH_DOMAIN + body_str).encode('utf-8'))
    return ReachRecord(body, body_str, signed.signature.decode('ascii'))
