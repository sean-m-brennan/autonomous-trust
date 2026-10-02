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
"""Area cards: a person's opt-in "I am around here", filed at a hub.

    Card := sign_Alice("at-area-card-v1|" + body)
    body := {v, typename: "at-area-card", uuid, key, area, bucket, name,
             seq, expiry, identity}

``area`` is the geohash prefix a hub serves (2 to 5 characters; 4 is about a
city) and ``bucket`` Alice's own coarse bucket inside it (``area`` up to 5
characters), which a finder uses only to show a distance. ``name`` is what
Alice calls herself, at most :data:`NAME_MAX` bytes. ``identity`` is her public
identity in the cross-runtime canonical form with the address left blank, as a
directory entry's: it is what a finder addresses a contact request to.

Nobody attests nearness, so a card carries no attestation. What bounds it is
the hub (only the card's own holder files it, one card per holder per area, a
short life, and reciprocal lookups), and what a card is worth is only what the
person on the other end says when asked. Finding is not adding: a card leads to
a contact request (first_contact/directory_contact.py), which its holder answers.

Signatures cover the EXACT transmitted body string, behind a domain prefix, as
every other signed AT object does. Same format and rules as C's
``contacts/area_card.{h,c}``.
"""
import json
import time

from autonomous_trust.rendezvous import relay_rosters as _rosters
from .directory import InvalidEntry, _check_sig, _is_hex_key, _is_int, _public_hex, \
    _sign, _signing_key, _split

CARD_DOMAIN = 'at-area-card-v1|'
CARD_TYPENAME = 'at-area-card'
VERSION = 1

#: Geohash base32, and the shortest and longest area a hub may serve: the
#: roster format's (network/relay_rosters.py). Five characters is about 5 km:
#: coarse on purpose. Same as C's.
GEOHASH_CHARS = _rosters.GEOHASH_CHARS
AREA_MIN = _rosters.AREA_MIN
AREA_MAX = _rosters.AREA_MAX
#: The longest bucket a card may carry.
BUCKET_MAX = 5
#: Longest name, in UTF-8 bytes. Same as C's AT_AREA_NAME_MAX.
NAME_MAX = 64
#: A card's default life: an hour. Its holder refiles while it stays listed.
DEFAULT_TTL_SECONDS = 3600
#: The longest life a hub accepts: a card cannot outlive a day.
MAX_TTL_SECONDS = 24 * 3600
#: Where a node keeps its own listings (in its data dir): identity writes it,
#: and the network process reads it to register first with the hubs for them.
STATE_FILENAME = 'area.cfg.json'


def normalize_area(area, min_len=AREA_MIN, max_len=AREA_MAX):
    """``area`` folded to lower case, or None if it is not a geohash prefix of
    ``min_len`` to ``max_len`` characters (the roster format's syntax)."""
    return _rosters.area_normalize(area, min_len, max_len)


def valid_name(name) -> bool:
    if not isinstance(name, str):
        return False
    try:
        raw = name.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return len(raw) <= NAME_MAX and all(ord(c) >= 0x20 and ord(c) != 0x7f for c in name)


class AreaCard:
    """Alice's opt-in: list me in ``area``."""

    def __init__(self, body, body_str, sig_hex):
        self.body, self.body_str, self.sig_hex = body, body_str, sig_hex

    uuid = property(lambda self: str(self.body.get('uuid', '')).lower())
    key = property(lambda self: self.body.get('key'))
    area = property(lambda self: self.body.get('area'))
    bucket = property(lambda self: self.body.get('bucket'))
    name = property(lambda self: self.body.get('name'))
    seq = property(lambda self: self.body.get('seq'))
    expiry = property(lambda self: self.body.get('expiry'))
    identity_json = property(lambda self: self.body.get('identity'))

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

    def verify(self, now=None):
        """Raise :class:`InvalidEntry` unless the card is well formed, signed
        by its own key, names its holder's identity, and is unexpired.
        Returns self. Whether it is for the area a finder asked about is the
        finder's check."""
        b = self.body
        if b.get('typename') != CARD_TYPENAME or not _is_int(b.get('v')) \
                or b['v'] != VERSION:
            raise InvalidEntry('not a version-%d AT area card' % VERSION)
        area = b.get('area')
        bucket = b.get('bucket')
        if not isinstance(area, str) or not isinstance(bucket, str) \
                or normalize_area(area) != area or normalize_area(bucket, 1, BUCKET_MAX) != bucket \
                or not bucket.startswith(area):
            raise InvalidEntry('card area or bucket is not a geohash prefix')
        if not valid_name(b.get('name')):
            raise InvalidEntry('card name is malformed')
        if not _is_hex_key(b.get('key')) or not isinstance(b.get('uuid'), str):
            raise InvalidEntry('card key or uuid is malformed')
        ident = b.get('identity')
        if not isinstance(ident, dict) or ident.get('typename') != 'identity' \
                or not isinstance(ident.get('uuid'), str) \
                or not isinstance(ident.get('signature'), dict) \
                or not isinstance(ident['signature'].get('hex_seed'), str):
            raise InvalidEntry('card identity is malformed')
        if not _is_int(b.get('seq')) or b['seq'] < 1 \
                or not _is_int(b.get('expiry')) or b['expiry'] <= 0:
            raise InvalidEntry('card seq or expiry is malformed')
        _check_sig(b['key'], CARD_DOMAIN, self.body_str, self.sig_hex)
        if (now if now is not None else time.time()) >= b['expiry']:
            raise InvalidEntry('card has expired', 'expired')
        if ident['uuid'].lower() != b['uuid'].lower() \
                or ident['signature']['hex_seed'].lower() != b['key']:
            raise InvalidEntry('card identity is not the holder', 'mismatch')
        return self


def create_card(identity, area, bucket, name, seq, expiry=None, now=None) -> AreaCard:
    """Alice's card for ``area``, signed by ``identity``. Raises
    :class:`InvalidEntry` for an area, bucket or name no hub would take."""
    signing = _signing_key(identity)
    area_n = normalize_area(area)
    bucket_n = normalize_area(bucket, 1, BUCKET_MAX)
    if area_n is None or bucket_n is None or not bucket_n.startswith(area_n):
        raise InvalidEntry('area or bucket is not a geohash prefix')
    if not valid_name(name):
        raise InvalidEntry('name is malformed')
    now = now if now is not None else time.time()
    if expiry is None:
        expiry = int(now) + DEFAULT_TTL_SECONDS
    from autonomous_trust.core.identity.identity import public_identity_to_canonical
    ident = public_identity_to_canonical(identity)
    ident['address'] = ''
    wire = _sign(signing, CARD_DOMAIN,
                 {'v': VERSION, 'typename': CARD_TYPENAME,
                  'uuid': str(identity.uuid).lower(), 'key': _public_hex(signing),
                  'area': area_n, 'bucket': bucket_n, 'name': name,
                  'seq': int(seq), 'expiry': int(expiry), 'identity': ident})
    return AreaCard.from_wire(wire)
