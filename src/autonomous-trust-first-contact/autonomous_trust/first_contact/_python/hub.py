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
"""The area hub: an opt-in role on a relay (``AT_HUB=1``), serving the areas
named in ``AT_HUB_AREAS`` (comma-separated geohash prefixes).

It holds area cards (first_contact/area_card.py) filed by the relay's own
registrants and answers area lookups, over the relay's existing TCP link,
whose two-way signed registration already proved who each client is. Ops (one
JSON frame each, as the relay's)::

    client -> hub  {"op": "hub_publish", "card": {body, sig}}
    hub -> client  {"op": "hub_published", "area": A, "seq": N}
                 | {"op": "hub_refused", "area": A, "reason": R}
    client -> hub  {"op": "hub_withdraw", "area": A}
    hub -> client  {"op": "hub_withdrawn", "area": A}
    client -> hub  {"op": "hub_lookup", "area": A}
    hub -> client  {"op": "hub_cards", "area": A, "cards": [{body, sig}, ...]}
                 | {"op": "hub_limited", "area": A}

What bounds it: a card is filed only from the registered holder of its key,
only for an area this hub serves, only over a lower ``seq``, never for longer
than a day, and one per holder per area. A lookup is RECIPROCAL: only a client
with a live card in that area is shown the area's cards; to anyone else the
answer is the empty list a quiet area gets, so a hub cannot be read from
outside the area it serves. An answer holds at most :data:`LOOKUP_MAX` cards,
the freshest first, never the asker's own, and never a holder this node has
come to distrust. Past the rate limit (``AT_HUB_RATE`` a minute per client
uuid, default 6) the answer is ``hub_limited``. Cards live in memory: a
restarted hub is refilled as its registrants re-register. Same ops and rules
as C's ``network/net_hub.{h,c}``.
"""
import os
import threading
import time

from . import area_card as _card
from .directory import InvalidEntry

AREAS_ENV = 'AT_HUB_AREAS'
RATE_ENV = 'AT_HUB_RATE'
#: Lookups a client may make per minute, by default. Same as C's.
DEFAULT_RATE = 6
#: Most cards one hub holds, and one area. Same as C's.
MAX_CARDS = 4096
MAX_PER_AREA = 256
#: Most cards one lookup answers with. Same as C's AT_HUB_LOOKUP_MAX.
LOOKUP_MAX = 32
#: Most areas one hub serves.
MAX_AREAS = 8


def hub_enabled() -> bool:
    """True iff this node serves as a hub (``AT_HUB``). Only meaningful on a
    node that is also a relay."""
    return os.environ.get('AT_HUB', '').strip().lower() in ('1', 'true', 'yes', 'on')


def hub_areas():
    """The areas this hub serves (``AT_HUB_AREAS``), normalized, in order,
    without repeats; anything that is not an area is skipped."""
    out = []
    for part in os.environ.get(AREAS_ENV, '').split(','):
        area = _card.normalize_area(part.strip())
        if area is not None and area not in out:
            out.append(area)
    return out[:MAX_AREAS]


def lookup_rate() -> int:
    try:
        rate = int(os.environ.get(RATE_ENV, '') or DEFAULT_RATE)
    except ValueError:
        return DEFAULT_RATE
    return rate if rate > 0 else DEFAULT_RATE


class Hub:
    """Area cards and the rate limits on reading them."""

    def __init__(self, areas, rate=None, distrusted=None, clock=time.monotonic,
                 wallclock=time.time, logger=None):
        import logging
        self.areas = tuple(areas)
        self.rate = rate or lookup_rate()
        self.distrusted = distrusted
        self.clock = clock
        self.wallclock = wallclock
        self.logger = logger or logging.getLogger(__name__)
        self._cards = {}            # area -> {uuid: AreaCard}
        self._buckets = {}          # uuid -> (tokens, last)
        self._lock = threading.Lock()

    def _count(self):
        return sum(len(held) for held in self._cards.values())

    def publish(self, uuid, pubkey, wire):
        """File ``uuid``'s card. Returns the reply frame."""
        area = ''
        try:
            card = _card.AreaCard.from_wire(wire)
            area = card.area if isinstance(card.area, str) else ''
            now = self.wallclock()
            card.verify(now)
        except InvalidEntry as err:
            return {'op': 'hub_refused', 'area': area, 'reason': err.reason}
        if card.area not in self.areas:
            return {'op': 'hub_refused', 'area': area, 'reason': 'area'}
        if card.expiry > now + _card.MAX_TTL_SECONDS:
            return {'op': 'hub_refused', 'area': area, 'reason': 'expiry'}
        # Only the holder files: the registrant proved its key, and the card
        # must be signed by that same key, for that same uuid.
        if card.key != pubkey or card.uuid != uuid:
            return {'op': 'hub_refused', 'area': area, 'reason': 'not_holder'}
        with self._lock:
            held = self._cards.setdefault(area, {})
            old = held.get(uuid)
            if old is not None:
                if card.seq == old.seq and card.body_str == old.body_str:
                    return {'op': 'hub_published', 'area': area, 'seq': card.seq}
                if card.seq <= old.seq:
                    return {'op': 'hub_refused', 'area': area, 'reason': 'stale'}
            else:
                self._evict_locked(now)
                if len(held) >= MAX_PER_AREA or self._count() >= MAX_CARDS:
                    return {'op': 'hub_refused', 'area': area, 'reason': 'full'}
            held[uuid] = card
        self.logger.info('Hub: %s listed in %s (seq %d)', uuid[:8], area, card.seq)
        return {'op': 'hub_published', 'area': area, 'seq': card.seq}

    def withdraw(self, uuid, pubkey, area):
        area = _card.normalize_area(area) or ''
        with self._lock:
            held = self._cards.get(area, {})
            old = held.get(uuid)
            if old is not None and old.key == pubkey:
                del held[uuid]
        return {'op': 'hub_withdrawn', 'area': area}

    def forget(self, uuid):
        """Drop every card ``uuid`` holds (its holder came to be distrusted)."""
        with self._lock:
            for held in self._cards.values():
                held.pop(uuid, None)

    def _take_token(self, uuid):
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.get(uuid, (float(self.rate), now))
            tokens = min(float(self.rate), tokens + (now - last) * self.rate / 60.0)
            if tokens < 1.0:
                self._buckets[uuid] = (tokens, now)
                return False
            self._buckets[uuid] = (tokens - 1.0, now)
            return True

    def lookup(self, uuid, area):
        """``uuid``'s lookup of ``area``. Returns the reply frame."""
        folded = _card.normalize_area(area) or ''
        if not self._take_token(uuid):
            return {'op': 'hub_limited', 'area': folded}
        now = self.wallclock()
        with self._lock:
            held = self._cards.get(folded, {})
            mine = held.get(uuid)
            if mine is None or mine.is_expired(now):
                return {'op': 'hub_cards', 'area': folded, 'cards': []}
            cards = [c for u, c in held.items() if u != uuid and not c.is_expired(now)]
        cards = [c for c in cards
                 if self.distrusted is None or not self.distrusted(c.uuid, c.key)]
        # Freshest first; uuid breaks a tie, so both runtimes answer alike.
        cards.sort(key=lambda c: (-c.expiry, c.uuid))
        return {'op': 'hub_cards', 'area': folded,
                'cards': [c.to_wire() for c in cards[:LOOKUP_MAX]]}

    def _evict_locked(self, now):
        for held in self._cards.values():
            for uuid in [u for u, c in held.items() if c.is_expired(now)]:
                del held[uuid]
