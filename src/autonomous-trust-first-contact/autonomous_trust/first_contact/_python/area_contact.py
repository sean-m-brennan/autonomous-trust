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
"""Finding people nearby at an area hub. Part of first contact: registered by
:func:`.first_contact.register`, so off unless ``AT_FIRST_CONTACT`` is on.

The flow, with Alice listed and Bob looking::

  1. Alice's app lists her in an area (``app_area_publish``: the area, her
     coarse bucket inside it, the name she goes by). Her node signs an area
     card (first_contact/area_card.py) and the network process files it at each of
     her relays, again at every registration; a relay that is a hub for that
     area keeps it. The card lives an hour, and her node issues a fresh one
     while it is past half its life, for as long as she stays listed.
  2. Bob, listed in the same area, asks who else is there
     (``app_area_lookup``). Every relay he is registered at is asked, and each
     card any hub answers with is checked HERE (signature, holder, the area
     asked) rather than taken on the hub's word. The app sees one ``card``
     event per person, then ``done``.
  3. Bob's app asks one of them to become a contact
     (``app_first_contact_request`` with ``area`` and ``peer_uuid``), and from
     there it is directory_contact.py's flow unchanged: Alice's node shows the
     request to her app only for an area she is listed in, and nothing
     happens until she accepts. Both sides record an UNVERIFIED contact of
     ``area`` provenance, capped at tier 1 until the safety numbers match.

Only Alice's own listings persist (``var/at/area.cfg.json``, so each card's
``seq`` only rises and she stays listed across a restart); what a lookup found
is held in memory for :data:`FOUND_TTL_SECONDS`. Withdrawing an area stops the
refresh, and the hub drops the card at once.
"""
import json
import os
import time

from dataclasses import dataclass

from autonomous_trust.core.app_verbs import AppEvent, is_local_app_verb, refuse_remote_app_verb
from autonomous_trust.core.network.network import Network
from . import area_card as _card
from .directory import InvalidEntry
from autonomous_trust.core.config.configuration import atomic_write, Configuration
from .fc_protocol import FirstContactProtocol

#: App verbs (local IPC only). Same strings as C's AT_APP_AREA_*.
APP_AREA_PUBLISH = 'app_area_publish'
APP_AREA_WITHDRAW = 'app_area_withdraw'
APP_AREA_LOOKUP = 'app_area_lookup'
#: (Installing a community's relay roster is rendezvous's: network/roster.py.)
APP_VERBS = (APP_AREA_PUBLISH, APP_AREA_WITHDRAW, APP_AREA_LOOKUP)

#: AreaEvent.kind values. C's AT_APP_EVENT_AREA_* carry the same outcomes.
EVENT_PUBLISHED = 'area_published'      # a hub listed us (``relay``, ``seq``)
EVENT_REFUSED = 'area_refused'          # see ``reason``
EVENT_WITHDRAWN = 'area_withdrawn'
EVENT_CARD = 'area_card'                # one person a lookup found
EVENT_DONE = 'area_done'                # end of a lookup: ``count``; ``reason`` '' | 'limited'

#: Most people a lookup's answers are remembered for, and for how long: a
#: request must name someone found recently.
FOUND_MAX = 256
FOUND_TTL_SECONDS = 600
#: Most areas one node lists itself in.
LISTED_MAX = 4

AREA_STATE_FILENAME = _card.STATE_FILENAME


@dataclass
class AreaEvent(AppEvent):
    """One area outcome, reported to the app. ``ref`` echoes the app's
    request."""
    kind: str
    ref: str = ''
    area: str = ''
    bucket: str = ''
    peer_uuid: str = ''
    name: str = ''
    relay: str = ''
    reason: str = ''
    seq: int = 0
    count: int = 0


def _fc():
    from . import first_contact
    return first_contact


def _dc():
    from . import directory_contact
    return directory_contact


def register(proc) -> None:
    """Wire the handlers into an IdentityProcess (from first_contact.register)."""
    import functools
    proc._area_found = {}           # holder uuid -> (AreaCard, relay 'host:port', time)
    proc._area_lookup_refs = {}     # area -> [ref, ...] waiting on a lookup
    proc._area_publish_refs = {}    # area -> ref of the last publish/withdraw
    proc._area_invites = set()      # invitation nonces minted for an area request
    for verb, handler in ((APP_AREA_PUBLISH, handle_app_area_publish),
                          (APP_AREA_WITHDRAW, handle_app_area_withdraw),
                          (APP_AREA_LOOKUP, handle_app_area_lookup),
                          (FirstContactProtocol.hub_result, handle_hub_result),
                          (FirstContactProtocol.hub_status, handle_hub_status)):
        proc.protocol.register_handler(verb, functools.partial(handler, proc))


def _emit(proc, queues, event):
    _fc()._emit(proc, queues, event)


# -- our own listings -------------------------------------------------------------
def _state_path():
    return os.path.join(Configuration.get_data_dir(), AREA_STATE_FILENAME)


def _load_state():
    try:
        with open(_state_path()) as f:
            state = json.load(f)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(proc, state) -> bool:
    try:
        os.makedirs(Configuration.get_data_dir(), exist_ok=True)
        with atomic_write(_state_path()) as f:
            json.dump(state, f, sort_keys=True)
        return True
    except OSError as err:
        proc.logger.warning('area: cannot save %s (%s)', _state_path(), err)
        return False


def listed_areas(proc):
    """The areas we are listed in now: a card is held for each, and we have
    not withdrawn it. A contact request is shown only for one of these."""
    return {area for area, held in _load_state().items()
            if isinstance(held, dict) and held.get('card') is not None}


def _issue(proc, queues, state, area, now):
    """Sign a fresh card for ``area`` from what ``state`` holds, save it, and
    hand it to the network process. Returns the card, or None."""
    held = state[area]
    seq = int(held.get('seq', 0) or 0) + 1
    card = _card.create_card(proc.identity, area, held.get('bucket', ''),
                             held.get('name', ''), seq, now=now)
    held['seq'] = seq
    held['card'] = card.to_wire()
    if not _save_state(proc, state):
        # A seq not saved could be reissued after a restart and refused as stale.
        return None
    _dc()._to_network(proc, queues, Network.hub_publish, {'card': card.to_wire()})
    return card


def refresh(proc, queues, now=None) -> int:
    """Refile every listing, issuing a fresh card for any past half its life.
    Run at startup and from the periodic resync. Returns how many were
    handed to the network process."""
    now = now if now is not None else _dc()._now(proc)
    state = _load_state()
    n = 0
    for area in sorted(listed_areas(proc)):
        held = state[area]
        try:
            card = _card.AreaCard.from_wire(held.get('card'))
            fresh = card.expiry - now > _card.DEFAULT_TTL_SECONDS / 2
        except InvalidEntry:
            fresh = False
        if fresh:
            _dc()._to_network(proc, queues, Network.hub_publish, {'card': card.to_wire()})
            n += 1
            continue
        try:
            if _issue(proc, queues, state, area, now) is not None:
                n += 1
        except InvalidEntry as err:
            proc.logger.warning('area: cannot refresh %s (%s)', area, err)
    return n


def handle_app_area_publish(proc, queues, message) -> bool:
    """Payload: ``area``, ``bucket`` (inside it), ``name`` (may be empty),
    ``ref``."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_AREA_PUBLISH)
    fc = _fc()
    req = fc._app_payload(message)
    ref = fc._app_ref(req)
    area = _card.normalize_area(req.get('area'))
    bucket = _card.normalize_area(req.get('bucket'), 1, _card.BUCKET_MAX)
    name = req.get('name', '')
    if ref is None or area is None or bucket is None or not bucket.startswith(area) \
            or not _card.valid_name(name):
        _emit(proc, queues, AreaEvent(EVENT_REFUSED, ref=ref or '', area=area or '',
                                      reason='bad_request'))
        return True
    state = _load_state()
    if area not in listed_areas(proc) and len(listed_areas(proc)) >= LISTED_MAX:
        _emit(proc, queues, AreaEvent(EVENT_REFUSED, ref=ref, area=area, reason='full'))
        return True
    held = state.setdefault(area, {'seq': 0})
    held['bucket'], held['name'] = bucket, name
    proc._area_publish_refs[area] = ref
    try:
        card = _issue(proc, queues, state, area, _dc()._now(proc))
    except InvalidEntry as err:
        card = None
        proc.logger.warning('area: app publish refused (%s)', err)
    if card is None:
        _emit(proc, queues, AreaEvent(EVENT_REFUSED, ref=ref, area=area, reason='mint_failed'))
        return True
    proc.logger.info('area: listing us in %s (seq %d)', area, card.seq)
    return True


def handle_app_area_withdraw(proc, queues, message) -> bool:
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_AREA_WITHDRAW)
    fc = _fc()
    req = fc._app_payload(message)
    ref = fc._app_ref(req) or ''
    area = _card.normalize_area(req.get('area'))
    if area is None:
        _emit(proc, queues, AreaEvent(EVENT_REFUSED, ref=ref, reason='bad_request'))
        return True
    state = _load_state()
    held = state.get(area)
    if isinstance(held, dict):
        # Keep the seq: a later listing in the same area must still rise.
        held['card'] = None
        _save_state(proc, state)
    proc._area_publish_refs[area] = ref
    _dc()._to_network(proc, queues, Network.hub_withdraw, {'area': area})
    return True


def handle_hub_status(proc, queues, message) -> bool:
    """A hub's answer to our publish or withdraw, via the network process."""
    if not _dc()._local(message):
        proc.logger.warning('area: refusing hub_status from the wire')
        return True
    body = _fc()._app_payload(message)
    area = str(body.get('area', ''))
    kind = {'hub_published': EVENT_PUBLISHED, 'hub_refused': EVENT_REFUSED,
            'hub_withdrawn': EVENT_WITHDRAWN}.get(body.get('op'))
    if kind is None:
        return True
    _emit(proc, queues, AreaEvent(
        kind, ref=proc._area_publish_refs.get(area, ''), area=area,
        relay=str(body.get('relay', '')), reason=str(body.get('reason', '')),
        seq=int(body.get('seq', 0) or 0)))
    return True


# -- finding people nearby ---------------------------------------------------------
def handle_app_area_lookup(proc, queues, message) -> bool:
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_AREA_LOOKUP)
    fc = _fc()
    req = fc._app_payload(message)
    ref = fc._app_ref(req)
    area = _card.normalize_area(req.get('area'))
    if ref is None or area is None:
        _emit(proc, queues, AreaEvent(EVENT_REFUSED, ref=ref or '', reason='bad_request'))
        return True
    waiting = proc._area_lookup_refs.setdefault(area, [])
    waiting.append(ref)
    if len(waiting) == 1:
        _dc()._to_network(proc, queues, Network.hub_lookup, {'area': area})
    return True


def handle_hub_result(proc, queues, message) -> bool:
    """A lookup's outcome from the network process: every card any hub
    answered with. Each is checked HERE: a hub is not trusted to have checked
    it, nor to answer the area that was asked. One card per holder (the
    highest seq), never our own."""
    dc = _dc()
    if not dc._local(message):
        proc.logger.warning('area: refusing hub_result from the wire')
        return True
    body = _fc()._app_payload(message)
    area = _card.normalize_area(body.get('area')) or ''
    refs = proc._area_lookup_refs.pop(area, None) or ['']
    me = str(proc.identity.uuid).lower()
    now = dc._now(proc)
    best = {}
    for item in body.get('cards') or []:
        if not isinstance(item, dict):
            continue
        try:
            card = _card.AreaCard.from_wire(item.get('card')).verify(now=now)
        except InvalidEntry as err:
            proc.logger.warning('area: a card for %s refused (%s)', area, err)
            continue
        if card.area != area or card.uuid == me:
            continue
        held = best.get(card.uuid)
        if held is None or card.seq > held[0].seq:
            best[card.uuid] = (card, str(item.get('relay', '')))
    found = proc._area_found
    for uuid in sorted(best):
        card, relay = best[uuid]
        found.pop(uuid, None)
        found[uuid] = (card, relay, now)
    while len(found) > FOUND_MAX:
        del found[next(iter(found))]
    reason = 'limited' if body.get('limited') else ''
    for ref in refs:
        for uuid in sorted(best):
            card, relay = best[uuid]
            _emit(proc, queues, AreaEvent(EVENT_CARD, ref=ref, area=area, bucket=card.bucket,
                                          peer_uuid=uuid, name=card.name, relay=relay,
                                          seq=card.seq))
        _emit(proc, queues, AreaEvent(EVENT_DONE, ref=ref, area=area, reason=reason,
                                      count=len(best)))
    return True


def found_card(proc, uuid, area):
    """``(card, relay)`` for ``uuid`` found in ``area`` recently and still
    unexpired, or None. What an area contact request is made from."""
    held = proc._area_found.get(str(uuid).lower())
    now = _dc()._now(proc)
    if held is None or now - held[2] > FOUND_TTL_SECONDS or held[0].is_expired(now) \
            or held[0].area != area:
        return None
    return held[0], held[1]


# -- the buckets we are listed under, for rendezvous's roster hints ----------
class _AreaListings:
    """The area provider first contact gives rendezvous (relay_rosters.
    set_area_provider): a hub serving one of these buckets is preferred among
    a community's relays. Read from the file, not identity's memory: the hints
    are computed in the network process too. Mirrors C's area_listings."""

    @staticmethod
    def listed_buckets():
        state = _load_state()
        return sorted(str(held.get('bucket', '')) for held in state.values()
                      if isinstance(held, dict) and held.get('card') is not None
                      and held.get('bucket'))

    @staticmethod
    def state_path():
        return _state_path()


def _register_area_provider():
    from autonomous_trust.rendezvous import relay_rosters as _rosters
    _rosters.set_area_provider(_AreaListings)


_register_area_provider()
