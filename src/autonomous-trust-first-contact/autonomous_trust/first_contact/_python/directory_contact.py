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
"""Finding someone by handle, and asking to become their contact
(FIRST_CONTACT_PLAN Phase 3). Part of first contact: registered by
:func:`.first_contact.register`, so off unless ``AT_FIRST_CONTACT`` is on.

The flow, with Alice published and Bob looking::

  1. Alice's app hands her node an issuer's attestation for her handle
     (``app_directory_publish``). The node signs an entry
     (first_contact/directory.py) and the network process files it at each of her
     relays that is a registry, again at every registration.
  2. Bob's app asks for the handle (``app_directory_lookup``). Every relay Bob
     is registered at is asked; the first entry found comes back, and Bob's
     node checks it itself (signatures, attestation, the handle it asked for)
     rather than take the registry's word. The app sees ``found``.
  3. Bob's app asks to add her (``app_first_contact_request``). The node sends
     a signed ``first_contact_request`` to Alice through the registry's relay.
  4. Alice's node checks it (signed by the sender the envelope names, for her,
     for a handle she published) and shows it to her app (``contact_request``).
     Nothing else happens until the app says ``app_first_contact_accept``; a
     decline, or silence, sends nothing back.
  5. On accept, Alice's node mints a single-use invitation and sends it to Bob
     in a ``first_contact_accept``. Bob's node takes it only for a request it
     has outstanding to that uuid, signed by the key the entry named, and then
     runs the ordinary hello (first_contact.initiate). Both sides record an
     UNVERIFIED contact of ``directory`` provenance, capped at tier 1 until
     the safety numbers match.

All of it is in memory bar Alice's own entries (``var/at/directory.cfg.json``,
so each entry's ``seq`` only rises and entries are refiled after a restart). A
restart forgets requests in flight on both sides; the person simply asks again.
"""
import json
import os
import time

from dataclasses import dataclass

from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.app_verbs import AppEvent, is_local_app_verb, refuse_remote_app_verb
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.network.network import Network
from autonomous_trust.rendezvous import relay as _relay
from . import directory as _dir
from . import Invitation, InvalidInvitation, Provenance, create_invitation
from autonomous_trust.core.config.configuration import to_json_string, atomic_write, Configuration
from autonomous_trust.core.identity.identity import Identity, public_identity_from_canonical
from .fc_protocol import FirstContactProtocol

#: App verbs (local IPC only). Same strings as C's AT_APP_DIR_* / AT_APP_FC_*.
APP_DIR_PUBLISH = 'app_directory_publish'
APP_DIR_WITHDRAW = 'app_directory_withdraw'
APP_DIR_LOOKUP = 'app_directory_lookup'
APP_REQUEST = 'app_first_contact_request'
APP_ACCEPT = 'app_first_contact_accept'
APP_DECLINE = 'app_first_contact_decline'
APP_VERBS = (APP_DIR_PUBLISH, APP_DIR_WITHDRAW, APP_DIR_LOOKUP,
             APP_REQUEST, APP_ACCEPT, APP_DECLINE)

#: DirectoryEvent.kind values. C's AT_APP_EVENT_DIR_* carry the same outcomes.
EVENT_PUBLISHED = 'published'           # a registry filed our entry (``relay``, ``seq``)
EVENT_REFUSED = 'refused'               # see ``reason``
EVENT_WITHDRAWN = 'withdrawn'
EVENT_FOUND = 'found'                   # a lookup found ``peer_uuid``
EVENT_NOT_FOUND = 'not_found'           # ``reason``: '' | 'limited' | 'invalid'
EVENT_REQUEST_SENT = 'request_sent'
EVENT_CONTACT_REQUEST = 'contact_request'   # someone asks; ``ref`` answers it
EVENT_ACCEPTED = 'accepted'
EVENT_DECLINED = 'declined'

#: Most requests one node holds for its app to answer, and at most one per
#: sender (a newer one replaces it). Same as C's AT_DIR_REQUESTS_IN_MAX.
REQUESTS_IN_MAX = 32
#: Most looked-up entries remembered for a request to name, and for how long.
FOUND_MAX = 64
FOUND_TTL_SECONDS = 600
#: How long the invitation an accept carries is good for.
ACCEPT_INVITATION_TTL = 600

DIR_STATE_FILENAME = 'directory.cfg.json'


@dataclass
class DirectoryEvent(AppEvent):
    """One directory outcome, reported to the app. ``ref`` echoes the app's
    request, or, on ``contact_request``, is what the app answers with."""
    kind: str
    ref: str = ''
    handle: str = ''
    peer_uuid: str = ''
    nickname: str = ''
    relay: str = ''
    reason: str = ''
    seq: int = 0


@dataclass
class _OutRequest:
    ref: str
    nonce: str
    key: str
    handle: str
    deadline: float
    area: str = ''


@dataclass
class _InRequest:
    sender: Identity
    handle: str
    relays: tuple
    expiry: float
    area: str = ''


def _now(proc) -> float:
    """This node's directory clock: wall clock plus ``proc._dir_clock_advance``,
    a test seam so a scenario can let an hour pass between a request and its
    accept. Every directory deadline reads it; the invitation an accept carries
    keeps its own clock. C twin: at_dir_contact_advance_clock."""
    return time.time() + float(getattr(proc, '_dir_clock_advance', 0.0) or 0.0)


def _fc():
    from . import first_contact
    return first_contact


def register(proc) -> None:
    """Wire the handlers into an IdentityProcess (from first_contact.register)."""
    import functools
    proc._dir_found = {}            # handle -> (DirectoryEntry, relay 'host:port', time)
    proc._dir_lookup_refs = {}      # handle -> [ref, ...] waiting on a lookup
    proc._dir_publish_refs = {}     # handle -> ref of the last publish/withdraw
    proc._dir_out = {}              # holder uuid -> _OutRequest
    proc._dir_in = {}               # request nonce -> _InRequest
    proc._dir_invites = set()       # invitation nonces minted for an accept
    proc._dir_clock_advance = 0.0   # test seam: seconds added to the directory clock
    for verb, handler in ((APP_DIR_PUBLISH, handle_app_dir_publish),
                          (APP_DIR_WITHDRAW, handle_app_dir_withdraw),
                          (APP_DIR_LOOKUP, handle_app_dir_lookup),
                          (APP_REQUEST, handle_app_request),
                          (APP_ACCEPT, handle_app_accept),
                          (APP_DECLINE, handle_app_decline),
                          (FirstContactProtocol.dir_result, handle_dir_result),
                          (FirstContactProtocol.dir_status, handle_dir_status),
                          (FirstContactProtocol.contact_request, handle_contact_request),
                          (FirstContactProtocol.contact_accept, handle_contact_accept)):
        proc.protocol.register_handler(verb, functools.partial(handler, proc))


def _emit(proc, queues, event):
    _fc()._emit(proc, queues, event)


def _to_network(proc, queues, verb, payload):
    msg = Message(CfgIds.network, verb, to_json_string(payload),
                  to_whom=None, from_whom=None)
    queues[CfgIds.network].put(msg, block=True, timeout=proc.q_cadence)


def _local(message) -> bool:
    return getattr(message, 'from_whom', None) is None


# -- our own entries ------------------------------------------------------------
def _state_path():
    return os.path.join(Configuration.get_data_dir(), DIR_STATE_FILENAME)


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
        proc.logger.warning('directory: cannot save %s (%s)', _state_path(), err)
        return False


def restore_entries(proc, queues) -> int:
    """At startup: hand every unexpired entry of ours to the network process
    to refile (registries hold entries in memory). Returns how many."""
    n = 0
    now = _now(proc)
    for handle, held in _load_state().items():
        try:
            entry = _dir.DirectoryEntry.from_wire(held.get('entry'))
        except (_dir.InvalidEntry, AttributeError):
            continue
        if entry.is_expired(now):
            continue
        _to_network(proc, queues, Network.dir_publish, {'entry': entry.to_wire()})
        n += 1
    if n:
        proc.logger.info('directory: refiling %d entr%s of ours', n, 'y' if n == 1 else 'ies')
    return n


def _published_handles(proc):
    now = _now(proc)
    out = set()
    for handle, held in _load_state().items():
        try:
            if not _dir.DirectoryEntry.from_wire(held.get('entry')).is_expired(now):
                out.add(handle)
        except (_dir.InvalidEntry, AttributeError):
            continue
    return out


def handle_app_dir_publish(proc, queues, message) -> bool:
    """Payload: ``attestation`` ({body, sig} or its JSON), ``visibility``
    ('anyone' | 'published', default 'anyone'), ``ref``."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_DIR_PUBLISH)
    fc = _fc()
    req = fc._app_payload(message)
    ref = fc._app_ref(req)
    if ref is None:
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, reason='bad_request'))
        return True
    visibility = req.get('visibility', _dir.VISIBILITY_ANYONE)
    try:
        att = _dir.Attestation.from_wire(req.get('attestation'))
        att.verify(now=_now(proc))
    except _dir.InvalidEntry as err:
        proc.logger.warning('directory: app publish refused (%s)', err)
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, reason=err.reason))
        return True
    if visibility not in _dir.VISIBILITIES:
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, handle=att.handle,
                                           reason='bad_request'))
        return True
    state = _load_state()
    seq = int((state.get(att.handle) or {}).get('seq', 0) or 0) + 1
    try:
        entry = _dir.create_entry(proc.identity, att, seq, visibility, now=_now(proc))
    except _dir.InvalidEntry as err:
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, handle=att.handle,
                                           reason=err.reason))
        return True
    state[att.handle] = {'seq': seq, 'entry': entry.to_wire()}
    if not _save_state(proc, state):
        # A seq not saved could be reissued after a restart and refused as stale.
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, handle=att.handle,
                                           reason='mint_failed'))
        return True
    proc._dir_publish_refs[att.handle] = ref
    _to_network(proc, queues, Network.dir_publish, {'entry': entry.to_wire()})
    proc.logger.info('directory: publishing %s (seq %d, %s)', att.handle, seq, visibility)
    return True


def handle_app_dir_withdraw(proc, queues, message) -> bool:
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_DIR_WITHDRAW)
    fc = _fc()
    req = fc._app_payload(message)
    ref = fc._app_ref(req) or ''
    handle = _dir.normalize_handle(req.get('handle'))
    if handle is None:
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, reason='bad_request'))
        return True
    state = _load_state()
    held = state.pop(handle, None)
    if held is not None:
        # Keep the seq: a later publish of the same handle must still rise.
        state[handle] = {'seq': held.get('seq', 0), 'entry': None}
        _save_state(proc, state)
    proc._dir_publish_refs[handle] = ref
    _to_network(proc, queues, Network.dir_withdraw, {'handle': handle})
    return True


def handle_dir_status(proc, queues, message) -> bool:
    """A registry's answer to our publish or withdraw, via the network process."""
    if not _local(message):
        proc.logger.warning('directory: refusing dir_status from the wire')
        return True
    body = _fc()._app_payload(message)
    handle = str(body.get('handle', ''))
    kind = {'dir_published': EVENT_PUBLISHED, 'dir_refused': EVENT_REFUSED,
            'dir_withdrawn': EVENT_WITHDRAWN}.get(body.get('op'))
    if kind is None:
        return True
    _emit(proc, queues, DirectoryEvent(
        kind, ref=proc._dir_publish_refs.get(handle, ''), handle=handle,
        relay=str(body.get('relay', '')), reason=str(body.get('reason', '')),
        seq=int(body.get('seq', 0) or 0)))
    return True


# -- finding someone -----------------------------------------------------------
def handle_app_dir_lookup(proc, queues, message) -> bool:
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_DIR_LOOKUP)
    fc = _fc()
    req = fc._app_payload(message)
    ref = fc._app_ref(req)
    handle = _dir.normalize_handle(req.get('handle'))
    if ref is None or handle is None:
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref or '', reason='bad_request'))
        return True
    waiting = proc._dir_lookup_refs.setdefault(handle, [])
    waiting.append(ref)
    if len(waiting) == 1:
        _to_network(proc, queues, Network.dir_lookup, {'handle': handle})
    return True


def handle_dir_result(proc, queues, message) -> bool:
    """A lookup's outcome from the network process. The entry is checked HERE:
    a registry is not trusted to have checked it, nor to answer the handle
    that was asked."""
    if not _local(message):
        proc.logger.warning('directory: refusing dir_result from the wire')
        return True
    body = _fc()._app_payload(message)
    handle = _dir.normalize_handle(body.get('handle')) or ''
    refs = proc._dir_lookup_refs.pop(handle, None) or ['']
    wire = body.get('entry')
    entry, reason = None, 'limited' if body.get('limited') else ''
    if isinstance(wire, dict):
        try:
            entry = _dir.DirectoryEntry.from_wire(wire).verify(now=_now(proc))
            if entry.handle != handle:
                raise _dir.InvalidEntry('the registry answered another handle', 'mismatch')
        except _dir.InvalidEntry as err:
            proc.logger.warning('directory: entry for %s refused (%s)', handle, err)
            entry, reason = None, 'invalid'
    if entry is None:
        for ref in refs:
            _emit(proc, queues, DirectoryEvent(EVENT_NOT_FOUND, ref=ref, handle=handle,
                                               reason=reason))
        return True
    relay = str(body.get('relay', ''))
    found = proc._dir_found
    found[handle] = (entry, relay, _now(proc))
    while len(found) > FOUND_MAX:
        del found[next(iter(found))]
    nickname = str((entry.identity_json or {}).get('nickname', '') or '')
    for ref in refs:
        _emit(proc, queues, DirectoryEvent(EVENT_FOUND, ref=ref, handle=handle,
                                           peer_uuid=entry.uuid, nickname=nickname,
                                           relay=relay))
    return True


def _own_hints(proc):
    fc = _fc()
    return [fc._own_relay_hint(proc, ep, pin) for ep, pin in _relay.own_relay_hints()]


def _area_label(area) -> str:
    """How an area request is named in a DirectoryEvent's ``handle``: the one
    string field the app already shows for "found by"."""
    return 'area:' + area


def handle_app_request(proc, queues, message) -> bool:
    """Ask the holder of a handle we looked up to become our contact.
    Payload: ``handle``, ``ref``; or, for someone an area lookup found
    (first_contact/area_contact.py), ``area``, ``peer_uuid``, ``ref``."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_REQUEST)
    fc = _fc()
    req = fc._app_payload(message)
    ref = fc._app_ref(req)
    area = ''
    if 'area' in req:
        from .area_card import normalize_area
        from . import area_contact
        area = normalize_area(req.get('area')) or ''
        if ref is None or not area:
            _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref or '',
                                               reason='bad_request'))
            return True
        handle = _area_label(area)
        found = area_contact.found_card(proc, req.get('peer_uuid', ''), area)
        if found is None:
            _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, handle=handle,
                                               reason='unknown_handle'))
            return True
        entry, relay = found
    else:
        handle = _dir.normalize_handle(req.get('handle'))
        if ref is None or handle is None:
            _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref or '',
                                               reason='bad_request'))
            return True
        found = proc._dir_found.get(handle)
        if found is None or _now(proc) - found[2] > FOUND_TTL_SECONDS \
                or found[0].is_expired(_now(proc)):
            _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, handle=handle,
                                               reason='unknown_handle'))
            return True
        entry, relay, _t = found
    if entry.uuid == str(proc.identity.uuid).lower():
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, handle=handle,
                                           reason='bad_request'))
        return True
    try:
        holder = public_identity_from_canonical(entry.identity_json)
    except (ValueError, TypeError, KeyError, AttributeError):
        holder = None
    if holder is None:
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, handle=handle,
                                           reason='invalid'))
        return True
    # The registry relay found the entry, and we are registered there: name it
    # first, so the holder can answer the way the request came.
    route = (['relay://' + relay] if relay else []) + _own_hints(proc)
    hints = []
    for hint in route:
        endpoint, _pin = _relay.parse_hint(hint)
        if endpoint is not None and endpoint not in [_relay.parse_hint(h)[0] for h in hints]:
            hints.append(hint)
    request = _dir.create_request(proc.identity, entry, relays=hints[:_dir.REQUEST_MAX_RELAYS],
                                  now=_now(proc))
    proc._dir_out[entry.uuid] = _OutRequest(ref=ref, nonce=request.nonce, key=entry.key,
                                            handle=handle, deadline=float(request.expiry),
                                            area=area)
    fc._send_relay_route(proc, queues, holder.uuid, hints[:1])
    msg = Message(proc.name, FirstContactProtocol.contact_request, request.to_json(),
                  to_whom=holder, from_whom=proc.identity, encrypt=False)
    queues[CfgIds.network].put(msg, block=True, timeout=proc.q_cadence)
    proc.logger.info('directory: asked %s (%s) to become a contact', handle, entry.uuid[:8])
    _emit(proc, queues, DirectoryEvent(EVENT_REQUEST_SENT, ref=ref, handle=handle,
                                       peer_uuid=entry.uuid, nickname=holder.nickname))
    return True


# -- being asked -----------------------------------------------------------------
def handle_contact_request(proc, queues, message) -> bool:
    """Someone found us by a handle we published and asks to be a contact.
    Checked, then handed to OUR APP to decide -- never answered on its own."""
    fc = _fc()
    sender = message.from_whom
    if not isinstance(sender, Identity):
        proc.logger.warning('directory: contact request with no sender identity; ignoring')
        return True
    try:
        request = _dir.ContactRequest.from_wire(message.obj).verify(now=_now(proc))
    except _dir.InvalidEntry as err:
        proc.logger.warning('directory: contact request refused (%s)', err)
        return True
    me = str(proc.identity.uuid).lower()
    if request.sender != str(sender.uuid).lower() or request.key != fc._signing_key(sender):
        proc.logger.warning('directory: contact request not signed by its sender; ignoring')
        return True
    if request.to != me or request.sender == me:
        proc.logger.warning('directory: contact request not addressed to us; ignoring')
        return True
    if request.area is not None:
        from . import area_contact
        if request.area not in area_contact.listed_areas(proc):
            proc.logger.warning('directory: contact request via area %s, where we are '
                                'not listed; ignoring', request.area)
            return True
        found_by = _area_label(request.area)
    elif request.handle not in _published_handles(proc):
        proc.logger.warning('directory: contact request for %s, which we do not '
                            'publish; ignoring', request.handle)
        return True
    else:
        found_by = request.handle
    store = fc._contacts_store(proc)
    if str(sender.uuid) in store:
        proc.logger.info('directory: %s asked again, but is already a contact',
                         sender.nickname)
        return True
    now = _now(proc)
    held = proc._dir_in
    for nonce in [n for n, r in held.items()
                  if r.expiry <= now or str(r.sender.uuid) == str(sender.uuid)]:
        del held[nonce]
    held[request.nonce] = _InRequest(sender=sender, handle=found_by,
                                     relays=tuple(request.relays),
                                     expiry=float(request.expiry),
                                     area=request.area or '')
    while len(held) > REQUESTS_IN_MAX:
        del held[next(iter(held))]
    proc.logger.info('directory: %s asks to become a contact (via %s)',
                     sender.nickname, found_by)
    _emit(proc, queues, DirectoryEvent(EVENT_CONTACT_REQUEST, ref=request.nonce,
                                       handle=found_by, peer_uuid=str(sender.uuid),
                                       nickname=sender.nickname))
    return True


def _take_in_request(proc, queues, message, verb):
    fc = _fc()
    req = fc._app_payload(message)
    ref = str(req.get('ref', '') or '')
    held = proc._dir_in.pop(ref, None)
    if held is None or held.expiry <= _now(proc):
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref[:fc.REF_MAX],
                                           reason='unknown_request'))
        return ref, None
    return ref, held


def handle_app_accept(proc, queues, message) -> bool:
    """Our app accepts a request (payload ``ref`` = the request's). Mint a
    single-use invitation and send it to the requester."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_ACCEPT)
    fc = _fc()
    ref, held = _take_in_request(proc, queues, message, APP_ACCEPT)
    if held is None:
        return True
    try:
        invitation = create_invitation(proc.identity, rendezvous=_own_hints(proc),
                                       ttl_seconds=ACCEPT_INVITATION_TTL)
    except (ValueError, TypeError, AttributeError) as err:
        proc.logger.error('directory: could not mint an invitation (%s)', err)
        _emit(proc, queues, DirectoryEvent(EVENT_REFUSED, ref=ref, reason='mint_failed'))
        return True
    # The hello this invitation brings back reports under the request's ref,
    # and records a directory-provenance contact.
    fc._remember_minted(proc, invitation.nonce, ref)
    if held.area:
        proc._area_invites.add(invitation.nonce)
    else:
        proc._dir_invites.add(invitation.nonce)
    fc._send_relay_route(proc, queues, held.sender.uuid, list(held.relays))
    msg = Message(proc.name, FirstContactProtocol.contact_accept,
                  to_json_string({'nonce': ref, 'invitation': invitation.encode()}),
                  to_whom=held.sender, from_whom=proc.identity, encrypt=False)
    queues[CfgIds.network].put(msg, block=True, timeout=proc.q_cadence)
    proc.logger.info('directory: accepted %s', held.sender.nickname)
    _emit(proc, queues, DirectoryEvent(EVENT_ACCEPTED, ref=ref, handle=held.handle,
                                       peer_uuid=str(held.sender.uuid),
                                       nickname=held.sender.nickname))
    return True


def handle_app_decline(proc, queues, message) -> bool:
    """Our app declines. Nothing goes back: the requester learns nothing it
    could not learn from silence."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_DECLINE)
    ref, held = _take_in_request(proc, queues, message, APP_DECLINE)
    if held is not None:
        _emit(proc, queues, DirectoryEvent(EVENT_DECLINED, ref=ref, handle=held.handle,
                                           peer_uuid=str(held.sender.uuid),
                                           nickname=held.sender.nickname))
    return True


def handle_contact_accept(proc, queues, message) -> bool:
    """The holder accepted our request: take its invitation, and only for a
    request we have outstanding to that uuid, signed by the key its entry
    named. Then the ordinary hello."""
    fc = _fc()
    holder = message.from_whom
    if not isinstance(holder, Identity):
        proc.logger.warning('directory: accept with no sender identity; ignoring')
        return True
    uuid = str(holder.uuid).lower()
    out = proc._dir_out.get(uuid)
    if out is None or out.deadline <= _now(proc):
        proc.logger.warning('directory: accept from %s, to whom no request is '
                            'outstanding; ignoring', uuid[:8])
        return True
    payload = fc._app_payload(message)
    if fc._signing_key(holder) != out.key or payload.get('nonce') != out.nonce:
        proc.logger.warning('directory: accept from %s does not answer our request '
                            '(key or nonce); ignoring', uuid[:8])
        return True
    blob = payload.get('invitation')
    try:
        invitation = Invitation.decode(blob)
        inviter = invitation.verify_signature()
    except InvalidInvitation as err:
        proc.logger.warning('directory: accept from %s carries a bad invitation (%s)',
                            uuid[:8], err)
        return True
    if str(inviter.uuid).lower() != uuid or fc._signing_key(inviter) != out.key \
            or invitation.is_expired():
        proc.logger.warning('directory: accept from %s carries an invitation that is '
                            'not its own, or has expired; ignoring', uuid[:8])
        return True
    del proc._dir_out[uuid]
    fc.initiate(proc, queues, blob, ref=out.ref,
                provenance=Provenance.area if out.area else Provenance.directory)
    fc._emit(proc, queues, fc.FirstContactEvent(
        fc.EVENT_HELLO_SENT, ref=out.ref, peer_uuid=str(inviter.uuid),
        nickname=inviter.nickname, role='initiator'))
    return True
