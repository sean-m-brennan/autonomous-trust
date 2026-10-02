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
"""Pairing one's own devices, and keeping their address books the same
(FIRST_CONTACT_PLAN Phase 4, live pairing, the wire half).

**Pairing.** The old device mints an ordinary invitation whose signed body
carries ``purpose: "pair"`` (``app_first_contact_invite`` with ``pair:
true``); the new device redeems it (``app_first_contact_initiate``) and the
two run the usual hello / hello_ack. Neither records a contact. Each pushes
its device cert, sealed, as after any handshake, and on receiving the other's
checks that both certs name the same operator key
(:meth:`..contacts.siblings.Siblings.add`). A match makes them siblings, in
``siblings.cfg.json``, and the app hears ``sibling_paired``. Anything else --
no cert, another operator, nothing within :data:`PAIR_WAIT_SECONDS` -- drops
the direct peer, and the app hears ``refused`` with reason ``not_sibling``. A
pair link never becomes a contact.

**Sync.** Siblings swap sealed ``contacts_sync`` payloads
(:mod:`..contacts.sync`): the whole address book right after pairing and at
startup, and the contacts that changed after each local edit. A full payload
at startup carries ``reply: true``, and the receiver answers once with its own
(``reply: false``), so both converge and nothing loops. Only a sibling's
payload is taken. A change it brings has the effect a local one would: a
contact added is admitted and routed, a removed one's peers are dropped, and
the app hears ``contact`` / ``removed`` with ``origin: "sibling"``.

Siblings are reached like contacts: re-admitted and routed at startup from
the hints in their file, and sent our reachability record, whose newer copies
they apply to ours. They are never tier-capped. Same messages and rules as
C's ``identity/sibling_sync.{h,c}``.
"""
import json
import os
import time
from dataclasses import dataclass
from queue import Full

from autonomous_trust.core.system import CfgIds
from . import sync as _sync
from .siblings import Siblings
from autonomous_trust.rendezvous import relay as _relay
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.identity.identity import Identity
from .fc_protocol import FirstContactProtocol

#: How long a pair handshake waits for the other side's device cert.
PAIR_WAIT_SECONDS = 120

#: The refusal reason when a pair handshake does not end in two siblings.
REASON_NOT_SIBLING = 'not_sibling'

#: Where a synced change came from, on the app's contact events.
ORIGIN_SIBLING = 'sibling'

#: App verbs (local only).
APP_SIBLING_LIST = 'app_sibling_list'
APP_SIBLING_REMOVE = 'app_sibling_remove'
APP_VERBS = (APP_SIBLING_LIST, APP_SIBLING_REMOVE)

#: Event kinds. ``sibling_paired`` is a FirstContactEvent (``ref``,
#: ``peer_uuid``, ``nickname``, ``role``); ``sibling`` / ``siblings_done``
#: are ContactEvents (``peer_uuid``, ``nickname``, ``added_at``; ``count``).
EVENT_SIBLING_PAIRED = 'sibling_paired'
EVENT_SIBLING = 'sibling'
EVENT_SIBLINGS_DONE = 'siblings_done'
EVENT_SIBLING_REMOVED = 'sibling_removed'   # ContactEvent: ``peer_dropped``


def _fc():
    from . import first_contact
    return first_contact


def _dc():
    from . import device_contact
    return device_contact


@dataclass
class _Pairing:
    """A pair handshake waiting for the other side's device cert."""
    ref: str
    role: str                 # 'inviter' or 'initiator'
    deadline: float
    hints: tuple = ()         # where the other side was reached
    nickname: str = ''        # for the refusal, should the peer be gone


def register(proc) -> None:
    import functools
    proc._siblings = None
    proc._pairing = {}
    proc._sync_seen = None
    proc.protocol.register_handler(FirstContactProtocol.contacts_sync,
                                   functools.partial(handle_contacts_sync, proc))
    proc.protocol.register_handler(APP_SIBLING_LIST,
                                   functools.partial(handle_app_sibling_list, proc))
    proc.protocol.register_handler(APP_SIBLING_REMOVE,
                                   functools.partial(handle_app_sibling_remove, proc))


# -- the sibling file ---------------------------------------------------------

def siblings(proc) -> Siblings:
    """This node's siblings, cached on the process (only the identity process
    writes the file)."""
    sib = getattr(proc, '_siblings', None)
    if sib is None:
        sib = proc._siblings = Siblings.load()
    return sib


def _save_siblings(proc, sib) -> None:
    try:
        sib.save()
    except OSError as err:
        proc.logger.warning('could not persist the sibling list (%s)', err)


_sibling_cache = {}


def sibling_uuids():
    """The uuids in siblings.cfg.json, re-read only when it changes. For the
    tier cap, which runs in processes that do not hold the list."""
    path = Siblings.default_path()
    try:
        key = (path, os.stat(path).st_mtime_ns)
    except OSError:
        return frozenset()
    if key not in _sibling_cache:
        _sibling_cache.clear()
        _sibling_cache[key] = frozenset(Siblings.load().uuids())
    return _sibling_cache[key]


def is_sibling(proc, identity) -> bool:
    """Whether ``identity`` is one of our siblings, under the key we hold."""
    dev = siblings(proc).get(str(identity.uuid))
    return dev is not None and \
        _fc()._signing_key(dev.identity) == _fc()._signing_key(identity)


def _sibling_peers(proc):
    """Every sibling that is a peer right now."""
    out = []
    for uuid in siblings(proc).uuids():
        peer = proc.peers.find_by_uuid(uuid)
        if peer is not None:
            out.append(peer)
    return out


def _route(proc, queues, uuid, hints):
    fc = _fc()
    hints = fc._relay_hints(list(hints))
    have = {_relay.parse_endpoint(h) for h in hints}
    hints += [fc._own_relay_hint(proc, ep, pin) for ep, pin in _relay.own_relay_hints()
              if ep not in have]
    fc._send_relay_route(proc, queues, uuid, hints[:_relay.MAX_RELAYS])


def _admit(proc, queues, identity, hints):
    _fc()._admit_direct_peer(proc, queues, identity)
    _route(proc, queues, identity.uuid, hints)


# -- pairing --------------------------------------------------------------------

def can_pair(proc) -> bool:
    """Whether this node has a device cert of its own to pair under."""
    return _dc().own_cert(proc) is not None


def _pending(proc):
    """Pair handshakes waiting for a cert: uuid -> :class:`_Pairing`."""
    pending = getattr(proc, '_pairing', None)
    if pending is None:
        pending = proc._pairing = {}
    return pending


def begin(proc, queues, identity, ref, role, hints=()) -> None:
    """A pair handshake with ``identity`` is done: wait for its cert, and
    send ours. Older handshakes past their wait are refused first, so the
    wait holds even where the periodic sweep does not run."""
    expire(proc, queues)
    _pending(proc)[str(identity.uuid)] = _Pairing(
        ref, role, time.time() + PAIR_WAIT_SECONDS, tuple(hints),
        getattr(identity, 'nickname', '') or '')
    _dc().push_own_cert(proc, queues, [identity])


def refuse(proc, queues, identity, ref, role, drop=True) -> None:
    """End a pair handshake that did not make two siblings."""
    fc = _fc()
    if drop:
        fc._drop_direct_peer(proc, queues, identity.uuid)
    proc.logger.info('first contact: %s is not a sibling; pairing refused',
                     getattr(identity, 'nickname', '') or str(identity.uuid)[:8])
    fc._emit(proc, queues, fc.FirstContactEvent(
        fc.EVENT_REFUSED, ref=ref, peer_uuid=str(identity.uuid),
        nickname=getattr(identity, 'nickname', '') or '',
        reason=REASON_NOT_SIBLING, role=role))


def on_device_cert(proc, queues, sender, cert) -> bool:
    """A device cert from ``sender``: True if it answers a pair handshake
    (and has been dealt with), False to handle it as a contact's."""
    entry = _pending(proc).pop(str(sender.uuid), None)
    if entry is None:
        return False
    if entry.deadline <= time.time():
        refuse(proc, queues, sender, entry.ref, entry.role)
        return True
    sib = siblings(proc)
    reason = sib.add(sender.publish(), cert, _dc().own_cert(proc))
    if reason:
        proc.logger.info('first contact: pairing with %s refused (%s)',
                         sender.nickname, reason)
        refuse(proc, queues, sender, entry.ref, entry.role)
        return True
    sib.set_hints(sender.uuid, entry.hints)
    _save_siblings(proc, sib)
    fc = _fc()
    _route(proc, queues, sender.uuid, entry.hints)
    fc._push_own_record(proc, queues, [sender])
    proc.logger.info('first contact: paired with %s, another device of ours',
                     sender.nickname)
    fc._emit(proc, queues, fc.FirstContactEvent(
        EVENT_SIBLING_PAIRED, ref=entry.ref, peer_uuid=str(sender.uuid),
        nickname=sender.nickname, role=entry.role))
    send_full(proc, queues, [sender], reply=False)
    return True


def expire(proc, queues, now=None) -> int:
    """Refuse every pair handshake whose cert never came. Returns how many."""
    now = now if now is not None else time.time()
    pending = _pending(proc)
    late = [(u, p) for u, p in pending.items() if p.deadline <= now]
    for uuid, entry in late:
        del pending[uuid]
        peer = proc.peers.find_by_uuid(uuid)
        refuse(proc, queues, _Unnamed(uuid, entry.nickname),
               entry.ref, entry.role, drop=peer is not None)
    return len(late)


class _Unnamed:
    """A peer already gone from Peers, named only by its uuid."""

    def __init__(self, uuid, nickname=''):
        self.uuid, self.nickname = uuid, nickname


# -- sync -----------------------------------------------------------------------

def _versions(store):
    seen = {('c', u): c.version() for u, c in store.contacts.items()}
    seen.update({('t', u): t for u, t in store.tombstones.items()})
    return seen


def _send(proc, queues, peers, payload) -> int:
    if CfgIds.network not in queues:
        return 0
    body = json.dumps(payload)
    sent = 0
    for peer in peers:
        msg = Message(proc.name, FirstContactProtocol.contacts_sync, body,
                      to_whom=peer, from_whom=proc.identity)
        try:
            queues[CfgIds.network].put(msg, block=True, timeout=proc.q_cadence)
            sent += 1
        except Full:
            proc.logger.warning('first contact: network queue full; address book '
                                'not synced to %s', str(peer.uuid)[:8])
    return sent


def send_full(proc, queues, peers=None, reply=False) -> int:
    """The whole address book to ``peers`` (default: every sibling that is a
    peer). ``reply`` asks each to answer once with its own."""
    store = _fc()._contacts_store(proc)
    payload = _sync.build(store)
    if reply:
        payload['reply'] = True
    if getattr(proc, '_sync_seen', None) is None:
        proc._sync_seen = _versions(store)
    return _send(proc, queues, _sibling_peers(proc) if peers is None else peers, payload)


def push_changes(proc, queues) -> int:
    """After a local edit: the contacts and removals that changed since the
    last push, to every sibling that is a peer. Returns how many were sent."""
    store = _fc()._contacts_store(proc)
    now = _versions(store)
    before = getattr(proc, '_sync_seen', None)
    proc._sync_seen = now
    if before is None:
        return 0
    changed = sorted({u for (kind, u), v in now.items() if before.get((kind, u)) != v})
    peers = _sibling_peers(proc)
    if not changed or not peers:
        return 0
    return _send(proc, queues, peers, _sync.build(store, changed))


def handle_contacts_sync(proc, queues, message) -> bool:
    """A sibling's address book, or the part of it that changed. Taken only
    from a sibling; answered only when it asks (``reply``)."""
    fc = _fc()
    sender = message.from_whom
    if not isinstance(sender, Identity) or not is_sibling(proc, sender):
        proc.logger.debug('first contact: address book from %s, not a sibling; '
                          'ignored', str(getattr(sender, 'uuid', ''))[:8])
        return True
    payload = fc._app_payload(message)
    store = fc._contacts_store(proc)
    before = {u: c for u, c in store.contacts.items()}
    exclude = [str(proc.identity.uuid)] + siblings(proc).uuids()
    try:
        changes = _sync.merge(store, payload, exclude=exclude)
    except _sync.InvalidSync as err:
        proc.logger.warning('first contact: address book from %s refused (%s)',
                            sender.nickname, err)
        return True
    if changes:
        fc._save_book(proc, store)
        # What we just took is not ours to push back.
        if getattr(proc, '_sync_seen', None) is not None:
            proc._sync_seen.update(_versions(store))
        _apply(proc, queues, store, before, changes)
        proc.logger.info('first contact: %d address-book change(s) from %s',
                         len(changes), sender.nickname)
    if isinstance(payload, dict) and payload.get('reply') is True:
        send_full(proc, queues, [sender], reply=False)
    return True


def _apply(proc, queues, store, before, changes, origin=ORIGIN_SIBLING) -> None:
    """Give each synced (or restored, first_contact/backup_contact.py) change the
    effect the same local edit has; the app's events carry ``origin``."""
    fc = _fc()
    me = str(proc.identity.uuid)
    for uuid, action in changes:
        if action == 'added':
            contact = store.contacts[uuid]
            for ident in contact.identities():
                if str(ident.uuid) != me:
                    _admit(proc, queues, ident, contact.rendezvous)
            # They know our sibling, not this device: say it is one of ours.
            _dc().announce(proc, queues, [contact])
            fc._emit(proc, queues, fc._contact_event(fc.EVENT_CONTACT, contact,
                                                     origin=origin))
        elif action == 'updated':
            fc._emit(proc, queues, fc._contact_event(fc.EVENT_CONTACT,
                                                     store.contacts[uuid],
                                                     origin=origin))
        elif action == 'removed' and uuid in before:
            gone = before[uuid]
            dropped = False
            for ident in gone.identities():
                dropped = fc._drop_direct_peer(proc, queues, ident.uuid) or dropped
            fc._emit(proc, queues, fc._contact_event(fc.EVENT_REMOVED, gone,
                                                     peer_dropped=dropped,
                                                     origin=origin))


# -- startup, reachability ------------------------------------------------------

def restore(proc, queues) -> int:
    """At startup: re-admit and route every sibling, send each our record,
    and swap address books. Returns how many siblings."""
    sib = siblings(proc)
    # Where change tracking starts: what is on disk now.
    proc._sync_seen = _versions(_fc()._contacts_store(proc))
    idents = []
    for dev in sib.devices:
        _admit(proc, queues, dev.identity, sib.hints.get(dev.uuid, []))
        idents.append(dev.identity)
    if idents:
        _fc()._push_own_record(proc, queues, idents)
        send_full(proc, queues, idents, reply=True)
        proc.logger.info('first contact: reconnecting %d sibling device(s)', len(idents))
    return len(idents)


def apply_record(proc, queues, record) -> bool:
    """A reachability record for one of our siblings: keep its newer hints.
    False if ``record`` is not a sibling's."""
    sib = siblings(proc)
    dev = sib.get(record.uuid)
    if dev is None:
        return False
    if _relay._signing_hex(dev.identity).lower() != record.key:
        proc.logger.warning('first contact: record for sibling %s is signed by '
                            'another key; refused', record.uuid[:8])
        return True
    if record.seq <= sib.reach_seq.get(dev.uuid, 0):
        return True
    sib.reach_seq[dev.uuid] = record.seq
    sib.set_hints(dev.uuid, _sync._merge_hints(record.relays + record.endpoints,
                                               sib.hints.get(dev.uuid, [])))
    _save_siblings(proc, sib)
    _route(proc, queues, dev.identity.uuid, sib.hints[dev.uuid])
    return True


# -- app verbs ------------------------------------------------------------------

def handle_app_sibling_list(proc, queues, message) -> bool:
    """One ``sibling`` event per sibling, then ``siblings_done`` with the
    count."""
    fc = _fc()
    if not fc.is_local_app_verb(proc, message):
        return fc.refuse_remote_app_verb(proc, message, APP_SIBLING_LIST)
    ref = fc._app_ref(fc._app_payload(message))
    if ref is None:
        fc._emit(proc, queues, fc.FirstContactEvent(fc.EVENT_REFUSED, reason='bad_request'))
        return True
    sib = siblings(proc)
    for dev in sib.devices:
        fc._emit(proc, queues, fc.ContactEvent(
            EVENT_SIBLING, ref=ref, peer_uuid=dev.uuid,
            nickname=getattr(dev.identity, 'nickname', '') or '',
            added_at=float(dev.added_at)))
    fc._emit(proc, queues, fc.ContactEvent(EVENT_SIBLINGS_DONE, ref=ref,
                                           count=len(sib)))
    return True


def handle_app_sibling_remove(proc, queues, message) -> bool:
    """Unpair (``{ref, peer}``): the sibling leaves siblings.cfg.json and its
    direct peer is dropped. Not synced: each device picks whom it syncs with.
    Answers ``sibling_removed``."""
    fc = _fc()
    if not fc.is_local_app_verb(proc, message):
        return fc.refuse_remote_app_verb(proc, message, APP_SIBLING_REMOVE)
    req = fc._app_payload(message)
    ref = fc._app_ref(req)
    if ref is None:
        fc._emit(proc, queues, fc.FirstContactEvent(fc.EVENT_REFUSED, reason='bad_request'))
        return True
    peer = req.get('peer') if isinstance(req, dict) else None
    sib = siblings(proc)
    dev = sib.get(peer) if isinstance(peer, str) else None
    if dev is None:
        fc._emit(proc, queues, fc.FirstContactEvent(
            fc.EVENT_REFUSED, ref=ref, peer_uuid=peer if isinstance(peer, str) else '',
            reason='unknown_contact'))
        return True
    sib.remove(dev.uuid)
    _save_siblings(proc, sib)
    dropped = fc._drop_direct_peer(proc, queues, dev.uuid)
    proc.logger.info('first contact: unpaired %s', dev.uuid[:8])
    fc._emit(proc, queues, fc.ContactEvent(
        EVENT_SIBLING_REMOVED, ref=ref, peer_uuid=dev.uuid,
        nickname=getattr(dev.identity, 'nickname', '') or '',
        peer_dropped=dropped))
    return True
