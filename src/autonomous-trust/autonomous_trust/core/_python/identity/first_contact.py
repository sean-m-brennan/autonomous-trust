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
"""The live 1:1 first-contact handshake, hosted in the identity process.

OPTIONAL and off by default: nothing here runs unless a node opts in with the
``AT_FIRST_CONTACT`` environment flag, so a default deployment registers no
handlers and behaves exactly as before. Kept as its own module (rather than
folded into the 4k-line ``idprocess.py``) precisely so the feature is a
self-contained, clearly-bounded add-on.

The flow (``doc/architecture/first-contact.md``, §4.0/§4.1):

  1. Alice mints a signed invitation carrying her endpoint and shares the link.
  2. Bob redeems it (the offline :mod:`..contacts` slice) and calls
     :func:`initiate`, which sends a ``hello`` to Alice's endpoint on the OPEN
     unencrypted channel — unencrypted because Alice does not know Bob yet. The
     ``hello`` carries Bob's identity (in the envelope) and the invitation as
     his ticket.
  3. Alice's :func:`handle_hello` validates the ticket — HER signature, not
     expired, and the nonce not already spent (invitations are SINGLE-USE) —
     then admits Bob as a DIRECT peer and replies ``hello_ack``.
  4. Bob's :func:`handle_hello_ack` admits Alice in turn. Both now hold each
     other's keys, so the encrypted point-to-point channel and reputation work.

"Direct peer" is narrower than group admission: :func:`_admit_direct_peer` adds
the peer to ``Peers`` (so the P2P receive path can attribute and decrypt its
traffic) but never propagates the group key and never inserts into the group
identity history — a contact is not a group member. The contact stays
``unverified`` until the out-of-band safety-number compare
(:func:`..contacts.verify_contact`).
"""
import functools
import json
import logging
import os
import time

from dataclasses import dataclass
from queue import Full

from ..system import CfgIds
from ..extensions import Extension, IdentityHooks
from ..app_verbs import AppEvent, is_local_app_verb, refuse_remote_app_verb
from ..network.message import Message
from ..network.network import Network
from ..network import relay as _relay
from ..contacts import reach as _reach
from ..config.configuration import to_json_string, atomic_write, Configuration
from .identity import Identity, public_identity_to_canonical
from .protocol import IdentityProtocol
from ..contacts import (Invitation, InvalidInvitation, Contact, Contacts,
                       create_invitation, redeem_invitation, Provenance,
                       safety_number, verify_contact, SafetyNumberMismatch)

_logger = logging.getLogger(__name__)

#: Environment flag. The feature is opt-in; absent/empty means OFF.
_FLAG = 'AT_FIRST_CONTACT'


#: The two verbs an APPLICATION sends this feature (``..app_verbs``). Local IPC
#: only -- never on the wire, and refused if one arrives from it. Same strings
#: as C's AT_APP_FC_INVITE / AT_APP_FC_INITIATE (identity/first_contact.h).
APP_INVITE = 'app_first_contact_invite'
APP_INITIATE = 'app_first_contact_initiate'
#: The address book, through the node -- which is thereby its only writer.
#: Same strings as C's AT_APP_FC_* (at_first_contact.h).
APP_SAFETY_NUMBER = 'app_first_contact_safety_number'
APP_VERIFY = 'app_first_contact_verify'
APP_LIST = 'app_first_contact_list'
APP_RENAME = 'app_first_contact_rename'
APP_REMOVE = 'app_first_contact_remove'

#: How long a sent hello waits for its ack. Past this the pending entry is
#: dropped and a late ack is refused like an unsolicited one. In memory only: a
#: restart forgets every pending hello, and the user simply redeems again.
#: Same value as C's AT_FC_PENDING_TTL_SECONDS.
PENDING_TTL_SECONDS = 120

#: Ceiling on invitations this node remembers minting for its app, so a
#: redemption can be reported under the app's ``ref``. Oldest dropped first.
MINTED_REFS_MAX = 256

#: Longest ``ref`` an app may put on a request. C echoes it in a fixed-width
#: field (AT_FC_REF_LEN - 1), and a cut ref would answer nobody, so a longer
#: one is refused (``bad_request``, with an empty ref) in both runtimes.
REF_MAX = 63

#: Longest link an ``invitation`` event carries. C's event is a fixed-width
#: ABI struct (AT_FC_BLOB_LEN - 1 characters), so a longer link is refused
#: there -- and here too, so an app sees the same answer from either runtime.
#: ~1.2 KB is typical; ZTA credentials in the identity are what grow it.
BLOB_MAX = 7679

#: FirstContactEvent.kind values. C's AT_APP_EVENT_FC_* kinds carry the same
#: four outcomes as numbers (at_first_contact.h).
EVENT_INVITATION = 'invitation'     # minted for the app; ``blob`` is the link
EVENT_HELLO_SENT = 'hello_sent'     # a hello left for ``peer_uuid``
EVENT_REFUSED = 'refused'           # see ``reason``
EVENT_ESTABLISHED = 'established'   # both sides hold each other; see ``role``

#: FirstContactEvent.reason values. Index = C's at_fc_reason_t.
REASONS = ('', 'malformed', 'bad_signature', 'expired', 'spent', 'endpoint',
           'bad_request', 'mint_failed', 'mismatch', 'unknown_contact')

#: ContactEvent.kind values. C's AT_APP_EVENT_FC_CONTACT.. carry the same
#: outcomes as numbers (at_first_contact.h).
EVENT_CONTACT = 'contact'               # one address-book record
EVENT_CONTACTS_DONE = 'contacts_done'   # end of a list; ``count`` records sent
EVENT_SAFETY_NUMBER = 'safety_number'   # ``safety_number`` to show the user
EVENT_VERIFIED = 'verified'             # ``method``: 'presented' or 'confirmed'
EVENT_REMOVED = 'removed'               # ``peer_dropped``: was a direct peer let go

#: Longest petname a rename may set (C's NAME_LEN).
PETNAME_MAX = 128

#: The highest trust tier an UNVERIFIED contact may use when it asks this node
#: to run a capability: tier 1, communication (doc/architecture/trust-tiers.md).
#: The contact may message; services and shared data wait for verification,
#: however much reputation it earns meanwhile. Same value as C's
#: AT_FC_UNVERIFIED_TIER_CAP.
UNVERIFIED_TIER_CAP = 1


@dataclass
class FirstContactEvent(AppEvent):
    """One first-contact outcome, reported to the app.

    ``ref`` echoes the ``ref`` the app put on the request this answers, so an
    app with several invitations out can tell them apart; empty when nothing
    this node's app asked for is involved. ``role`` is ``'inviter'`` or
    ``'initiator'`` on an ``established`` or ``refused`` event.

    A refused hello is NOT reported to the initiator: the inviter sends nothing
    back (a probe must learn nothing from a bad ticket), so the initiator's app
    sees ``hello_sent`` and then either ``established`` or nothing. Silence past
    :data:`PENDING_TTL_SECONDS` means refused or unreachable, deliberately
    indistinguishable."""
    kind: str
    ref: str = ''
    peer_uuid: str = ''
    nickname: str = ''
    blob: str = ''
    expiry: int = 0
    reason: str = ''
    role: str = ''


@dataclass
class ContactEvent(AppEvent):
    """One address-book answer, reported to the app.

    ``provenance`` is the Provenance value ('in_person', 'token',
    'directory'). ``method`` says how a ``verified`` event was reached:
    'presented' (the node compared digits the user typed from the OTHER
    person's screen) or 'confirmed' (the user compared by eye and said so).
    ``peer_dropped`` on ``removed`` is False when the contact was also a cohort
    member (whose peer entry belongs to the group) or was not a peer at all."""
    kind: str
    ref: str = ''
    peer_uuid: str = ''
    nickname: str = ''
    petname: str = ''
    verified: bool = False
    provenance: str = ''
    added_at: float = 0.0
    verified_at: float = 0.0
    safety_number: str = ''
    method: str = ''
    peer_dropped: bool = False
    count: int = 0


def _emit(proc, queues, event) -> None:
    """Hand ``event`` to the main loop, which owns the hop to the app."""
    try:
        queues[CfgIds.main].put(event, block=True, timeout=proc.q_cadence)
    except KeyError:
        # No main queue (unit tests, embedded use): nothing is listening.
        pass
    except Full:
        proc.logger.warning('first contact: main queue full; %s event for '
                            'the app dropped', event.kind)


def _signing_key(identity) -> str:
    """The public signing key, hex, as the cross-runtime canonical form spells
    it -- the thing a forged envelope cannot share with the real inviter."""
    try:
        return public_identity_to_canonical(identity)['signature']['hex_seed']
    except (AttributeError, KeyError, TypeError):
        return ''


def enabled() -> bool:
    """True iff first contact is opted in via ``AT_FIRST_CONTACT``."""
    return os.environ.get(_FLAG, '').strip().lower() in ('1', 'true', 'yes', 'on')


class SpentNonces:
    """Durable single-use guard: the invitation nonces this node has already
    honored, so a RESTART cannot let a redeemer re-present a still-unexpired
    invitation.

    Persisted as ``<data_dir>/first_contact_nonces.cfg.json`` via the same
    atomic-write path the rest of AT's config uses. Each nonce is stored with
    its invitation's expiry, so a record is pruned once the invitation would be
    rejected as expired anyway; a nonce from a no-expiry invitation (expiry 0)
    is kept forever, because such an invitation never becomes self-limiting and
    single use is then the ONLY thing bounding replay.

    Only the identity process reads or writes this file, so no cross-process
    locking is needed. A save failure degrades to in-memory enforcement for the
    current run rather than dropping the frame (logged, never raised)."""

    FILENAME = 'first_contact_nonces'

    def __init__(self, data_dir=None):
        self._data_dir = data_dir
        self._by_nonce = {}   # nonce -> expiry (epoch int; 0 = never expires)
        self._load()

    def _path(self) -> str:
        data_dir = self._data_dir or Configuration.get_data_dir()
        return os.path.join(data_dir, self.FILENAME + Configuration.file_ext)

    def _load(self) -> None:
        path = self._path()
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r') as fh:
                data = json.load(fh)
            self._by_nonce = {str(k): int(v)
                              for k, v in (data.get('nonces') or {}).items()}
        except (OSError, ValueError, TypeError) as err:
            # Fail-safe: an unreadable guard starts empty (re-honoring is only
            # possible within an invitation's expiry, and trust still gates on
            # the out-of-band safety number). Loud, because it is a weakening.
            _logger.warning('first-contact nonce store unreadable (%s); '
                            'starting with an empty single-use guard', err)
            self._by_nonce = {}

    def _save(self) -> None:
        path = self._path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with atomic_write(path) as fh:
                json.dump({'typename': self.FILENAME, 'version': 1,
                           'nonces': self._by_nonce}, fh, indent=2, sort_keys=True)
        except OSError as err:
            _logger.warning('could not persist first-contact nonce store (%s); '
                            'single use enforced in-memory for this run', err)

    def prune(self, now=None) -> None:
        now = now if now is not None else time.time()
        self._by_nonce = {n: e for n, e in self._by_nonce.items()
                          if e == 0 or e > now}

    def __contains__(self, nonce) -> bool:
        return str(nonce) in self._by_nonce

    def add(self, nonce, expiry, now=None) -> None:
        """Record a spent nonce (pruning expired records first) and persist."""
        self.prune(now)
        self._by_nonce[str(nonce)] = int(expiry or 0)
        self._save()


def register(proc) -> None:
    """Wire the handlers into an ``IdentityProcess``. Call ONLY when
    :func:`enabled` — a default node registers nothing here."""
    # Durable single-use replay guard (survives restart). See SpentNonces.
    proc._first_contact_nonces = SpentNonces()
    # Hellos we sent and are waiting on (inviter uuid -> _Pending). Only an ack
    # matching one of these is honored; see handle_hello_ack.
    proc._first_contact_pending = {}
    # Invitations minted for our app (nonce -> ref), to report a redemption.
    proc._first_contact_minted = {}
    # partial, not lambdas: multiproc mode pickles the process, and a lambda
    # does not pickle.
    proc.protocol.register_handler(IdentityProtocol.hello,
                                   functools.partial(handle_hello, proc))
    proc.protocol.register_handler(IdentityProtocol.hello_ack,
                                   functools.partial(handle_hello_ack, proc))
    proc.protocol.register_handler(APP_INVITE,
                                   functools.partial(handle_app_invite, proc))
    # Our own relays' proven identities, from the network process, to pin
    # them in the links we mint: endpoint -> (uuid, fp).
    proc._own_relay_pins = {}
    proc.protocol.register_handler(Network.relay_identity,
                                   functools.partial(handle_relay_identity, proc))
    proc.protocol.register_handler(IdentityProtocol.reach_record,
                                   functools.partial(handle_reach_record, proc))
    proc.protocol.register_handler(APP_INITIATE,
                                   functools.partial(handle_app_initiate, proc))
    for verb, handler in ((APP_SAFETY_NUMBER, handle_app_safety_number),
                          (APP_VERIFY, handle_app_verify),
                          (APP_LIST, handle_app_list),
                          (APP_RENAME, handle_app_rename),
                          (APP_REMOVE, handle_app_remove)):
        proc.protocol.register_handler(verb, functools.partial(handler, proc))
    # Finding someone by handle (FIRST_CONTACT_PLAN Phase 3).
    from . import directory_contact
    directory_contact.register(proc)


def _register_extension(proc, proc_name: str) -> None:
    if proc_name != 'identity':
        return
    register(proc)
    proc.logger.info('First contact (1:1 introduction) enabled')


# --------------------------------------------------------------------------
# Reachability records (contacts/reach.py): ours, pushed and published; theirs,
# verified against the key we already hold and applied.
# --------------------------------------------------------------------------
#: Where our own record's sequence and last issue live (var/at/), so the
#: sequence only ever rises, across restarts too.
REACH_STATE_FILENAME = 'reach.cfg.json'


def _reach_state_path():
    return os.path.join(Configuration.get_data_dir(), REACH_STATE_FILENAME)


def _load_reach_state():
    try:
        with open(_reach_state_path()) as fh:
            state = json.load(fh)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def _own_reachability(proc):
    """What our record states now: our relays (pinned where proven) and our
    own address. A relay not yet re-proven this run keeps the pin our last
    record gave it: a restart must not issue a weaker, unpinned record only
    to issue the pinned one again moments later."""
    previous = {}
    current = _current_own_record(proc)
    for hint in (current.relays if current is not None else []):
        endpoint, pin = _relay.parse_hint(hint)
        if endpoint is not None and pin is not None:
            previous[endpoint] = pin
    relays = [_own_relay_hint(proc, ep, pin or previous.get(ep))
              for ep, pin in _relay.own_relay_hints()]
    address = getattr(proc.identity, 'address', '') or ''
    return relays, [address] if address else []


def _current_own_record(proc):
    """Our last issued record, if it is still valid."""
    wire = _load_reach_state().get('record')
    if not wire:
        return None
    try:
        return _reach.ReachRecord.from_wire(wire).verify()
    except _reach.InvalidRecord:
        return None


def refresh_own_record(proc, queues, now=None):
    """Issue a new record when what it states has changed, or when the one we
    have is past half its life; push it to every contact that is a peer now
    and hand it to the network process to file at our relays. With nothing
    new, the record we have is handed on again (a restarted network process
    holds none). Returns the record in force, or None."""
    now = now if now is not None else time.time()
    relays, endpoints = _own_reachability(proc)
    if not relays and not endpoints:
        return None
    state = _load_reach_state()
    current = _current_own_record(proc)
    fresh = (current is not None and current.relays == relays
             and current.endpoints == endpoints
             and (not current.expiry
                  or current.expiry - now > _reach.DEFAULT_TTL_SECONDS / 2))
    if fresh:
        record = current
    else:
        seq = int(state.get('seq', 0) or 0) + 1
        record = _reach.create_record(proc.identity, seq, relays, endpoints,
                                      expiry=int(now) + _reach.DEFAULT_TTL_SECONDS)
        try:
            os.makedirs(Configuration.get_data_dir(), exist_ok=True)
            with atomic_write(_reach_state_path()) as fh:
                json.dump({'seq': seq, 'record': record.to_wire()}, fh)
        except OSError as err:
            proc.logger.warning('first contact: could not save our reachability '
                                'record (%s); not publishing it', err)
            return None
        proc.logger.info('first contact: our reachability is now %d relay(s), '
                         '%d endpoint(s) (record seq %d)', len(relays),
                         len(endpoints), seq)
        _push_own_record(proc, queues, None, record)
    publish = Message(CfgIds.network, Network.reach_publish, record.to_json(),
                      to_whom=None, from_whom=None)
    try:
        queues[CfgIds.network].put(publish, block=True, timeout=proc.q_cadence)
    except (Full, KeyError):
        proc.logger.warning('first contact: network queue unavailable; our '
                            'record is not filed at our relays yet')
    return record


def _push_own_record(proc, queues, peers=None, record=None):
    """Send our record to ``peers`` (Identities), or to every contact that is a
    peer right now. Over the sealed channel: each is a known peer."""
    record = record or _current_own_record(proc)
    if record is None or CfgIds.network not in queues:
        return
    if peers is None:
        store = _contacts_store(proc)
        peers = [proc.peers.find_by_uuid(c.identity.uuid) for c in store.all()]
    for peer in peers:
        if peer is None or str(peer.uuid) == str(proc.identity.uuid):
            continue
        msg = Message(proc.name, IdentityProtocol.reach_record, record.to_json(),
                      to_whom=peer, from_whom=proc.identity)
        try:
            queues[CfgIds.network].put(msg, block=True, timeout=proc.q_cadence)
        except Full:
            proc.logger.warning('first contact: network queue full; record not '
                                'pushed to %s', str(peer.uuid)[:8])


def handle_reach_record(proc, queues, message) -> bool:
    """A contact's reachability record: pushed by the contact itself (on the
    wire, from_whom = the contact), or handed on by our network process from a
    relay lookup (local, no sender). Applied only if it verifies, its key is
    the key we hold for that contact, and its seq is above any applied."""
    sender = getattr(message, 'from_whom', None)
    try:
        record = _reach.ReachRecord.from_wire(message.obj).verify()
    except _reach.InvalidRecord as err:
        proc.logger.warning('first contact: reachability record refused: %s', err)
        return True
    if sender is not None and str(getattr(sender, 'uuid', '')).lower() != record.uuid:
        proc.logger.warning('first contact: %s pushed a record for %s; refused',
                            str(getattr(sender, 'uuid', ''))[:8], record.uuid[:8])
        return True
    store = _contacts_store(proc)
    contact = store.get(record.uuid) if record.uuid in store else None
    if contact is None:
        for c in store.all():
            if str(c.identity.uuid).lower() == record.uuid:
                contact = c
    if contact is None:
        proc.logger.debug('first contact: record for %s, not a contact; ignored',
                          record.uuid[:8])
        return True
    if _relay._signing_hex(contact.identity).lower() != record.key:
        proc.logger.warning('first contact: record for %s is signed by another '
                            'key; refused', contact.petname)
        return True
    if record.seq <= contact.reach_seq:
        proc.logger.debug('first contact: record %d for %s is not newer than %d',
                          record.seq, contact.petname, contact.reach_seq)
        return True
    contact.reach_seq = record.seq
    contact.rendezvous = _merge_hints(record.relays + record.endpoints,
                                      contact.rendezvous)
    try:
        store.save()
    except OSError as err:
        proc.logger.warning('could not persist contact for %s (%s)',
                            contact.petname, err)
    hints = _relay_hints(contact.rendezvous)
    have = {_relay.parse_endpoint(h) for h in hints}
    hints += [_own_relay_hint(proc, ep, pin) for ep, pin in _relay.own_relay_hints()
              if ep not in have]
    _send_relay_route(proc, queues, contact.identity.uuid, hints[:_relay.MAX_RELAYS])
    proc.logger.info('first contact: %s is reachable via %d relay(s) (record seq %d)',
                     contact.petname, len(record.relays), record.seq)
    return True


def restore_contacts(proc, queues) -> int:
    """At startup, reconnect every saved contact: re-admit it as a direct peer
    (``Peers`` is rebuilt each session and keeps no direct peer) and tell the
    network process which relays reach it -- the ones its record names, then
    our own, where it registered to reach us. Unverified contacts come back
    tier-capped as before (:func:`capped_tier`). Returns how many."""
    store = _contacts_store(proc)
    own = _relay.own_relay_hints()
    me = str(proc.identity.uuid)
    added = []
    restored = 0
    for contact in list(store.all()):
        ident = contact.identity
        if str(ident.uuid) == me:
            continue
        if proc.peers.find_by_uuid(ident.uuid) is None:
            proc.peers.add(ident, proc.peers.mid_level)
            added.append(ident)
        hints = _relay_hints(contact.rendezvous)
        have = {_relay.parse_endpoint(h) for h in hints}
        hints += [_own_relay_hint(proc, ep, pin) for ep, pin in own
                  if ep not in have]
        _send_relay_route(proc, queues, ident.uuid, hints[:_relay.MAX_RELAYS])
        restored += 1
    if added:
        proc._record_peers(queues)
        send = getattr(proc, '_send_caps_query', None)
        for ident in added:
            if send is not None:
                send(queues, ident)
    if restored:
        proc.logger.info('first contact: reconnecting %d saved contact(s)', restored)
    refresh_own_record(proc, queues)
    return restored


#: First contact as an optional feature (``..extensions``): identity only,
#: gated on ``AT_FIRST_CONTACT``.
def _on_start(proc, queues):
    """At startup: re-admit the address book, and refile our directory entries."""
    from . import directory_contact
    restored = restore_contacts(proc, queues)
    directory_contact.restore_entries(proc, queues)
    return restored


def _app_verbs():
    from .directory_contact import APP_VERBS as dir_verbs
    return (APP_INVITE, APP_INITIATE, APP_SAFETY_NUMBER, APP_VERIFY, APP_LIST,
            APP_RENAME, APP_REMOVE) + dir_verbs


EXTENSION = Extension(name='first_contact', enabled=enabled,
                      register_handlers=_register_extension,
                      identity=IdentityHooks(on_start=_on_start),
                      app_verbs=tuple((verb, CfgIds.identity) for verb in _app_verbs()))


def _in_group(grp, key) -> bool:
    members = getattr(grp, '_address_map', None) if grp is not None else None
    return isinstance(members, dict) and key in {str(k) for k in members}


def _in_own_group(proc, uuid) -> bool:
    """True iff ``uuid`` belongs to this node's own group -- a peer that
    group's vote admitted."""
    return _in_group(getattr(proc, 'group', None), str(uuid))


def _in_a_child_group(proc, uuid) -> bool:
    """True iff ``uuid`` belongs to a child group this node gateways."""
    key = str(uuid)
    return any(_in_group(grp, key)
               for grp in (getattr(proc, 'child_groups', None) or {}).values())


#: (path, mtime) -> {uuid: verified} read from that version of the store.
_verified_cache = {}


def _contact_records():
    """Every recorded contact's uuid mapped to whether it is VERIFIED, re-read
    only when the store changes."""
    path = Contacts.default_path()
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        return {}                   # no store: nobody is recorded
    key = (path, mtime)
    if key not in _verified_cache:
        try:
            records = {str(c.identity.uuid): bool(c.verified)
                       for c in Contacts.load().all()}
        except (OSError, ValueError, TypeError) as err:
            _logger.warning('contacts store unreadable (%s); treating every '
                            'direct peer as unverified', err)
            records = {}
        _verified_cache.clear()
        _verified_cache[key] = records
    return _verified_cache[key]


def capped_tier(proc, peer_uuid, tier) -> int:
    """The trust tier ``peer_uuid`` may USE when it asks ``proc`` (any core
    process holding ``group`` / ``child_groups``) to run a capability.

    §10.3: an unverified contact may message, and higher-trust actions wait
    for verification, so such a peer is held at :data:`UNVERIFIED_TIER_CAP`
    whatever its earned tier:

    - a member of this node's own group is never capped -- its vote admitted it;
    - a VERIFIED contact is never capped;
    - a child-group member IS capped while it is on record as an unverified
      contact (the child's vote does not vouch for what first contact
      introduced), and is not capped with no contact record at all -- an
      ordinary child member never went through first contact;
    - any other peer is capped. A missing record counts as unverified here:
      losing or deleting ``contacts.cfg.json`` must not lift the cap.

    Only while first contact is enabled; with it off, nothing is capped.
    Mirrors C's at_first_contact_capped_tier."""
    if tier <= UNVERIFIED_TIER_CAP or not enabled():
        return tier
    if _in_own_group(proc, peer_uuid):
        return tier
    verified = _contact_records().get(str(peer_uuid))
    if verified:
        return tier
    if verified is None and _in_a_child_group(proc, peer_uuid):
        return tier
    return UNVERIFIED_TIER_CAP


def _admit_direct_peer(proc, queues, identity) -> bool:
    """No-vote, no-group-key admission of a direct peer.

    Adds ``identity`` to ``Peers`` (address-keyed listing, so the encrypted P2P
    channel can attribute its frames) and propagates the update. Deliberately
    does NOT call ``_confirm_group_membership`` (which would hand over the group
    key) or ``_history.insert_peer`` (the consensus DAG): a first-contact peer
    is directly reachable, not a group member. Idempotent. Returns True if newly
    added."""
    existing = proc.peers.find_by_uuid(identity.uuid)
    if existing is not None and existing == identity:
        return False
    proc.peers.add(identity, proc.peers.mid_level)
    proc._record_peers(queues)
    # Ask what it can do now, as confirming a cohort member does, rather than
    # leave it to the periodic caps sweep (up to one interval later).
    send = getattr(proc, '_send_caps_query', None)
    if send is not None:
        send(queues, identity)
    return True


#: How many reachability hints one contact keeps. A peer that re-handshakes
#: from a new network on every join would otherwise grow its hint list without
#: bound in a file that is never pruned; the newest is the one worth trying
#: first, so the list is most-recent-first and truncated here.
MAX_RENDEZVOUS_HINTS = 4


def _merge_hints(fresh, existing):
    """A contact's rendezvous list: ``fresh`` hints ahead of ``existing``,
    deduplicated. Relay hints and direct addresses are capped separately
    (:data:`..network.relay.MAX_RELAYS` and :data:`MAX_RENDEZVOUS_HINTS`), so
    refreshing an address can never push out a relay a contact is reached
    through. Relay hints come first, in the order to try them. Mirrors C's
    _fc_merge_hints."""
    relays, direct, relay_eps = [], [], set()
    for hint in list(fresh) + list(existing):
        hint = str(hint or '')
        if not hint:
            continue
        if hint.startswith(_relay.SCHEME):
            # One hint per relay endpoint, the first (freshest) kept: a pinned
            # and an unpinned hint for the same relay are the same relay.
            endpoint = _relay.parse_endpoint(hint)
            if endpoint is None or endpoint in relay_eps:
                continue
            relay_eps.add(endpoint)
            relays.append(hint)
        elif hint not in direct:
            direct.append(hint)
    return relays[:_relay.MAX_RELAYS] + direct[:MAX_RENDEZVOUS_HINTS]


def _relay_hints(hints):
    """The ``relay://`` hints of ``hints``, in order, as hint strings (pins
    kept) -- deduplicated by endpoint."""
    found, seen = [], set()
    for hint in hints:
        if str(hint).startswith(_relay.SCHEME):
            endpoint, pin = _relay.parse_hint(hint)
            if endpoint is not None and endpoint not in seen:
                seen.add(endpoint)
                found.append(_relay.hint_for(endpoint, pin))
    return found[:_relay.MAX_RELAYS]


def _send_relay_route(proc, queues, uuid, hints) -> None:
    """Tell the network process to reach ``uuid`` through ``hints`` (relay
    hints, pinned or not, in preference order). Local IPC, consumed by the
    network process's handler before any send, so it carries no encrypt=False:
    that marks WIRE verbs sent in the clear (identity.protocol.UNENCRYPTED_VERBS),
    and this is not one."""
    if not hints:
        return
    relays = []
    for hint in hints:
        endpoint, pin = _relay.parse_hint(hint)
        if endpoint is None:
            continue
        text = _relay.hint_for(endpoint, pin)[len(_relay.SCHEME):]
        relays.append(text)
    route = Message(CfgIds.network, Network.relay_route,
                    to_json_string({'uuid': str(uuid), 'relays': relays}),
                    to_whom=None, from_whom=None)
    queues[CfgIds.network].put(route, block=True, timeout=proc.q_cadence)


def _contacts_store(proc):
    """Lazy handle on the durable contacts store, cached on the process.

    Read once per process rather than per handshake: the file is this node's
    own address book, and only the identity process writes it (the same
    single-writer argument :class:`SpentNonces` relies on). An unreadable store
    degrades to an empty in-memory one -- loud, because it means this node will
    re-add contacts it already had."""
    store = getattr(proc, '_first_contact_contacts', None)
    if store is None:
        try:
            store = Contacts.load()
        except (OSError, ValueError, TypeError) as err:
            proc.logger.warning('contacts store unreadable (%s); starting empty', err)
            store = Contacts()
        proc._first_contact_contacts = store
    return store


def _record_contact(proc, identity, nonce='', endpoint='', relays=(),
                    provenance=Provenance.token):
    """Write or refresh the durable :class:`..contacts.Contact` for a peer we
    just completed a handshake with.

    A NEW contact is always ``token``-provenance and UNVERIFIED: the accepter
    cannot know how its invitation travelled (``create_invitation`` carries no
    in-person flag -- ``in_person`` is the *redeemer's* local knowledge), so the
    key that just arrived over the wire has had no out-of-band confirmation.
    Verification, and the trust seed that follows it, still come from a
    safety-number compare (:func:`..contacts.verify_contact`).

    An EXISTING contact keeps everything the user or an earlier verification
    established -- verified state, petname, provenance, trust seed, added_at --
    and only its reachability and originating nonce are refreshed. A handshake
    must never downgrade a verified contact (a re-presented ticket would
    otherwise be an attacker's way to strip the verified flag), and must never
    re-derive the petname, which is random-suffixed and already on the user's
    screen.

    ``relays`` are ``relay://`` hints the peer is reached through (the
    initiator's copy of the link's), kept ahead of any it had.

    Returns the stored Contact, or None if it could not be recorded."""
    store = _contacts_store(proc)
    fresh = list(relays) + ([endpoint] if endpoint else [])
    try:
        contact = store.get(str(identity.uuid))
    except (AttributeError, TypeError):
        contact = None
    if contact is None:
        contact = Contact(identity, rendezvous=_merge_hints(fresh, []),
                          provenance=provenance, nonce=nonce)
        store.add(contact)
        proc.logger.info('first contact: recorded %s as an unverified contact',
                         contact.petname)
    else:
        if fresh:
            contact.rendezvous = _merge_hints(fresh, contact.rendezvous)
        if nonce:
            contact.nonce = nonce
        proc.logger.debug('first contact: refreshed reachability for %s',
                          contact.petname)
    try:
        store.save()
    except OSError as err:
        # In-memory only for this run: the peer is admitted either way, and a
        # lost record costs a re-add, not a security property.
        proc.logger.warning('could not persist contact for %s (%s)',
                            contact.petname, err)
    return contact


def handle_hello(proc, queues, message) -> bool:
    """Inviter side: honor a valid, single-use invitation we minted, admit the
    sender as a direct peer, and acknowledge."""
    sender = message.from_whom
    if not isinstance(sender, Identity):
        proc.logger.warning('first-contact hello with no sender identity; ignoring')
        return True
    try:
        invitation = Invitation.decode(message.obj)
        inviter = invitation.verify_signature()   # raises InvalidInvitation
    except InvalidInvitation as err:
        proc.logger.warning('first-contact hello: invalid invitation (%s)', err)
        return True
    # The ticket must be one WE signed, or it is not ours to honor.
    if str(inviter.uuid) != str(proc.identity.uuid):
        proc.logger.warning('first-contact hello: invitation not minted by us; ignoring')
        return True
    # From here the ticket is provably ours, so a refusal is worth telling our
    # app about ("your link expired"). Before this point it is a stranger's
    # garbage, and reporting it would let anyone on the LAN flood the app.
    nonce = invitation.nonce
    ref = getattr(proc, '_first_contact_minted', {}).get(nonce, '')
    if invitation.is_expired():
        proc.logger.info('first-contact hello: invitation expired; ignoring')
        _emit(proc, queues, FirstContactEvent(
            EVENT_REFUSED, ref=ref, peer_uuid=str(sender.uuid),
            nickname=sender.nickname, reason='expired', role='inviter'))
        return True
    spent = getattr(proc, '_first_contact_nonces', None)
    if spent is None:
        spent = proc._first_contact_nonces = SpentNonces()
    if nonce in spent:
        proc.logger.warning('first-contact hello: nonce already spent (single-use); ignoring')
        _emit(proc, queues, FirstContactEvent(
            EVENT_REFUSED, ref=ref, peer_uuid=str(sender.uuid),
            nickname=sender.nickname, reason='spent', role='inviter'))
        return True
    spent.add(nonce, invitation.expiry)   # durable: survives a restart

    _admit_direct_peer(proc, queues, sender)
    proc.logger.info('first contact: admitted %s as a direct peer', sender.nickname)

    ack = Message(proc.name, IdentityProtocol.hello_ack,
                  to_json_string({'nonce': nonce}),
                  to_whom=sender, from_whom=proc.identity, encrypt=False)
    queues[CfgIds.network].put(ack, block=True, timeout=proc.q_cadence)
    # After the ack is on its way: the address book is durable state, not part
    # of the handshake's critical path.
    directory = nonce in getattr(proc, '_dir_invites', ())
    _record_contact(proc, sender, nonce=nonce,
                    endpoint=getattr(sender, 'address', '') or '',
                    provenance=Provenance.directory if directory else Provenance.token)
    _push_own_record(proc, queues, [sender])
    _emit(proc, queues, FirstContactEvent(
        EVENT_ESTABLISHED, ref=ref, peer_uuid=str(sender.uuid),
        nickname=sender.nickname, role='inviter'))
    return True


@dataclass
class _Pending:
    """A hello we sent, and what its ack must match."""
    ref: str
    nonce: str
    signing_key: str
    deadline: float
    relays: tuple = ()      # the link's relay:// hints, for the contact
    provenance: Provenance = Provenance.token


def _take_pending(proc, accepter, nonce, now=None):
    """Consume and return the pending hello ``accepter``'s ack answers, or
    None (and log why) if there is none it may answer.

    The whole of the ack's trust: an ack is honored ONLY from an inviter we
    sent a hello to, before the deadline, with the nonce of the ticket we
    presented, signed by the key the invitation carried. The key check is not
    redundant with the uuid: the envelope is verified against the identity it
    itself carries, so a forger can name the inviter's uuid and still sign
    correctly -- with its own key."""
    now = now if now is not None else time.time()
    pending = getattr(proc, '_first_contact_pending', None)
    if pending is None:
        pending = proc._first_contact_pending = {}
    for key in [k for k, p in pending.items() if p.deadline <= now]:
        del pending[key]
    entry = pending.get(str(accepter.uuid))
    if entry is None:
        proc.logger.warning('first-contact ack from %s: no hello pending to '
                            'it (unsolicited or too late); ignoring',
                            str(accepter.uuid)[:8])
        return None
    if entry.signing_key != _signing_key(accepter):
        proc.logger.warning('first-contact ack from %s: signing key differs '
                            'from the invitation; ignoring',
                            str(accepter.uuid)[:8])
        return None
    if entry.nonce != nonce:
        proc.logger.warning('first-contact ack from %s: nonce does not match '
                            'the ticket we presented; ignoring',
                            str(accepter.uuid)[:8])
        return None
    del pending[str(accepter.uuid)]
    return entry


def handle_hello_ack(proc, queues, message) -> bool:
    """Initiator side: the inviter accepted; admit them as a direct peer so the
    channel is live both ways (we already hold their key from the invitation).

    Only an ack answering a hello WE sent is honored (:func:`_take_pending`).
    Before that gate existed, any stranger's plaintext ack made it a direct
    peer: the unknown-sender receive path routes a plaintext envelope with no
    verb filter, so nothing upstream stood in the way."""
    accepter = message.from_whom
    if not isinstance(accepter, Identity):
        proc.logger.warning('first-contact ack with no sender identity; ignoring')
        return True
    nonce = ''
    try:
        payload = json.loads(message.obj) if isinstance(message.obj, str) else message.obj
        if isinstance(payload, dict):
            nonce = str(payload.get('nonce', '') or '')
    except (ValueError, TypeError):
        pass
    entry = _take_pending(proc, accepter, nonce)
    if entry is None:
        return True
    _admit_direct_peer(proc, queues, accepter)
    # Our own side of the address book. The redeemer usually already has a
    # Contact for this identity (redeem_invitation built one, possibly verified
    # in-person); the preserve rule in _record_contact keeps that posture and
    # only refreshes where the inviter answered from.
    _record_contact(proc, accepter, nonce=nonce,
                    endpoint=getattr(accepter, 'address', '') or '',
                    relays=entry.relays, provenance=entry.provenance)
    proc.logger.info('first contact: %s accepted; direct peer established',
                     accepter.nickname)
    _push_own_record(proc, queues, [accepter])
    _emit(proc, queues, FirstContactEvent(
        EVENT_ESTABLISHED, ref=entry.ref, peer_uuid=str(accepter.uuid),
        nickname=accepter.nickname, role='initiator'))
    return True


def endpoint_host(raw) -> str:
    """Reduce a rendezvous hint or advertised address to a bare host.

    Strips a ``/path`` tail and a trailing ``:port``. Getting this right for
    IPv6 is the whole reason it is a named function: a bracketless IPv6 literal
    **cannot express a port** (the colons are part of the address), so the naive
    ``rsplit(':', 1)`` this replaced turned ``fe80::1`` into ``fe80:`` — a
    well-formed address silently mangled into an unroutable one, which is the
    worst shape of bug because both strings look like addresses.

    A port is therefore only possible in two forms, and only those two are
    split:

    ==========================  ==================
    input                       host
    ==========================  ==================
    ``10.0.0.1``                ``10.0.0.1``
    ``10.0.0.1:9000``           ``10.0.0.1``
    ``fe80::1``                 ``fe80::1``
    ``2001:db8::1%eth0``        ``2001:db8::1%eth0``
    ``[fe80::1]``               ``fe80::1``
    ``[fe80::1]:9000``          ``fe80::1``
    ``relay.example:9000/x``    ``relay.example``
    ==========================  ==================

    An unterminated bracket (``[fe80::1``) yields everything after the ``[`` —
    a best effort on malformed input, chosen so the two runtimes agree on it
    rather than because it is meaningful.

    Mirrors C :c:func:`at_first_contact_endpoint_host` exactly, including that
    last case. The one deliberate difference is length: C must fit the result in
    ``ADDR_LEN`` (45, so ``ADDR_LEN + 1`` is ``INET6_ADDRSTRLEN`` — every
    numeric address fits) and refuses rather than truncating what does not,
    while nothing here is bounded at all. See the note in ``first_contact.h``.
    """
    text = str(raw or '')
    text = text.split('/', 1)[0]          # drop any path tail first
    if text.startswith('['):
        # Bracketed literal: the host is what is inside the brackets, and
        # anything after ']' is the port.
        return text[1:].partition(']')[0]
    if text.count(':') != 1:
        # 0 colons -> a bare host or IPv4. More than 1 -> a bracketless IPv6
        # literal, which has no room for a port, so the whole string is host.
        return text
    return text.split(':', 1)[0]


def initiate(proc, queues, invitation_blob, endpoint=None, ref='',
             provenance=Provenance.token):
    """Initiator side: reach the inviter named in ``invitation_blob`` and open
    the handshake.

    :param invitation_blob: the invitation link/blob (or an :class:`Invitation`).
    :param endpoint: override the reachable host; defaults to the invitation's
        first rendezvous hint, then the inviter's advertised address. Only the
        host is used — Phase 1 assumes the shared comm port (cross-port waits on
        the rendezvous relay layer).
    :param ref: the app's tag for this request, echoed on the ``established``
        event.
    :returns: the inviter's public :class:`Identity`.

    Records the hello as pending (:data:`PENDING_TTL_SECONDS`): the inviter's
    ack is honored only while it is.
    """
    invitation = Invitation.decode(invitation_blob)
    inviter = invitation.verify_signature()
    # Relay hints win when the caller names no endpoint: they reach an
    # inviter behind NAT, which its own address cannot. The network process is
    # told the route -- every relay the link names, in its order, to fail over
    # along -- BEFORE the hello is queued, so the hello takes it
    # (network/relay.py). The address below is then only a label.
    relay_eps = _relay_hints(invitation.rendezvous) if endpoint is None else []
    direct = [h for h in invitation.rendezvous
              if not str(h).startswith(_relay.SCHEME)]
    host = endpoint
    if host is None and direct:
        host = direct[0]
    if host is None:
        host = inviter.address
    inviter.address = endpoint_host(host)
    _send_relay_route(proc, queues, inviter.uuid, relay_eps)
    blob = invitation_blob if isinstance(invitation_blob, str) else invitation.encode()
    hello = Message(proc.name, IdentityProtocol.hello, blob,
                    to_whom=inviter, from_whom=proc.identity, encrypt=False)
    pending = getattr(proc, '_first_contact_pending', None)
    if pending is None:
        pending = proc._first_contact_pending = {}
    # Before the send, so an ack that races back cannot find nothing pending.
    pending[str(inviter.uuid)] = _Pending(
        ref=str(ref or ''), nonce=invitation.nonce,
        signing_key=_signing_key(inviter),
        deadline=time.time() + PENDING_TTL_SECONDS,
        relays=tuple(relay_eps), provenance=provenance)
    queues[CfgIds.network].put(hello, block=True, timeout=proc.q_cadence)
    return inviter


# --------------------------------------------------------------------------
# App verbs: how an application adds a friend (``..app_verbs``)
# --------------------------------------------------------------------------
def _app_payload(message) -> dict:
    """The request's JSON object, or {} if it is not one."""
    obj = message.obj
    if isinstance(obj, dict):
        return obj
    try:
        data = json.loads(obj) if isinstance(obj, (str, bytes)) else None
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _app_ref(req):
    """The request's ``ref``, or None if it is too long to echo intact."""
    ref = str(req.get('ref', '') or '')
    return ref if len(ref) <= REF_MAX else None


def _remember_minted(proc, nonce, ref) -> None:
    minted = getattr(proc, '_first_contact_minted', None)
    if minted is None:
        minted = proc._first_contact_minted = {}
    minted[nonce] = ref
    while len(minted) > MINTED_REFS_MAX:
        del minted[next(iter(minted))]      # dicts keep insertion order


def handle_app_invite(proc, queues, message) -> bool:
    """The app asked this node to MINT an invitation (``APP_INVITE``).

    An app holds no private key, so it cannot sign one itself. Payload (JSON,
    every field optional): ``ref`` (echoed back), ``ttl_seconds`` or absolute
    ``expiry`` (0 with ``ttl_seconds`` 0 = never expires), ``rendezvous`` (a
    list of reachability hints; empty means "my advertised address"). Answers
    with an ``invitation`` event carrying the ``at+contact:`` link, or
    ``refused``."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_INVITE)
    req = _app_payload(message)
    ref = _app_ref(req)
    if ref is None:
        proc.logger.warning('first contact: app invite ref over %d chars', REF_MAX)
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, reason='bad_request'))
        return True
    try:
        rendezvous = req.get('rendezvous') or []
        if not isinstance(rendezvous, list) or not all(
                isinstance(h, str) for h in rendezvous):
            raise TypeError('rendezvous must be a list of strings')
        kwargs = {}
        if 'expiry' in req:
            kwargs['expiry'] = int(req['expiry'])
        elif 'ttl_seconds' in req:
            kwargs['ttl_seconds'] = int(req['ttl_seconds'])
    except (TypeError, ValueError):
        proc.logger.warning('first contact: app invite with an unusable payload')
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, ref=ref,
                                              reason='bad_request'))
        return True
    # Behind relays, say so in the link: they are how a friend on another
    # network reaches us at all (network/relay.py). All of them, in our order
    # of preference, so the friend can fail over; none if the app named its
    # own.
    if not any(str(h).startswith(_relay.SCHEME) for h in rendezvous):
        rendezvous = list(rendezvous) + [_own_relay_hint(proc, ep, pin)
                                         for ep, pin in _relay.own_relay_hints()]
    try:
        invitation = create_invitation(proc.identity, rendezvous=rendezvous,
                                       **kwargs)
    except (ValueError, TypeError, AttributeError) as err:
        proc.logger.error('first contact: could not mint an invitation (%s)', err)
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, ref=ref,
                                              reason='mint_failed'))
        return True
    link = invitation.to_uri()
    if len(link) > BLOB_MAX:
        # Refused, not cut: a truncated link is not a shorter link but a
        # broken one, and it would fail in the friend's hands, far from here.
        proc.logger.error('first contact: minted link is %d chars, over the '
                          '%d the app event carries; not handed out',
                          len(link), BLOB_MAX)
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, ref=ref,
                                              reason='mint_failed'))
        return True
    _remember_minted(proc, invitation.nonce, ref)
    proc.logger.info('first contact: minted an invitation for the app')
    _emit(proc, queues, FirstContactEvent(
        EVENT_INVITATION, ref=ref, blob=link, expiry=int(invitation.expiry)))
    return True


def _own_relay_hint(proc, endpoint, configured_pin):
    """The hint naming one of our own relays: pinned to who it proved to be
    when it has (else to the operator's configured pin, else unpinned)."""
    pin = getattr(proc, '_own_relay_pins', {}).get(endpoint) or configured_pin
    return _relay.hint_for(endpoint, pin)


def handle_relay_identity(proc, queues, message) -> bool:
    """The network process says one of our own relays proved who it is
    (``{relay, uuid, fp}``). Local IPC only: a peer must not choose the pin
    our links carry."""
    if getattr(message, 'from_whom', None) is not None:
        proc.logger.warning('first contact: refusing relay_identity from the wire')
        return True
    try:
        spec = json.loads(message.obj) if isinstance(message.obj, str) else message.obj
        endpoint = _relay.parse_endpoint(spec['relay'])
        pin = (str(spec['uuid']).lower(), str(spec['fp']).lower())
    except (KeyError, TypeError, ValueError, AttributeError):
        proc.logger.warning('first contact: unusable relay_identity %r', message.obj)
        return True
    if endpoint is None or _relay.parse_hint(_relay.hint_for(endpoint, pin))[0] is None:
        proc.logger.warning('first contact: unusable relay_identity %r', message.obj)
        return True
    pins = getattr(proc, '_own_relay_pins', None)
    if pins is None:
        pins = proc._own_relay_pins = {}
    if pins.get(endpoint) != pin:
        pins[endpoint] = pin
        proc.logger.info('first contact: our relay %s:%d is %s; links now pin it',
                         endpoint[0], endpoint[1], pin[0][:8])
        refresh_own_record(proc, queues)
    return True


def handle_app_initiate(proc, queues, message) -> bool:
    """The app handed this node a friend's invitation to REDEEM and INITIATE
    (``APP_INITIATE``).

    Payload (JSON): ``invitation`` (required: the link or bare blob), ``ref``,
    ``endpoint`` (override the reachable host), ``in_person`` (true iff the
    link came over a channel with no possible man in the middle -- a QR
    scanned face to face -- which makes the contact verified at once),
    ``petname``. Writes the contact, sends the hello, and answers
    ``hello_sent``; ``established`` follows when the inviter acks."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_INITIATE)
    req = _app_payload(message)
    ref = _app_ref(req)

    def refuse(reason, peer=None):
        proc.logger.warning('first contact: app initiate refused (%s)', reason)
        _emit(proc, queues, FirstContactEvent(
            EVENT_REFUSED, ref=ref, reason=reason, role='initiator',
            peer_uuid=str(peer.uuid) if peer is not None else '',
            nickname=peer.nickname if peer is not None else ''))
        return True

    if ref is None:
        ref = ''
        return refuse('bad_request')
    blob = req.get('invitation')
    if not isinstance(blob, str) or not blob:
        return refuse('bad_request')
    # The three checks redeem_invitation makes, one at a time, so the app is
    # told WHICH one failed.
    try:
        invitation = Invitation.decode(blob)
    except InvalidInvitation:
        return refuse('malformed')
    try:
        inviter = invitation.verify_signature()
    except InvalidInvitation:
        return refuse('bad_signature')
    if invitation.is_expired():
        return refuse('expired', inviter)
    if str(inviter.uuid) == str(proc.identity.uuid):
        return refuse('bad_request', inviter)     # our own link

    contact = redeem_invitation(invitation, in_person=bool(req.get('in_person')),
                                petname=str(req.get('petname', '') or ''))
    store = _contacts_store(proc)
    existing = store.get(str(inviter.uuid)) if str(inviter.uuid) in store else None
    if existing is None:
        store.add(contact)
    else:
        if contact.verified and not existing.verified:
            # Re-adding someone in person upgrades them; nothing here downgrades.
            existing.mark_verified()
        # A newer link says where they are now.
        existing.rendezvous = _merge_hints(invitation.rendezvous, existing.rendezvous)
    try:
        store.save()
    except OSError as err:
        proc.logger.warning('could not persist contact for %s (%s)',
                            contact.petname, err)

    endpoint = req.get('endpoint') or None
    initiate(proc, queues, blob, endpoint=endpoint, ref=ref)
    _emit(proc, queues, FirstContactEvent(
        EVENT_HELLO_SENT, ref=ref, peer_uuid=str(inviter.uuid),
        nickname=inviter.nickname, role='initiator'))
    return True


# --------------------------------------------------------------------------
# App verbs: the address book, through the node
# --------------------------------------------------------------------------
def _contact_event(kind, contact, ref='', **extra) -> ContactEvent:
    ident = contact.identity
    return ContactEvent(
        kind, ref=ref, peer_uuid=str(ident.uuid),
        nickname=getattr(ident, 'nickname', '') or '', petname=contact.petname,
        verified=bool(contact.verified),
        provenance=getattr(contact.provenance, 'value', str(contact.provenance)),
        added_at=float(contact.added_at or 0.0),
        verified_at=float(contact.verified_at or 0.0), **extra)


def _book_request(proc, queues, message, verb):
    """The shared front half of every address-book verb: local-only, a usable
    ref, and the named contact. Returns (req, ref, contact, store), or None
    once it has refused (and said why)."""
    if not is_local_app_verb(proc, message):
        refuse_remote_app_verb(proc, message, verb)
        return None
    req = _app_payload(message)
    ref = _app_ref(req)
    if ref is None:
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, reason='bad_request'))
        return None
    peer = req.get('peer')
    if not isinstance(peer, str) or not peer:
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, ref=ref,
                                              reason='bad_request'))
        return None
    store = _contacts_store(proc)
    contact = store.get(peer) if peer in store else None
    if contact is None:
        proc.logger.info('first contact: %s names no contact', verb)
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, ref=ref,
                                              peer_uuid=peer,
                                              reason='unknown_contact'))
        return None
    return req, ref, contact, store


def _save_book(proc, store) -> None:
    try:
        store.save()
    except OSError as err:
        proc.logger.warning('could not persist the contacts store (%s)', err)


def handle_app_safety_number(proc, queues, message) -> bool:
    """The app wants the safety number to show the user (``APP_SAFETY_NUMBER``,
    payload ``{ref, peer}``). Both people see the same 60 digits; they compare
    them, then the app calls ``APP_VERIFY``."""
    got = _book_request(proc, queues, message, APP_SAFETY_NUMBER)
    if got is None:
        return True
    _req, ref, contact, _store = got
    number = safety_number(proc.identity.publish(), contact.identity)
    _emit(proc, queues, _contact_event(EVENT_SAFETY_NUMBER, contact, ref,
                                       safety_number=number))
    return True


def handle_app_verify(proc, queues, message) -> bool:
    """Mark a contact verified (``APP_VERIFY``, payload ``{ref, peer, presented}``
    or ``{ref, peer, confirmed: true}``).

    ``presented`` is the safety number as the user typed it from the OTHER
    person's screen, and the node compares it: a mismatch is refused and the
    contact stays unverified. ``confirmed`` is the user saying they compared
    the two screens by eye -- the Signal flow -- and is trusted as ``in_person``
    is, on the same local-app channel. Either way the trust seed follows
    (reputation reads it from the store). Sending back the number the node
    itself handed out would prove nothing, which is why ``confirmed`` exists
    rather than pretending that is a comparison."""
    got = _book_request(proc, queues, message, APP_VERIFY)
    if got is None:
        return True
    req, ref, contact, store = got
    presented = req.get('presented')
    if isinstance(presented, str) and presented.strip():
        try:
            verify_contact(contact, presented, proc.identity.publish())
        except SafetyNumberMismatch:
            proc.logger.warning('first contact: safety number mismatch for %s; '
                                'left unverified', contact.petname)
            _emit(proc, queues, FirstContactEvent(
                EVENT_REFUSED, ref=ref, peer_uuid=str(contact.identity.uuid),
                nickname=contact.identity.nickname, reason='mismatch'))
            return True
        method = 'presented'
    elif req.get('confirmed') is True:
        contact.mark_verified()
        method = 'confirmed'
    else:
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, ref=ref,
                                              reason='bad_request'))
        return True
    _save_book(proc, store)
    proc.logger.info('first contact: %s verified (%s)', contact.petname, method)
    _emit(proc, queues, _contact_event(EVENT_VERIFIED, contact, ref,
                                       method=method))
    return True


def handle_app_list(proc, queues, message) -> bool:
    """Send the address book (``APP_LIST``, payload ``{ref}``): one ``contact``
    event per record, oldest first, then ``contacts_done`` with the count -- so
    an empty book still answers, rather than looking like no answer."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_LIST)
    ref = _app_ref(_app_payload(message))
    if ref is None:
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, reason='bad_request'))
        return True
    records = sorted(_contacts_store(proc).all(),
                     key=lambda c: (float(c.added_at or 0.0),
                                    str(c.identity.uuid)))
    for contact in records:
        _emit(proc, queues, _contact_event(EVENT_CONTACT, contact, ref))
    _emit(proc, queues, ContactEvent(EVENT_CONTACTS_DONE, ref=ref,
                                     count=len(records)))
    return True


def handle_app_rename(proc, queues, message) -> bool:
    """Change a contact's local name (``APP_RENAME``, payload
    ``{ref, peer, petname}``). A petname never leaves this node."""
    got = _book_request(proc, queues, message, APP_RENAME)
    if got is None:
        return True
    req, ref, contact, store = got
    petname = req.get('petname')
    if not isinstance(petname, str) or not petname.strip() \
            or len(petname) > PETNAME_MAX:
        _emit(proc, queues, FirstContactEvent(EVENT_REFUSED, ref=ref,
                                              reason='bad_request'))
        return True
    contact.petname = petname
    _save_book(proc, store)
    _emit(proc, queues, _contact_event(EVENT_CONTACT, contact, ref))
    return True


def _drop_direct_peer(proc, queues, uuid) -> bool:
    """Let go of a DIRECT peer now; True if one was dropped.

    A cohort member is kept: its place in ``Peers`` belongs to the group the
    vote admitted it to, and dropping it would leave this node's peer list and
    the group key's holders disagreeing. Every other process replaces its
    ``Peers`` wholesale on the broadcast ``_record_peers`` sends, so the
    network stops attributing the peer's frames. Reputation keeps whatever it
    earned. Mirrors C's identity_remove_direct_peer."""
    grp = getattr(proc, 'group', None)
    members = getattr(grp, '_address_map', None) if grp is not None else None
    if isinstance(members, dict) and str(uuid) in {str(k) for k in members}:
        return False
    peer = proc.peers.find_by_uuid(uuid)
    if peer is None:
        return False
    proc.peers.remove(peer)
    proc._record_peers(queues)
    return True


def handle_app_remove(proc, queues, message) -> bool:
    """Remove a contact (``APP_REMOVE``, payload ``{ref, peer}``): the record
    goes, and a direct peer is dropped at once (see :func:`_drop_direct_peer`).
    Adding them back takes a fresh invitation."""
    got = _book_request(proc, queues, message, APP_REMOVE)
    if got is None:
        return True
    _req, ref, contact, store = got
    uuid = str(contact.identity.uuid)
    store.remove(uuid)
    _save_book(proc, store)
    dropped = _drop_direct_peer(proc, queues, uuid)
    proc.logger.info('first contact: removed %s%s', contact.petname,
                     ' and dropped the direct peer' if dropped else '')
    _emit(proc, queues, _contact_event(EVENT_REMOVED, contact, ref,
                                       peer_dropped=dropped))
    return True
