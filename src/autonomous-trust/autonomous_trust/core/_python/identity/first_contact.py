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
import json
import logging
import os
import time

from ..system import CfgIds
from ..network.message import Message
from ..config.configuration import to_json_string, atomic_write, Configuration
from .identity import Identity
from .protocol import IdentityProtocol
from ..contacts import (Invitation, InvalidInvitation, Contact, Contacts,
                       Provenance)

_logger = logging.getLogger(__name__)

#: Environment flag. The feature is opt-in; absent/empty means OFF.
_FLAG = 'AT_FIRST_CONTACT'


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
    proc.protocol.register_handler(IdentityProtocol.hello,
                                   lambda q, m: handle_hello(proc, q, m))
    proc.protocol.register_handler(IdentityProtocol.hello_ack,
                                   lambda q, m: handle_hello_ack(proc, q, m))


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
    return True


#: How many reachability hints one contact keeps. A peer that re-handshakes
#: from a new network on every join would otherwise grow its hint list without
#: bound in a file that is never pruned; the newest is the one worth trying
#: first, so the list is most-recent-first and truncated here.
MAX_RENDEZVOUS_HINTS = 4


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


def _record_contact(proc, identity, nonce='', endpoint=''):
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

    Returns the stored Contact, or None if it could not be recorded."""
    store = _contacts_store(proc)
    try:
        contact = store.get(str(identity.uuid))
    except (AttributeError, TypeError):
        contact = None
    if contact is None:
        contact = Contact(identity, rendezvous=[endpoint] if endpoint else [],
                          provenance=Provenance.token, nonce=nonce)
        store.add(contact)
        proc.logger.info('first contact: recorded %s as an unverified contact',
                         contact.petname)
    else:
        if endpoint:
            hints = [endpoint] + [h for h in contact.rendezvous if h != endpoint]
            contact.rendezvous = hints[:MAX_RENDEZVOUS_HINTS]
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
    if invitation.is_expired():
        proc.logger.info('first-contact hello: invitation expired; ignoring')
        return True
    nonce = invitation.nonce
    spent = getattr(proc, '_first_contact_nonces', None)
    if spent is None:
        spent = proc._first_contact_nonces = SpentNonces()
    if nonce in spent:
        proc.logger.warning('first-contact hello: nonce already spent (single-use); ignoring')
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
    _record_contact(proc, sender, nonce=nonce,
                    endpoint=getattr(sender, 'address', '') or '')
    return True


def handle_hello_ack(proc, queues, message) -> bool:
    """Initiator side: the inviter accepted; admit them as a direct peer so the
    channel is live both ways (we already hold their key from the invitation)."""
    accepter = message.from_whom
    if not isinstance(accepter, Identity):
        proc.logger.warning('first-contact ack with no sender identity; ignoring')
        return True
    _admit_direct_peer(proc, queues, accepter)
    # Our own side of the address book. The redeemer usually already has a
    # Contact for this identity (redeem_invitation built one, possibly verified
    # in-person); the preserve rule above keeps that posture and only refreshes
    # where the inviter answered from.
    nonce = ''
    try:
        payload = json.loads(message.obj) if isinstance(message.obj, str) else message.obj
        if isinstance(payload, dict):
            nonce = str(payload.get('nonce', '') or '')
    except (ValueError, TypeError):
        pass
    _record_contact(proc, accepter, nonce=nonce,
                    endpoint=getattr(accepter, 'address', '') or '')
    proc.logger.info('first contact: %s accepted; direct peer established',
                     accepter.nickname)
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


def initiate(proc, queues, invitation_blob, endpoint=None):
    """Initiator side: reach the inviter named in ``invitation_blob`` and open
    the handshake.

    :param invitation_blob: the invitation link/blob (or an :class:`Invitation`).
    :param endpoint: override the reachable host; defaults to the invitation's
        first rendezvous hint, then the inviter's advertised address. Only the
        host is used — Phase 1 assumes the shared comm port (cross-port waits on
        the rendezvous relay layer).
    :returns: the inviter's public :class:`Identity`.
    """
    invitation = Invitation.decode(invitation_blob)
    inviter = invitation.verify_signature()
    host = endpoint
    if host is None and invitation.rendezvous:
        host = invitation.rendezvous[0]
    if host is None:
        host = inviter.address
    inviter.address = endpoint_host(host)
    blob = invitation_blob if isinstance(invitation_blob, str) else invitation.encode()
    hello = Message(proc.name, IdentityProtocol.hello, blob,
                    to_whom=inviter, from_whom=proc.identity, encrypt=False)
    queues[CfgIds.network].put(hello, block=True, timeout=proc.q_cadence)
    return inviter
