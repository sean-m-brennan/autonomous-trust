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
"""One human, several devices, on the wire (FIRST_CONTACT_PLAN Phase 4,
slice 1b). Part of first contact: registered by :func:`.first_contact.register`,
so off unless ``AT_FIRST_CONTACT`` is on.

The offline half (first_contact/device.py) says when a device belongs with a
contact. This moves the two things it needs:

  1. **Our own device cert, to each contact** (``device_cert``, sealed). Sent
     once a handshake makes us direct peers, and to every contact that is a
     peer at startup, as reachability records are. A contact learns our
     operator key from it (``adopt_operator``), and only from a cert naming
     the very node that sent it.
  2. **A new device, announcing itself** (``device_announce``, plaintext: the
     contact does not know this node yet). At startup a node holding a cert
     tells every contact in its store -- the store a pairing or a backup gave
     it -- and the contact files it under the matching verified contact
     (``link_device``), admits it as a direct peer, and tells its app
     (``device_linked``). **Nothing comes back**: a refused announce is
     silent, so a stranger learns nothing from sending one.

The node's own cert is written by the operator's tooling
(``tools/device_cert.py``) to ``<cfg_dir>/device_cert.cfg.json``; the operator
key itself never enters a node. A cert that does not name this node is
ignored. Same verbs and rules as C's ``first_contact/device_contact.c``.
"""
import json
import os
from queue import Full

from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config.configuration import Configuration
from autonomous_trust.core.network.message import Message
from autonomous_trust.rendezvous import relay as _relay
from .device import DeviceCert, InvalidDevice, adopt_operator, link_device
from autonomous_trust.core.identity.identity import Identity
from .fc_protocol import FirstContactProtocol

DEVICE_CERT_FILENAME = 'device_cert'

#: ContactEvent.kind for a further device filed under a contact. C's
#: AT_APP_EVENT_FC_DEVICE_LINKED.
EVENT_DEVICE_LINKED = 'device_linked'


def _fc():
    from . import first_contact
    return first_contact


def device_cert_path(cfg_dir=None) -> str:
    return os.path.join(cfg_dir or Configuration.get_cfg_dir(),
                        DEVICE_CERT_FILENAME + Configuration.file_ext)


def own_cert(proc):
    """This node's device cert, or None: none installed, unreadable, forged,
    or naming another node. Re-read only when the file changes."""
    path = device_cert_path()
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        proc._device_cert_cache = (None, None)
        return None
    cached_mtime, cert = getattr(proc, '_device_cert_cache', (None, None))
    if cached_mtime == mtime:
        return cert
    cert = None
    try:
        with open(path) as fh:
            cert = DeviceCert.from_wire(json.load(fh)).verify()
        if not cert.names(proc.identity):
            proc.logger.warning('device cert at %s names another node; ignored', path)
            cert = None
    except (OSError, ValueError, InvalidDevice) as err:
        proc.logger.warning('device cert at %s unusable (%s); ignored', path, err)
        cert = None
    proc._device_cert_cache = (mtime, cert)
    return cert


def register(proc) -> None:
    import functools
    proc._device_cert_cache = (None, None)
    proc.protocol.register_handler(FirstContactProtocol.device_cert,
                                   functools.partial(handle_device_cert, proc))
    proc.protocol.register_handler(FirstContactProtocol.device_announce,
                                   functools.partial(handle_device_announce, proc))


def _contact_peers(proc):
    """Every device of every contact that is a peer right now."""
    peers = []
    for contact in _fc()._contacts_store(proc).all():
        for ident in contact.identities():
            peer = proc.peers.find_by_uuid(ident.uuid)
            if peer is not None and str(peer.uuid) != str(proc.identity.uuid):
                peers.append(peer)
    return peers


def push_own_cert(proc, queues, peers=None) -> int:
    """Send our device cert, sealed, to ``peers`` (Identities), or to every
    contact that is a peer now. Returns how many were sent."""
    cert = own_cert(proc)
    if cert is None or CfgIds.network not in queues:
        return 0
    body = json.dumps(cert.to_wire())
    sent = 0
    for peer in _contact_peers(proc) if peers is None else peers:
        msg = Message(proc.name, FirstContactProtocol.device_cert, body,
                      to_whom=peer, from_whom=proc.identity)
        try:
            queues[CfgIds.network].put(msg, block=True, timeout=proc.q_cadence)
            sent += 1
        except Full:
            proc.logger.warning('first contact: network queue full; device cert not '
                                'pushed to %s', str(peer.uuid)[:8])
    return sent


def handle_device_cert(proc, queues, message) -> bool:
    """A contact's own device cert: learn its operator key. Only from the
    contact's first device, and only a cert naming that node."""
    sender = message.from_whom
    if not isinstance(sender, Identity):
        return True
    from . import sibling_sync
    if sibling_sync.on_device_cert(proc, queues,
                                   sender, _fc()._app_payload(message) or message.obj):
        return True     # it answered a pair handshake
    store = _fc()._contacts_store(proc)
    contact = store.get(str(sender.uuid))
    if contact is None or contact.uuid != str(sender.uuid):
        proc.logger.debug('first contact: device cert from %s, not a contact\'s first '
                          'device; ignored', str(sender.uuid)[:8])
        return True
    if _fc()._signing_key(sender) != _fc()._signing_key(contact.identity):
        proc.logger.warning('first contact: device cert from %s under another key; '
                            'ignored', contact.petname)
        return True
    had = contact.operator_key
    reason = adopt_operator(contact, _fc()._app_payload(message) or message.obj, store)
    if reason:
        proc.logger.warning('first contact: device cert from %s refused (%s)',
                            contact.petname, reason)
        return True
    if contact.operator_key != had:
        try:
            store.save()
        except OSError as err:
            proc.logger.warning('could not persist contact for %s (%s)',
                                contact.petname, err)
        proc.logger.info('first contact: learned the operator key of %s', contact.petname)
        sibling_sync.push_changes(proc, queues)
    return True


def _own_hints(proc):
    fc = _fc()
    return [fc._own_relay_hint(proc, ep, pin) for ep, pin in _relay.own_relay_hints()]


def announce(proc, queues, contacts=None) -> int:
    """Tell every device of every contact in our store (or of ``contacts``)
    that this node is one of our operator's devices. Plaintext: they may not
    know this node yet. Returns how many were sent (0 with no cert
    installed)."""
    cert = own_cert(proc)
    if cert is None or CfgIds.network not in queues:
        return 0
    body = json.dumps({'cert': cert.to_wire(), 'relays': _own_hints(proc)[:_relay.MAX_RELAYS]})
    me = str(proc.identity.uuid)
    sent = 0
    for contact in _fc()._contacts_store(proc).all() if contacts is None else contacts:
        for ident in contact.identities():
            if str(ident.uuid) == me:
                continue
            msg = Message(proc.name, FirstContactProtocol.device_announce, body,
                          to_whom=ident, from_whom=proc.identity, encrypt=False)
            try:
                queues[CfgIds.network].put(msg, block=True, timeout=proc.q_cadence)
                sent += 1
            except Full:
                proc.logger.warning('first contact: network queue full; announce not '
                                    'sent to %s', str(ident.uuid)[:8])
    if sent:
        proc.logger.info('first contact: announced this device to %d contact node(s)', sent)
    return sent


def handle_device_announce(proc, queues, message) -> bool:
    """A node says it is another device of one of our contacts. File it (the
    link rules decide), admit it as a direct peer, route to it, and tell the
    app. Sends nothing back, refused or not."""
    fc = _fc()
    sender = message.from_whom
    if not isinstance(sender, Identity):
        proc.logger.warning('first contact: device announce with no sender identity; '
                            'ignoring')
        return True
    payload = fc._app_payload(message) or {}
    store = fc._contacts_store(proc)
    known = str(sender.uuid) in store
    contact, reason = link_device(store, sender.publish(), payload.get('cert'))
    if reason:
        proc.logger.info('first contact: device announce from %s refused (%s)',
                         str(sender.uuid)[:8], reason)
        return True
    if known:
        return True     # already filed here: nothing new to say
    try:
        store.save()
    except OSError as err:
        proc.logger.warning('could not persist contact for %s (%s)', contact.petname, err)
    from . import sibling_sync
    sibling_sync.push_changes(proc, queues)
    fc._admit_direct_peer(proc, queues, sender)
    relays = [str(h) for h in payload.get('relays') or [] if isinstance(h, str)]
    hints = fc._relay_hints(relays)
    have = {_relay.parse_endpoint(h) for h in hints}
    hints += [h for h in _own_hints(proc) if _relay.parse_endpoint(h) not in have]
    fc._send_relay_route(proc, queues, sender.uuid, hints[:_relay.MAX_RELAYS])
    fc._push_own_record(proc, queues, [sender])
    proc.logger.info('first contact: %s is another device of %s; linked',
                     sender.nickname, contact.petname)
    fc._emit(proc, queues, fc._contact_event(EVENT_DEVICE_LINKED, contact,
                                             device_uuid=str(sender.uuid)))
    return True
