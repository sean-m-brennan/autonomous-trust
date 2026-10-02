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
"""Rendezvous in the network process: the relay routes and clients, our own
relay server, reachability records, and the frames the relays carry.

FEATURE_SPLIT_PLAN Phase 7b: lifted out of ``NetworkProcess`` with the logic
unchanged, as functions over the process (``proc``), the way first contact's
fc_net.py is. The state lives on the process, so it pickles with it, and keeps
its old names (``proc._relay_routes`` and the rest). The hooks in
:mod:`.rendezvous` call these. Mirrors C's rdv_net.c.
"""
import functools
import json
import threading
import time
import uuid as _uuid_mod
from collections import deque
from queue import Full

from autonomous_trust.core.system import CfgIds
from . import relay as _relay
from . import rendezvous as _rdv
from autonomous_trust.core.network.message import Message, WireFormatMismatch
from autonomous_trust.core.network.network import Network

#: Identity's verb for a reachability record a relay lookup answered (first
#: contact's FirstContactProtocol.reach_record), named here rather than imported
#: so rendezvous does not import first contact. Mirrors rdv_net.c's
#: NET_ID_REACH_RECORD.
_ID_REACH_RECORD = 'reach_record'

#: Seconds between attempts to (re)register with one relay.
RELAY_RETRY_SEC = 5.0
#: How many times a frame every relay refused is walked again.
RELAY_RETRY_ROUNDS = 3
#: Seconds between lookups of one peer's reachability record.
REACH_LOOKUP_INTERVAL = 60.0


def _setting(proc, name):
    """``proc``'s own value of the setting ``name`` if it has one (a test
    shortens it), else this module's."""
    return getattr(proc, name, globals()[name])


def init_state(proc) -> None:
    """The network process's relay state (idempotent)."""
    # Rendezvous relays (network/relay.py). Built in the worker, in the
    # child: sockets and threads do not survive the fork.
    if not hasattr(proc, 'relay_messages'):   # (frame, from_uuid, endpoint)
        proc.relay_messages = deque()
    if not hasattr(proc, 'relay_unreachable'):  # (endpoint, to_uuid) a relay refused
        proc.relay_unreachable = deque()
    # peer uuid (str) -> [(host, port), ...]: its relays in preference
    # order, the ACTIVE one first. One relay carries a peer's traffic at a
    # time; a failure rotates the next to the front.
    if not hasattr(proc, '_relay_routes'):
        proc._relay_routes = {}
    # peer uuid (str) -> (frame, relays tried): the last frame sent to the
    # peer by relay, kept to resend it through the next relay when the
    # active one says it cannot reach the peer (a relay acknowledges
    # nothing, so the refusal is the only signal, and it comes later).
    if not hasattr(proc, '_relay_last'):
        proc._relay_last = {}
    # peer uuid (str) -> (monotonic due time, rounds so far): a frame every
    # relay refused, to walk the route again -- the peer may register a few
    # seconds later (a relay restarting, or it minted its link before its
    # own registration finished).
    if not hasattr(proc, '_relay_retry'):
        proc._relay_retry = {}
    if not hasattr(proc, '_relay_clients'):        # (host, port) -> RelayClient
        proc._relay_clients = {}
    if not hasattr(proc, '_relay_connecting'):  # endpoints a background connect is on
        proc._relay_connecting = set()
    if not hasattr(proc, '_relay_last_try'):       # endpoint -> monotonic time of last try
        proc._relay_last_try = {}
    if not hasattr(proc, '_relay_live'):           # peer uuid -> relay its traffic last came by
        proc._relay_live = {}
    # endpoint -> (uuid, fp): which relay a link or our config says answers
    # there. A client for that endpoint refuses anything else.
    if not hasattr(proc, '_relay_pins'):
        proc._relay_pins = {}
    if not hasattr(proc, '_relay_queues'):       # set in process(), for relay_identity
        proc._relay_queues = None
    if not hasattr(proc, '_own_record'):         # our reachability record (wire dict)
        proc._own_record = None
    if not hasattr(proc, 'relay_records'):    # (record id, wire) answers to lookups
        proc.relay_records = deque()
    if not hasattr(proc, '_reach_asked'):          # peer uuid -> monotonic time of last lookup
        proc._reach_asked = {}
    if not hasattr(proc, '_relay_server'):
        proc._relay_server = None


def is_distrusted(proc, uuid, pubkey_hex):
    """The relay gate, both directions: reputation cut ``uuid`` off, or
    the proven key belongs to someone it cut off, or ``uuid`` is a peer we
    know under a DIFFERENT key (an impostor). Unknown and neutral pass."""
    uuid = str(uuid).lower()
    key = str(pubkey_hex or '').lower()
    if proc.is_excluded(uuid, key):
        return True
    known = proc._peer_key(uuid)
    return known is not None and key != '' and known != key


def _drop_distrusted_relays(proc):
    """Act on a new exclusion at once: evict a distrusted client from the
    relay we serve, and hang up on a relay we distrust (its peers' routes
    then fail over)."""
    if proc._relay_server is not None:
        for uuid in list(proc._relay_server.registered()):
            if proc.is_excluded(uuid):
                proc._relay_server.evict(uuid)
    for endpoint, client in list(proc._relay_clients.items()):
        if client.relay_uuid is not None and client.connected \
                and is_distrusted(proc, client.relay_uuid, client.relay_key):
            proc.logger.warning('Relay: %s:%d (%s) is now distrusted; '
                                'disconnecting', endpoint[0], endpoint[1],
                                client.relay_uuid[:8])
            client.close()


def _relay_client(proc, endpoint):
    client = proc._relay_clients.get(endpoint)
    if client is None:
        client = _relay.RelayClient(
            endpoint, proc.myself,
            lambda frm, frame, ep=endpoint:
                proc.relay_messages.append((frame, frm, ep)),
            logger=proc.logger,
            on_unreachable=lambda to, ep=endpoint:
                proc.relay_unreachable.append((ep, to)),
            on_record=lambda rid, wire:
                proc.relay_records.append((rid, wire)),
            pin=proc._relay_pins.get(endpoint),
            distrusted=functools.partial(is_distrusted, proc))
        # The services riding the relays hear their ops' answers.
        for svc in _rdv.services():
            if svc.prefix and svc.on_answer is not None:
                client.on_op(svc.prefix, lambda frame, ep=endpoint, svc=svc:
                             svc.on_answer(proc, ep, frame))
        proc._relay_clients[endpoint] = client
    return client


def _pin_relay(proc, endpoint, pin):
    """Remember that ``pin`` answers at ``endpoint``. A second, DIFFERENT
    pin for the same endpoint is refused (logged): two links disagreeing
    on who a relay is means one of them is wrong, and the first wins."""
    if pin is None:
        return
    known = proc._relay_pins.get(endpoint)
    if known is not None and known != pin:
        proc.logger.warning('Relay: %s:%d is pinned to %s already; ignoring a '
                            'pin to %s', endpoint[0], endpoint[1],
                            known[0][:8], pin[0][:8])
        return
    proc._relay_pins[endpoint] = pin
    client = proc._relay_clients.get(endpoint)
    if client is not None and client.pin != pin:
        client.pin = pin
        proven = client.proven_pin
        if client.connected and proven != pin:
            proc.logger.warning('Relay: %s:%d is not the pinned relay; '
                                'disconnecting', endpoint[0], endpoint[1])
            client.close()


def _announce_own_relay(proc, endpoint):
    """Tell identity that one of our own relays proved who it is, so the
    links it mints pin that relay, and file our reachability record there
    (a relay holds records in memory, so every registration refills it).
    Local IPC."""
    client = proc._relay_clients.get(endpoint)
    if client is not None and proc._own_record is not None \
            and endpoint in _relay.own_relays():
        try:
            client.publish(proc._own_record)
        except (OSError, ConnectionError) as err:
            proc.logger.debug('Relay: could not file our record at %s:%d (%s)',
                              endpoint[0], endpoint[1], err)
    if client is not None and endpoint in _relay.own_relays():
        # And whatever the services riding the relay hold here (first
        # contact's directory entries and area cards).
        for svc in _rdv.services():
            if svc.own_registered is not None:
                svc.own_registered(proc, endpoint, client)
    pin = client.proven_pin if client is not None else None
    queues = proc._relay_queues
    if pin is None or queues is None or CfgIds.identity not in queues \
            or endpoint not in _relay.own_relays():
        return
    msg = Message(CfgIds.identity, Network.relay_identity,
                  json.dumps({'relay': '%s:%d' % endpoint,
                              'uuid': pin[0], 'fp': pin[1]}),
                  to_whom=None, from_whom=None)
    try:
        queues[CfgIds.identity].put(msg, block=True, timeout=proc.q_cadence)
    except Full:
        proc.logger.warning('Relay: identity queue full; own relay pin not sent')


def _start_relays(proc):
    """Serve as a relay (AT_RELAY) and register with our own relays
    (AT_USE_RELAY). Registration runs in the background and a failure is
    retried by :meth:`_maintain_relays`."""
    for endpoint, pin in _relay.own_relay_hints():
        _pin_relay(proc, endpoint, pin)
    if _relay.relay_enabled() and proc._relay_server is None:
        try:
            proc._relay_server = _relay.RelayServer(
                proc.myself.address or '0.0.0.0', _relay.relay_port(),
                proc.logger, identity=proc.myself,
                distrusted=functools.partial(is_distrusted, proc))
        except OSError as err:
            proc.logger.error('Relay: cannot serve on port %d (%s)',
                              _relay.relay_port(), err)
        else:
            for svc in _rdv.services():
                if svc.server_started is not None:
                    svc.server_started(proc, proc._relay_server)
    _maintain_relays(proc)


def _relays_to_hold(proc):
    """Every relay we stay registered with: our own, and each one a peer's
    route names -- a peer can reach us only through a relay we are
    registered at, and it may fail over to any on its list."""
    held = list(_relay.own_relays())
    for route in proc._relay_routes.values():
        for endpoint in route:
            if endpoint not in held:
                held.append(endpoint)
    return held


def _maintain_relays(proc):
    """Keep our registrations alive. Without them no one can reach us
    through a relay, and a node that only listens never sends -- so
    "retry on the next send" would never come. Each attempt runs on its own
    thread: a dead relay costs a connect timeout, which the network loop
    must not wait out."""
    now = time.monotonic()
    for endpoint in _relays_to_hold(proc):
        client = _relay_client(proc, endpoint)
        if client.connected or endpoint in proc._relay_connecting:
            continue
        last = proc._relay_last_try.get(endpoint, float('-inf'))
        if now - last < _setting(proc, 'RELAY_RETRY_SEC'):
            continue
        proc._relay_last_try[endpoint] = now
        proc._relay_connecting.add(endpoint)
        threading.Thread(target=functools.partial(_connect_relay, proc), args=(endpoint,),
                         daemon=True, name='relay-connect').start()


def _connect_relay(proc, endpoint):
    client = _relay_client(proc, endpoint)
    try:
        client.connect()
        _announce_own_relay(proc, endpoint)
    except (OSError, ConnectionError) as err:
        if client.refused:
            proc.logger.warning('Relay: %s:%d refused: %s', endpoint[0],
                                endpoint[1], client.refused)
        else:
            proc.logger.debug('Relay: %s:%d not reachable yet (%s)',
                              endpoint[0], endpoint[1], err)
    finally:
        proc._relay_connecting.discard(endpoint)


def _relay_send(proc, uuid, frame):
    """Send ``frame`` to peer ``uuid`` through its active relay, failing
    over down its route when a relay cannot be reached. Raises
    ConnectionError when none can."""
    key = str(uuid).lower()
    route = proc._relay_routes.get(key) or []
    last_err = None
    for _ in range(len(route)):
        endpoint = route[0]
        try:
            _relay_client(proc, endpoint).send(key, frame)
        except (OSError, ConnectionError) as err:
            last_err = err
            proc.logger.info('Relay: %s:%d unusable for %s (%s); trying the '
                             'next', endpoint[0], endpoint[1], key[:8], err)
            route.append(route.pop(0))
            continue
        proc._relay_last[key] = (frame, {endpoint})
        proc._relay_retry.pop(key, None)    # a new frame: the old one is moot
        return
    _lookup_reach(proc, key)
    raise ConnectionError('no relay reaches %s (%s)' % (key[:8], last_err))


def _drain_relay_unreachable(proc):
    """A relay said it cannot reach a peer: fail over to the peer's next
    relay and resend the frame the refusal answers. Each frame is tried at
    most once per relay, so a peer registered nowhere ends the walk."""
    while proc.relay_unreachable:
        endpoint, to = proc.relay_unreachable.popleft()
        route = proc._relay_routes.get(to)
        if not route or route[0] != endpoint:
            continue            # stale: already failed over
        route.append(route.pop(0))
        frame, tried = proc._relay_last.get(to, (None, set()))
        if frame is None:
            continue
        while route[0] not in tried:
            endpoint = route[0]
            tried.add(endpoint)
            try:
                _relay_client(proc, endpoint).send(to, frame)
                proc.logger.info('Relay: %s now reached through %s:%d',
                                 to[:8], endpoint[0], endpoint[1])
                break
            except (OSError, ConnectionError):
                route.append(route.pop(0))
        else:
            rounds = proc._relay_retry.get(to, (0.0, 0))[1]
            _lookup_reach(proc, to)
            if rounds < _setting(proc, 'RELAY_RETRY_ROUNDS'):
                due = time.monotonic() + _setting(proc, 'RELAY_RETRY_SEC')
                proc._relay_retry[to] = (due, rounds + 1)
                proc.logger.info('Relay: none of %d relay(s) reaches %s yet; '
                                 'retrying in %.0f s', len(route), to[:8],
                                 _setting(proc, 'RELAY_RETRY_SEC'))
            else:
                proc._relay_retry.pop(to, None)
                proc.logger.warning('Relay: none of %d relay(s) reaches %s',
                                    len(route), to[:8])


def _retry_refused_relayed(proc):
    """Resend each frame every relay refused, once its retry is due, as a
    fresh walk down the peer's route."""
    now = time.monotonic()
    for to, (due, _rounds) in list(proc._relay_retry.items()):
        if now < due:
            continue
        frame, _tried = proc._relay_last.get(to, (None, None))
        route = proc._relay_routes.get(to)
        if frame is None or not route:
            proc._relay_retry.pop(to, None)
            continue
        # Parked, not dropped, until the walk it starts ends one way or the
        # other (a refusal re-arms it; a delivery says nothing).
        proc._relay_retry[to] = (float('inf'), _rounds)
        endpoint = route[0]
        try:
            _relay_client(proc, endpoint).send(to, frame)
            proc._relay_last[to] = (frame, {endpoint})
        except (OSError, ConnectionError):
            proc._relay_last[to] = (frame, {endpoint})
            proc.relay_unreachable.append((endpoint, to))


def handle_relay_route(proc, queues, message):
    """Identity says: reach peer ``uuid`` through ``relays`` (a list, in
    preference order; ``relay``, one, is also accepted). They go ahead of
    any the route already names. Local IPC only -- a peer must not be able
    to reroute this node's traffic, so anything carrying a sender is
    refused."""
    if getattr(message, 'from_whom', None) is not None:
        proc.logger.warning('Refusing relay_route from the wire')
        return True
    try:
        spec = json.loads(message.obj) if isinstance(message.obj, str) else message.obj
        uuid = str(spec['uuid']).lower()
        given = spec.get('relays')
        if given is None:
            given = [spec['relay']]
        if not isinstance(given, list):
            raise TypeError('relays must be a list')
    except (KeyError, TypeError, ValueError, AttributeError):
        proc.logger.warning('relay_route: unusable request %r', message.obj)
        return True
    endpoints = []
    for item in given:
        endpoint, pin = _relay.parse_hint(str(item))
        if endpoint is None:
            proc.logger.warning('relay_route: %r is not [uuid:fp@]host:port', item)
        else:
            _pin_relay(proc, endpoint, pin)
            endpoints.append(endpoint)
    if not endpoints:
        return True
    route = _relay.merge_endpoints(endpoints, proc._relay_routes.get(uuid, []))
    proc._relay_routes[uuid] = route
    # Register with the first now: the hello that follows goes through it.
    # The rest are registered in the background by _maintain_relays.
    try:
        _relay_client(proc, route[0]).connect()
        _announce_own_relay(proc, route[0])
    except (OSError, ConnectionError) as err:
        proc.logger.warning('Relay: cannot register with %s:%d (%s)',
                            route[0][0], route[0][1], err)
    _maintain_relays(proc)
    return True


def handle_reach_publish(proc, queues, message):
    """Identity hands us our own current reachability record: file it at
    each of our relays now (and at every later registration). Local only."""
    if getattr(message, 'from_whom', None) is not None:
        proc.logger.warning('Refusing reach_publish from the wire')
        return True
    try:
        wire = json.loads(message.obj) if isinstance(message.obj, str) else message.obj
        if not isinstance(wire, dict) or 'body' not in wire or 'sig' not in wire:
            raise ValueError(wire)
    except (ValueError, TypeError):
        proc.logger.warning('reach_publish: unusable record')
        return True
    proc._own_record = wire
    for endpoint in _relay.own_relays():
        client = proc._relay_clients.get(endpoint)
        if client is not None and client.connected:
            try:
                client.publish(wire)
            except (OSError, ConnectionError):
                pass            # filed again at the next registration
    return True


def _lookup_reach(proc, uuid):
    """We have lost ``uuid`` through every relay we know: ask each relay we
    are registered at for its reachability record (filed under its key's
    fingerprint). Answers go to identity, which verifies them."""
    key = proc._peer_key(uuid)
    if not key:
        return
    now = time.monotonic()
    if now - proc._reach_asked.get(uuid, float('-inf')) < _setting(proc, 'REACH_LOOKUP_INTERVAL'):
        return
    proc._reach_asked[uuid] = now
    rid = _relay.key_fingerprint(key)
    asked = 0
    for client in list(proc._relay_clients.values()):
        if client.connected:
            try:
                client.lookup(rid)
                asked += 1
            except (OSError, ConnectionError):
                pass
    if asked:
        proc.logger.info('Relay: looking up where %s is now (%d relay(s))',
                         str(uuid)[:8], asked)


def _drain_relay_records(proc, queues):
    """Hand lookup answers to identity (the single writer of contacts),
    which verifies each against the contact's key before using it."""
    while proc.relay_records:
        rid, wire = proc.relay_records.popleft()
        if not isinstance(wire, dict) or CfgIds.identity not in queues:
            continue
        msg = Message(CfgIds.identity, _ID_REACH_RECORD,
                      json.dumps(wire), to_whom=None, from_whom=None)
        try:
            queues[CfgIds.identity].put(msg, block=True, timeout=proc.q_cadence)
        except Full:
            proc.logger.warning('Relay: identity queue full; record %s dropped',
                                rid[:8])


def _tell_identity_relay_peer(proc, queues, uuid):
    """Local IPC: ``uuid`` reached us through a relay, first in this run or
    through another one (Network.relay_peer)."""
    if CfgIds.identity not in queues:
        return
    msg = Message(CfgIds.identity, Network.relay_peer, json.dumps({'uuid': uuid}),
                  to_whom=None, from_whom=None)
    try:
        queues[CfgIds.identity].put(msg, block=False)
    except Full:
        proc.logger.debug('Relay: identity queue full; relay_peer for %s dropped',
                          uuid[:8])


def _drain_relayed(proc, queues, budget):
    """Hand relayed frames to the same parse-and-route paths UDP uses,
    attributing each by the uuid the RELAY stamped, not by an address."""
    drained = 0
    while drained < budget and proc.relay_messages:
        frame, frm, endpoint = proc.relay_messages.popleft()
        drained += 1
        # Replies go back the way this came: that relay becomes the
        # active one, ahead of the rest of the route.
        proc._relay_routes[frm] = _relay.merge_endpoints(
            [endpoint], proc._relay_routes.get(frm, []))
        try:
            peer = proc.peers.find_by_uuid(_uuid_mod.UUID(frm))
        except ValueError:
            continue
        if peer is not None:
            fmt = proc._wire_format_for_addr(peer.address)
            try:
                plain = proc.myself.decrypt(frame, peer)
            except Exception:
                if not proc._accept_unencrypted(frame, peer, queues,
                                                wire_format=fmt):
                    proc.logger.error('Relay: frame from %s neither decrypts '
                                      'nor is an unencrypted verb', frm[:8])
                continue
            if proc._relay_live.get(frm) != endpoint:
                # Once per change, so an operator can see which relay
                # carries a peer, and when it failed over.
                proc._relay_live[frm] = endpoint
                proc.logger.info('Relay: %s is talking to us through %s:%d',
                                 frm[:8], endpoint[0], endpoint[1])
                _tell_identity_relay_peer(proc, queues, frm)
            proc._msg_to_queue(plain, peer, queues, 'relay', wire_format=fmt)
            continue
        # A sender we do not know yet: only plaintext can be read (the
        # first-contact hello). The envelope must name the sender the relay
        # vouched for -- the relay cannot forge `from`, so neither may the
        # frame.
        try:
            probe = Message.parse(frame, None, validate=False)
            claimed = str(getattr(probe.from_whom, 'uuid', '')).lower()
        except Exception:
            proc.logger.debug('Relay: unreadable frame from unknown %s', frm[:8])
            continue
        if claimed != frm:
            proc.logger.warning('Relay: frame from %s claims to be %s; '
                                'dropped', frm[:8], claimed[:8])
            continue
        try:
            proc._msg_to_queue(frame, 'relay:' + frm, queues, 'relay',
                               validate=False, opaque=True)
        except (UnicodeDecodeError, WireFormatMismatch):
            proc.logger.debug('Relay: undecodable frame from unknown %s', frm[:8])
    return drained
