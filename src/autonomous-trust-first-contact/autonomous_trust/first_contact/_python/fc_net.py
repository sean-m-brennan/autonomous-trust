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
"""First contact in the network process: the directory and area-hub clients
over the rendezvous relays, and the registry and hub our relay serves.

FEATURE_SPLIT_PLAN Phase 7, R1/R2: moved out of ``NetworkProcess`` with the
logic unchanged. Both ride the relays as :class:`.rendezvous.RelayService`
s: their ops reach a relay through ``RelayClient.request``, their answers
come back through the service's ``on_answer``, and our relay serves the
registry (``dir_``) and the hub (``hub_``) through ``RelayServer.add_op``.
Identity's six local verbs and the drains reach this module through its own
extension (:data:`EXTENSION`), which is always on -- as before, a node
answers them whether or not ``AT_FIRST_CONTACT`` is set -- and travels with
first contact. Mirrors C's first_contact/fc_net.c.

State lives on the network process (``proc``), so it pickles with it:
``_own_entries`` / ``relay_dir`` / ``_dir_lookups`` and ``_own_cards`` /
``relay_hub`` / ``_hub_lookups``, as they were.
"""
import functools
import json
import time
from collections import deque
from queue import Full

from autonomous_trust.core.extensions import Extension, NetworkHooks
from .fc_protocol import FirstContactProtocol
from autonomous_trust.core.system import CfgIds
from . import hub as _hub
from . import registry as _registry
from autonomous_trust.rendezvous import rendezvous as _rdv
from autonomous_trust.rendezvous import rdv_net as _rdv_net
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.network.network import Network

#: Seconds a lookup waits for its relays before answering "not found".
DIR_LOOKUP_TIMEOUT = 10.0
#: Seconds an area lookup waits for its relays before answering with what came.
HUB_LOOKUP_TIMEOUT = 10.0


def init_state(proc) -> None:
    """The network process's directory and hub state (idempotent)."""
    for name, make in (('_own_entries', dict), ('relay_dir', deque), ('_dir_lookups', dict),
                       ('_own_cards', dict), ('relay_hub', deque), ('_hub_lookups', dict)):
        if not hasattr(proc, name):
            setattr(proc, name, make())
    for name in ('_fc_registry', '_fc_hub'):
        if not hasattr(proc, name):
            setattr(proc, name, None)


def _local_only(proc, message, verb):
    if getattr(message, 'from_whom', None) is not None:
        proc.logger.warning('Refusing %s from the wire', verb)
        return False
    return True


def _payload(message):
    try:
        obj = json.loads(message.obj) if isinstance(message.obj, str) else message.obj
    except (ValueError, TypeError):
        return {}
    return obj if isinstance(obj, dict) else {}


def _to_identity(proc, queues, verb, body):
    """Local IPC to identity. Raises queue.Full."""
    msg = Message(CfgIds.identity, verb, json.dumps(body), to_whom=None, from_whom=None)
    queues[CfgIds.identity].put(msg, block=True, timeout=proc.q_cadence)


# -- the directory (first_contact/registry.py) ---------------------------------------
def handle_dir_publish(proc, queues, message):
    """Identity hands us our own directory entry: file it at each of our relays
    now, and at every later registration. Local only."""
    if not _local_only(proc, message, Network.dir_publish):
        return True
    wire = _payload(message).get('entry')
    try:
        from .directory import DirectoryEntry
        handle = DirectoryEntry.from_wire(wire).handle
    except ValueError:
        proc.logger.warning('dir_publish: unusable entry')
        return True
    proc._own_entries[handle] = wire
    for _ep, client in _rdv.clients(proc, own_only=True):
        try:
            client.request({'op': 'dir_publish', 'entry': wire})
        except (OSError, ConnectionError):
            pass
    return True


def handle_dir_withdraw(proc, queues, message):
    if not _local_only(proc, message, Network.dir_withdraw):
        return True
    handle = str(_payload(message).get('handle', ''))
    proc._own_entries.pop(handle, None)
    for _ep, client in _rdv.clients(proc, own_only=True):
        try:
            client.request({'op': 'dir_withdraw', 'handle': handle})
        except (OSError, ConnectionError):
            pass
    return True


def handle_dir_lookup(proc, queues, message):
    """Ask every relay we are registered at for ``handle``. Local only."""
    if not _local_only(proc, message, Network.dir_lookup):
        return True
    from .directory import normalize_handle
    handle = normalize_handle(_payload(message).get('handle'))
    if handle is None:
        _dir_answer(proc, queues, str(_payload(message).get('handle', '')),
                    None, None, False)
        return True
    asked = set()
    for endpoint, client in _rdv.clients(proc, own_only=False):
        try:
            client.request({'op': 'dir_lookup', 'handle': handle})
            asked.add(endpoint)
        except (OSError, ConnectionError):
            pass
    if not asked:
        _dir_answer(proc, queues, handle, None, None, False)
        return True
    proc._dir_lookups[handle] = {'asked': asked, 'answered': set(),
                                 'limited': False, 'since': time.monotonic()}
    return True


def _dir_answer(proc, queues, handle, entry, endpoint, limited):
    if CfgIds.identity not in queues:
        return
    body = {'handle': handle, 'entry': entry, 'limited': bool(limited),
            'relay': '%s:%d' % endpoint if endpoint else ''}
    try:
        _to_identity(proc, queues, FirstContactProtocol.dir_result, body)
    except Full:
        proc.logger.warning('Registry: identity queue full; answer for %s dropped',
                            handle)


def drain_dir(proc, queues):
    """Registry answers -> identity: a lookup's one outcome, and the registry's
    word on our publish or withdraw."""
    while proc.relay_dir:
        endpoint, frame = proc.relay_dir.popleft()
        op = frame.get('op')
        handle = str(frame.get('handle', ''))
        if op in ('dir_entry', 'dir_limited') or (
                op == 'dir_refused' and handle in proc._dir_lookups
                and frame.get('reason') == 'not_registry'):
            pending = proc._dir_lookups.get(handle)
            if pending is None or endpoint not in pending['asked']:
                continue
            if op == 'dir_entry' and isinstance(frame.get('entry'), dict):
                del proc._dir_lookups[handle]
                _dir_answer(proc, queues, handle, frame['entry'], endpoint, False)
                continue
            pending['answered'].add(endpoint)
            pending['limited'] |= op == 'dir_limited'
            if pending['answered'] >= pending['asked']:
                del proc._dir_lookups[handle]
                _dir_answer(proc, queues, handle, None, None, pending['limited'])
            continue
        if op in ('dir_published', 'dir_refused', 'dir_withdrawn') \
                and CfgIds.identity in queues:
            body = {'op': op, 'handle': handle, 'relay': '%s:%d' % endpoint,
                    'reason': str(frame.get('reason', '') or ''),
                    'seq': frame.get('seq', 0) if isinstance(frame.get('seq'), int) else 0}
            try:
                _to_identity(proc, queues, FirstContactProtocol.dir_status, body)
            except Full:
                pass
    now = time.monotonic()
    for handle in [h for h, p in proc._dir_lookups.items()
                   if now - p['since'] > DIR_LOOKUP_TIMEOUT]:
        pending = proc._dir_lookups.pop(handle)
        _dir_answer(proc, queues, handle, None, None, pending['limited'])


def on_dir_answer(proc, endpoint, frame):
    """A registry's answer, on the relay client's reader thread: queued for
    :func:`drain_dir`."""
    if frame.get('op') == 'dir_refused':
        proc.logger.warning('Relay %s:%d refused directory %s: %s', *endpoint,
                            frame.get('handle'), frame.get('reason'))
    proc.relay_dir.append((endpoint, frame))


# -- area hubs (first_contact/hub.py) -------------------------------------------------
def handle_hub_publish(proc, queues, message):
    """Identity hands us our own area card: file it at each of our relays now,
    and at every later registration. Local only."""
    if not _local_only(proc, message, Network.hub_publish):
        return True
    wire = _payload(message).get('card')
    try:
        from .area_card import AreaCard
        area = AreaCard.from_wire(wire).area
    except ValueError:
        proc.logger.warning('hub_publish: unusable card')
        return True
    if not isinstance(area, str):
        return True
    proc._own_cards[area] = wire
    for _ep, client in _rdv.clients(proc, own_only=True):
        try:
            client.request({'op': 'hub_publish', 'card': wire})
        except (OSError, ConnectionError):
            pass
    return True


def handle_hub_withdraw(proc, queues, message):
    if not _local_only(proc, message, Network.hub_withdraw):
        return True
    area = str(_payload(message).get('area', ''))
    proc._own_cards.pop(area, None)
    for _ep, client in _rdv.clients(proc, own_only=True):
        try:
            client.request({'op': 'hub_withdraw', 'area': area})
        except (OSError, ConnectionError):
            pass
    return True


def handle_hub_lookup(proc, queues, message):
    """Ask every relay we are registered at who is listed in ``area``. Local
    only."""
    if not _local_only(proc, message, Network.hub_lookup):
        return True
    from .area_card import normalize_area
    area = normalize_area(_payload(message).get('area'))
    if area is None:
        _hub_answer(proc, queues, str(_payload(message).get('area', '')), [], False)
        return True
    if area in proc._hub_lookups:
        return True             # one in flight answers every asker
    asked = set()
    for endpoint, client in _rdv.clients(proc, own_only=False):
        try:
            client.request({'op': 'hub_lookup', 'area': area})
            asked.add(endpoint)
        except (OSError, ConnectionError):
            pass
    if not asked:
        _hub_answer(proc, queues, area, [], False)
        return True
    proc._hub_lookups[area] = {'asked': asked, 'answered': set(), 'cards': [],
                               'limited': False, 'since': time.monotonic()}
    return True


def _hub_answer(proc, queues, area, cards, limited):
    if CfgIds.identity not in queues:
        return
    body = {'area': area, 'cards': cards, 'limited': bool(limited)}
    try:
        _to_identity(proc, queues, FirstContactProtocol.hub_result, body)
    except Full:
        proc.logger.warning('Hub: identity queue full; answer for %s dropped', area)


def drain_hub(proc, queues):
    """Hub answers -> identity: a lookup's one outcome, and a hub's word on our
    publish or withdraw. A relay that is no hub answers ``not_hub``, which
    counts as an empty answer to a lookup and is not reported for a publish."""
    while proc.relay_hub:
        endpoint, frame = proc.relay_hub.popleft()
        op = frame.get('op')
        area = str(frame.get('area', ''))
        pending = proc._hub_lookups.get(area)
        if pending is not None and endpoint in pending['asked'] \
                and endpoint not in pending['answered'] \
                and (op in ('hub_cards', 'hub_limited') or (
                    op == 'hub_refused' and frame.get('reason') == 'not_hub')):
            pending['answered'].add(endpoint)
            pending['limited'] |= op == 'hub_limited'
            if op == 'hub_cards' and isinstance(frame.get('cards'), list):
                relay = '%s:%d' % endpoint
                pending['cards'].extend({'card': c, 'relay': relay}
                                        for c in frame['cards'][:_hub.LOOKUP_MAX]
                                        if isinstance(c, dict))
            if pending['answered'] >= pending['asked']:
                del proc._hub_lookups[area]
                _hub_answer(proc, queues, area, pending['cards'], pending['limited'])
            continue
        if op in ('hub_published', 'hub_refused', 'hub_withdrawn') \
                and frame.get('reason') != 'not_hub' and CfgIds.identity in queues:
            body = {'op': op, 'area': area, 'relay': '%s:%d' % endpoint,
                    'reason': str(frame.get('reason', '') or ''),
                    'seq': frame.get('seq', 0) if isinstance(frame.get('seq'), int) else 0}
            try:
                _to_identity(proc, queues, FirstContactProtocol.hub_status, body)
            except Full:
                pass
    now = time.monotonic()
    for area in [a for a, p in proc._hub_lookups.items()
                 if now - p['since'] > HUB_LOOKUP_TIMEOUT]:
        pending = proc._hub_lookups.pop(area)
        _hub_answer(proc, queues, area, pending['cards'], pending['limited'])


def on_hub_answer(proc, endpoint, frame):
    """A hub's answer, on the relay client's reader thread: queued for
    :func:`drain_hub`."""
    if frame.get('op') == 'hub_refused' and frame.get('reason') != 'not_hub':
        proc.logger.warning('Relay %s:%d refused area card %s: %s', *endpoint,
                            frame.get('area'), frame.get('reason'))
    proc.relay_hub.append((endpoint, frame))


# -- the services our relay serves (R2): the registry and the hub ---------------
def _serve_directory(proc, uuid, pubkey, op, req):
    """A registry op from registrant ``uuid``. Returns the reply frame."""
    handle = req.get('handle') if isinstance(req.get('handle'), str) else ''
    registry = getattr(proc, '_fc_registry', None)
    if registry is None:
        return {'op': 'dir_refused', 'handle': handle, 'reason': 'not_registry'}
    if op == 'dir_publish':
        return registry.publish(uuid, pubkey, req.get('entry'))
    if op == 'dir_withdraw':
        return registry.withdraw(uuid, pubkey, handle)
    if op == 'dir_lookup':
        return registry.lookup(uuid, handle)
    return {'op': 'dir_refused', 'handle': handle, 'reason': 'unknown_op'}


def _serve_hub(proc, uuid, pubkey, op, req):
    """A hub op from registrant ``uuid``. Returns the reply frame."""
    area = str(req.get('area', '') or '')
    hub = getattr(proc, '_fc_hub', None)
    if hub is None:
        return {'op': 'hub_refused', 'area': area, 'reason': 'not_hub'}
    if op == 'hub_publish':
        return hub.publish(uuid, pubkey, req.get('card'))
    if op == 'hub_withdraw':
        return hub.withdraw(uuid, pubkey, area)
    if op == 'hub_lookup':
        return hub.lookup(uuid, area)
    return {'op': 'hub_refused', 'area': area, 'reason': 'unknown_op'}


def serve_registry(proc, server, registry) -> None:
    """Serve the directory with ``registry`` (None: refuse it, not_registry) on
    relay ``server``. Mirrors C's fc_net_serve_registry."""
    proc._fc_registry = registry
    server.add_op('dir_', functools.partial(_serve_directory, proc))   # once


def serve_hub(proc, server, hub) -> None:
    """Serve the area hub with ``hub`` (None: not_hub) on relay ``server``.
    Mirrors C's fc_net_serve_hub."""
    proc._fc_hub = hub
    server.add_op('hub_', functools.partial(_serve_hub, proc))         # once


def _dir_server_started(proc, server):
    """Our relay is up: serve the directory (AT_REGISTRY). The family is always
    plugged in, so a relay that is no registry still says so."""
    init_state(proc)
    registry = proc._fc_registry
    if registry is None and _registry.registry_enabled():
        registry = _registry.Registry(_registry.load_issuers(),
                                      distrusted=functools.partial(_rdv_net.is_distrusted, proc), logger=proc.logger)
        proc.logger.info('Registry: serving the directory (%d trusted issuer(s))',
                         len(registry.issuers))
    serve_registry(proc, server, registry)


def _hub_server_started(proc, server):
    """Our relay is up: serve the area hub (AT_HUB)."""
    init_state(proc)
    hub = proc._fc_hub
    if hub is None and _hub.hub_enabled():
        hub = _hub.Hub(_hub.hub_areas(), distrusted=functools.partial(_rdv_net.is_distrusted, proc),
                       logger=proc.logger)
        proc.logger.info('Hub: serving area(s) %s', ', '.join(hub.areas) or '(none)')
    serve_hub(proc, server, hub)


def _dir_own_registered(proc, endpoint, client):
    """We registered at one of our own relays: file our entries there again,
    since a registry holds them in memory."""
    for wire in list(getattr(proc, '_own_entries', {}).values()):
        try:
            client.request({'op': 'dir_publish', 'entry': wire})
        except (OSError, ConnectionError):
            pass            # filed again at the next registration


def _hub_own_registered(proc, endpoint, client):
    for wire in list(getattr(proc, '_own_cards', {}).values()):
        try:
            client.request({'op': 'hub_publish', 'card': wire})
        except (OSError, ConnectionError):
            pass            # filed again at the next registration


_rdv.register_service(_rdv.RelayService(
    name='directory', prefix='dir_', on_answer=on_dir_answer,
    own_registered=_dir_own_registered, server_started=_dir_server_started))
_rdv.register_service(_rdv.RelayService(
    name='area_hub', prefix='hub_', on_answer=on_hub_answer,
    own_registered=_hub_own_registered, server_started=_hub_server_started))


# -- first contact's network extension ----------------------------------------
def _register(proc, proc_name: str) -> None:
    """Identity's six local verbs for the directory and the hubs."""
    if proc_name != 'network':
        return
    init_state(proc)
    for verb, fn in ((Network.dir_publish, handle_dir_publish),
                     (Network.dir_withdraw, handle_dir_withdraw),
                     (Network.dir_lookup, handle_dir_lookup),
                     (Network.hub_publish, handle_hub_publish),
                     (Network.hub_withdraw, handle_hub_withdraw),
                     (Network.hub_lookup, handle_hub_lookup)):
        proc.protocol.register_handler(verb, functools.partial(fn, proc))


def _periodic(proc, queues) -> None:
    if not hasattr(proc, 'relay_dir'):
        return
    drain_dir(proc, queues)
    drain_hub(proc, queues)


def enabled() -> bool:
    return True


EXTENSION = Extension(name='first_contact_network', enabled=enabled,
                      register_handlers=_register,
                      network=NetworkHooks(periodic=_periodic))
