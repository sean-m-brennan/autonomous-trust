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
"""Rendezvous -- reaching a node across NAT -- as an extension of the network
process (FEATURE_SPLIT_PLAN Phase 7).

The network loop names none of the relay; it calls these through
:class:`..extensions.NetworkHooks`, and the local verbs register through the
extension hook. The relay's network-process code is :mod:`.rdv_net`, as
functions over the process (FEATURE_SPLIT_PLAN Phase 7b). Mirrors C's
``rendezvous_net_ext`` in rdv_net.c.

Always enabled: each piece keeps its own gate, as before (``AT_RELAY`` serves,
``AT_USE_RELAY`` registers, a route exists only where identity set one).
"""
import functools
from dataclasses import dataclass
from typing import Any, Callable, Optional

from autonomous_trust.core.extensions import Extension, NetworkHooks
from . import rdv_net as _net
from . import relay as _relay
from autonomous_trust.core.network.network import Network
from autonomous_trust.core.system import CfgIds

#: The roster app verbs (roster.py), named here so the extension declares them
#: without importing the handlers at load.
APP_ROSTER_INSTALL = 'app_relay_roster_install'
APP_ROSTER_REMOVE = 'app_relay_roster_remove'


# -- services riding the relays (FEATURE_SPLIT_PLAN Phase 7, R1/R2) ----------
@dataclass(frozen=True)
class RelayService:
    """A feature that rides the rendezvous relays, as first contact's
    directory registry ("dir_" ops) and area hub ("hub_" ops) do. Mirrors C's
    net_rdv_service_t (network/net_rendezvous.h). Every member but ``name``
    may be None.

    ``on_answer(proc, endpoint, frame)`` gets every answer whose op starts
    with ``prefix``, on the relay client's reader thread.
    ``own_registered(proc, endpoint, client)`` runs each time we register at
    one of our OWN relays, so the service refiles what it holds there.
    ``server_started(proc, server)`` runs once our RelayServer is up, so the
    service plugs in its ops (``RelayServer.add_op``). ``reset(proc)`` drops
    its network-process state (tests)."""
    name: str
    prefix: Optional[str] = None
    on_answer: Optional[Callable[[Any, Any, dict], None]] = None
    own_registered: Optional[Callable[[Any, Any, Any], None]] = None
    server_started: Optional[Callable[[Any, Any], None]] = None
    reset: Optional[Callable[[Any], None]] = None


#: Most services the relay carries. Same as C's NET_RDV_SERVICES_MAX.
SERVICES_MAX = 4
_services: list = []


def register_service(svc: RelayService) -> bool:
    """Register ``svc`` (at import). False for an unnamed, duplicate or
    surplus one. Mirrors C's net_rendezvous_service_register."""
    if not isinstance(svc, RelayService) or not svc.name:
        return False
    if any(s.name == svc.name for s in _services) or len(_services) >= SERVICES_MAX:
        return False
    _services.append(svc)
    return True


def services() -> tuple:
    return tuple(_services)


def clients(proc, own_only: bool) -> list:
    """``[(endpoint, client), ...]``: every connected relay client, or only
    those at our own relays when ``own_only``. Mirrors C's
    net_rendezvous_clients."""
    held = getattr(proc, '_relay_clients', {}) or {}
    if own_only:
        return [(ep, held[ep]) for ep in _relay.own_relays()
                if ep in held and held[ep].connected]
    return [(ep, c) for ep, c in list(held.items()) if c.connected]


def _register(proc, proc_name: str) -> None:
    """On identity, the roster app verbs (:mod:`.roster`). On the network
    process, the local verbs identity sends it, each refused from the wire by
    its handler. (The directory and area-hub verbs are first contact's,
    first_contact/fc_net.py.)"""
    if proc_name == CfgIds.identity:
        from . import roster
        roster.register(proc)
        return
    if proc_name != 'network':
        return
    _net.init_state(proc)
    for verb, fn in ((Network.relay_route, _net.handle_relay_route),
                     (Network.reach_publish, _net.handle_reach_publish)):
        proc.protocol.register_handler(verb, functools.partial(fn, proc))


def _on_start(proc, queues) -> None:
    """Serve as a relay and/or register with our own relays."""
    _net.init_state(proc)
    proc._relay_queues = queues
    _net._start_relays(proc)


def _periodic(proc, queues) -> None:
    """Keep the registrations alive, fail over what relays refused, and hand
    identity what the relay readers queued."""
    _net._maintain_relays(proc)
    _net._drain_relay_unreachable(proc)
    _net._retry_refused_relayed(proc)
    _net._drain_relay_records(proc, queues)


def _drain_inbound(proc, queues, budget: int) -> int:
    return _net._drain_relayed(proc, queues, budget)


def _reaches(proc, peer_uuid) -> bool:
    """A peer behind a relay: identity gave it a route."""
    return bool(getattr(proc, '_relay_routes', {}).get(str(peer_uuid).lower()))


def _unicast(proc, peer_uuid, frame) -> None:
    _net._relay_send(proc, peer_uuid, frame)


def _on_exclusion(proc, uuid_str: str, excluded: bool) -> None:
    """Act on a new exclusion at once: evict the client from the relay we
    serve, and hang up on a relay we now distrust."""
    if excluded:
        _net._drop_distrusted_relays(proc)


def enabled() -> bool:
    return True


EXTENSION = Extension(name='rendezvous', enabled=enabled,
                      register_handlers=_register,
                      app_verbs=((APP_ROSTER_INSTALL, CfgIds.identity),
                                 (APP_ROSTER_REMOVE, CfgIds.identity)),
                      network=NetworkHooks(on_start=_on_start,
                                           periodic=_periodic,
                                           drain_inbound=_drain_inbound,
                                           reaches=_reaches,
                                           unicast=_unicast,
                                           on_exclusion=_on_exclusion))
