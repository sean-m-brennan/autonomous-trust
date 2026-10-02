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
"""The hybrid transport: one node on several transports at once. The Python
twin of C's net_transport_hybrid.c (``hybrid_net``).

Typical shapes (at-over-dtn.md §4.3): a gateway with UDP on its LAN and a DTN
leg to a cluster behind a Bundle Protocol agent; a node on two subnets; TCP to
wired peers and UDP to the rest.

Configured by ``hybrid_net.cfg.json`` in the node's config directory, the file
and shape C reads::

    {"typename": "hybrid_net",
     "inners": [{"kind": "udp_net_4", "match_cidr": "10.0.0.0/24",
                 "net_cfg": {"ip4_cidr": "10.0.0.7/24", ...}},
                {"kind": "dtn_bp", "match_eid": true, "is_default": true}],
     "is_gateway": false,
     "group_routes": [{"group_uuid": "...", "leg_index": 1}]}

Selected by class path:
``AT_TRANSPORT=autonomous_trust.core.network.hybrid.HybridNetworkProcess``.

A leg's ``kind`` is C's transport name. The core supplies ``udp_net_4`` and
``tcp_net_4``; an extension supplies the rest by name (DTN's ``dtn_bp``,
:func:`~..extensions.transport_class`). ``udp_net_6`` and ``tcp_net_6`` exist
only in C.

A unicast goes to the first leg whose matcher takes the target
(:func:`hybrid_route`, C's rule exactly: an EID leg for ``dtn:``/``ipn:``, a
CIDR leg for an address inside it, else the first default leg). A broadcast
goes out on every leg, and succeeds if any leg takes it.

Each leg is a transport of its own kind, sharing this process's view of peers
and group, its inbound queues, statistics and exclusions, so its receivers
deliver straight into the queues this process drains.

Differences from C, recorded: a leg without ``net_cfg`` uses the node's own
network configuration, where C opens it on a zeroed one; the leg a frame
arrived on is not kept, because nothing in Python consumes it (C keeps it for
gateway group forwarding, which Python does not have); and ``is_gateway`` and
``group_routes`` are read and checked but drive nothing here, for the same
reason.
"""
import importlib
import re
import socket
import threading
from dataclasses import dataclass, field
from uuid import UUID

from .netprocess import NetworkProcess, NetworkProtocol, TransmissionError
from ..extensions import transport_class
from ..system import CfgIds

#: The config section (file stem), as C's DECLARE_CONFIGURATION names it.
CFG_NAME = 'hybrid_net'
HYBRID_MAX_INNERS = 4
HYBRID_MAX_GROUP_ROUTES = 8
#: The longest CIDR each matcher reads: C copies into CIDR4_LEN / CIDR6_LEN
#: buffers, so a longer string is cut there.
CIDR4_LEN = 19
CIDR6_LEN = 50

_pkg = __name__.rsplit('.', 1)[0]
CORE_KINDS = {
    'udp_net_4': _pkg + '.udp.UDPNetworkProcess',
    'tcp_net_4': _pkg + '.tcp.TCPNetworkProcess',
}
C_ONLY_KINDS = ('udp_net_6', 'tcp_net_6')

#: What a leg shares with the hybrid process that owns it.
_SHARED = ('protocol', 'peer_messages', 'group_messages', 'unknown_messages', 'pests',
           'statistics', '_rejected_addresses', '_excluded_uuids', '_excluded_keys',
           '_crypto_error_counts')


# ---------- matching ----------

def _atoi(text: str) -> int:
    """C's atoi: leading space, a sign, then digits; 0 when there are none."""
    m = re.match(r'\s*([+-]?\d+)', text)
    return int(m.group(1)) if m else 0


def _split(cidr: str, limit: int, sep_from_right: bool):
    cidr = cidr[:limit]
    idx = cidr.rfind('/') if sep_from_right else cidr.find('/')
    if idx < 0:
        return None, None
    return cidr[:idx], _atoi(cidr[idx + 1:])


def addr_in_cidr4(ip: str, cidr: str) -> bool:
    if ip is None or cidr is None:
        return False
    net, prefix = _split(cidr, CIDR4_LEN, False)
    if net is None or not 0 <= prefix <= 32:
        return False
    try:
        net_b = socket.inet_pton(socket.AF_INET, net)
        ip_b = socket.inet_pton(socket.AF_INET, ip)
    except (OSError, ValueError):
        return False
    mask = 0 if prefix == 0 else (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return int.from_bytes(net_b, 'big') & mask == int.from_bytes(ip_b, 'big') & mask


def addr_in_cidr6(ip: str, cidr: str) -> bool:
    if ip is None or cidr is None:
        return False
    net, prefix = _split(cidr, CIDR6_LEN, True)
    if net is None or not 0 <= prefix <= 128:
        return False
    try:
        net_b = socket.inet_pton(socket.AF_INET6, net)
        ip_b = socket.inet_pton(socket.AF_INET6, ip)
    except (OSError, ValueError):
        return False
    full, rem = divmod(prefix, 8)
    if net_b[:full] != ip_b[:full]:
        return False
    if rem == 0:
        return True
    mask = (0xFF << (8 - rem)) & 0xFF
    return net_b[full] & mask == ip_b[full] & mask


def addr_in_cidr(ip: str, cidr: str) -> bool:
    """The CIDR's family picks the matcher, so a v4 target never matches a v6
    CIDR or the reverse."""
    if cidr is None:
        return False
    return addr_in_cidr6(ip, cidr) if ':' in cidr else addr_in_cidr4(ip, cidr)


def is_eid_literal(target) -> bool:
    return isinstance(target, str) and target.startswith(('dtn:', 'ipn:'))


# ---------- configuration ----------

@dataclass
class HybridInner:
    kind: str
    match_cidr: str = ''
    match_eid: bool = False
    is_default: bool = False
    #: The leg's network configuration as C serializes it (a dict), a
    #: Network, or None for the node's own.
    net_cfg: object = None


@dataclass
class HybridConfig:
    inners: list = field(default_factory=list)
    is_gateway: bool = False
    #: ``[(group uuid string, leg index), ...]``
    group_routes: list = field(default_factory=list)


def hybrid_config_from_json(obj: dict) -> HybridConfig:
    """Read C's ``hybrid_net`` JSON, refusing what C's hybrid_from_json
    refuses (ValueError)."""
    if not isinstance(obj, dict):
        raise ValueError('hybrid_net: not an object')
    arr = obj.get('inners')
    if not isinstance(arr, list) or not 0 < len(arr) <= HYBRID_MAX_INNERS:
        raise ValueError('hybrid_net: "inners" must hold 1 to %d legs' % HYBRID_MAX_INNERS)
    cfg = HybridConfig()
    for idx, jin in enumerate(arr):
        if not isinstance(jin, dict) or not isinstance(jin.get('kind'), str):
            raise ValueError('hybrid_net: inners[%d] needs a string "kind"' % idx)
        cidr = jin.get('match_cidr')
        net = jin.get('net_cfg')
        cfg.inners.append(HybridInner(
            kind=jin['kind'],
            match_cidr=cidr if isinstance(cidr, str) else '',
            match_eid=jin.get('match_eid') is True,
            is_default=jin.get('is_default') is True,
            net_cfg=net if net is not None and not isinstance(net, (str, int, float, list)) else None))
    cfg.is_gateway = obj.get('is_gateway') is True
    routes = obj.get('group_routes')
    if isinstance(routes, list):
        if len(routes) > HYBRID_MAX_GROUP_ROUTES:
            raise ValueError('hybrid_net: more than %d group routes' % HYBRID_MAX_GROUP_ROUTES)
        for idx, jr in enumerate(routes):
            if not isinstance(jr, dict):
                raise ValueError('hybrid_net: group_routes[%d] is not an object' % idx)
            try:
                group = str(UUID(jr.get('group_uuid')))
            except (TypeError, ValueError, AttributeError) as err:
                raise ValueError('hybrid_net: group_routes[%d] has no valid group_uuid' % idx) from err
            leg = jr.get('leg_index')
            if isinstance(leg, bool) or not isinstance(leg, int) or not 0 <= leg < len(cfg.inners):
                raise ValueError('hybrid_net: group_routes[%d].leg_index out of range' % idx)
            cfg.group_routes.append((group, leg))
    return cfg


def hybrid_route(cfg: HybridConfig, target) -> int:
    """The index of the leg a unicast to ``target`` takes, or -1 (C's
    hybrid_route)."""
    if cfg is None or target is None:
        return -1
    default_idx = -1
    for idx, inner in enumerate(cfg.inners):
        if inner.match_eid and is_eid_literal(target):
            return idx
        if inner.match_cidr and addr_in_cidr(target, inner.match_cidr):
            return idx
        if inner.is_default and default_idx < 0:
            default_idx = idx
    return default_idx


def group_route_lookup(cfg: HybridConfig, group_uuid) -> int | None:
    """The leg ``group_uuid`` is routed to, or None (C's
    hybrid_group_route_lookup)."""
    if cfg is None or group_uuid is None:
        return None
    try:
        want = str(UUID(str(group_uuid)))
    except ValueError:
        return None
    for group, leg in cfg.group_routes:
        if group == want:
            return leg
    return None


def leg_class(kind: str):
    """The transport class for a leg ``kind``; ValueError for one this node
    cannot open."""
    if kind == CFG_NAME:
        raise ValueError('hybrid_net: a leg cannot itself be hybrid')
    if kind in C_ONLY_KINDS:
        raise ValueError('hybrid_net: leg kind %s exists only in the C runtime' % kind)
    path = CORE_KINDS.get(kind) or transport_class(kind)
    if path is None:
        raise ValueError('hybrid_net: leg kind %r is not registered (is its extension '
                         'installed?)' % kind)
    module, _, name = path.rpartition('.')
    return getattr(importlib.import_module(module), name)


def _leg_net_cfg(net, fallback):
    """A leg's Network configuration from C's serialized form, or ``fallback``."""
    if net is None:
        return fallback
    if not isinstance(net, dict):
        return net
    from .network import Network
    return Network(net.get('ip4_cidr') or None, net.get('ip6_cidr') or None,
                   net.get('mac_addr') or None,
                   net.get('mcast4_addr') or Network.multicast_v4_address,
                   net.get('mcast6_addr') or Network.multicast_v6_address,
                   net.get('port') or None)


# ---------- the transport ----------

class HybridNetworkProcess(NetworkProcess):
    # As C: identity-address selection treats the hybrid as IPv4, the leg that
    # carries node-local traffic.
    net_proto = NetworkProtocol.IPV4
    kind = CFG_NAME

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, **kwargs):
        super().__init__(configurations, subsystems, log_q, acceptance_func, **kwargs)
        raw = configurations.get(CFG_NAME)
        if raw is None:
            raise ValueError('hybrid_net transport selected, but there is no %s.cfg.json'
                             % CFG_NAME)
        self.hybrid_cfg = raw if isinstance(raw, HybridConfig) else hybrid_config_from_json(raw)
        self.legs = self._open_legs(configurations, subsystems, log_q, acceptance_func, **kwargs)
        self.logger.info('Hybrid: %d inner transport(s)', len(self.legs))
        for idx, inner in enumerate(self.hybrid_cfg.inners):
            self.logger.info('Hybrid:   [%d] %s (match: cidr=%s eid=%d default=%d)', idx,
                             inner.kind, inner.match_cidr or '(none)', int(inner.match_eid),
                             int(inner.is_default))

    def _open_legs(self, configurations, subsystems, log_q, acceptance_func, **kwargs):
        """One transport per configured leg, each on its own network
        configuration and sharing this process's state (:data:`_SHARED`)."""
        legs = []
        for inner in self.hybrid_cfg.inners:
            cls = leg_class(inner.kind)
            leg_cfgs = dict(configurations)
            leg_cfgs[CfgIds.network] = _leg_net_cfg(inner.net_cfg, self.net_cfg)
            leg = cls(leg_cfgs, subsystems, log_q, acceptance_func, **kwargs)
            for name in _SHARED:
                setattr(leg, name, getattr(self, name))
            legs.append(leg)
        return legs

    @property
    def is_gateway(self):
        return self.hybrid_cfg.is_gateway

    # --- lifecycle: each leg's, in the worker ----------------------------

    def rebind_socket_timeouts(self):
        for leg in self.legs:
            leg.rebind_socket_timeouts()

    def _init_transport(self):
        for leg in self.legs:
            leg._init_transport()  # noqa: SLF001

    def start_receivers(self, queues):
        """Each leg's receivers, and its stranger receiver, delivering into
        the queues this process drains."""
        for leg in self.legs:
            leg.start_receivers(queues)
            threading.Thread(target=leg.unknown_receiver, daemon=True).start()

    def unknown_receiver(self):
        """Nothing: every leg runs its own (start_receivers)."""
        return

    def reap_idle_conns(self):
        for leg in self.legs:
            leg.reap_idle_conns()

    def close_connections(self):
        for leg in self.legs:
            leg.stop = True
        for leg in self.legs:
            leg.close_connections()

    def close_listeners(self):
        for leg in self.legs:
            leg.close_listeners()

    def link_class_ms(self, target=None):
        """The latency class of the leg a unicast to ``target`` takes."""
        idx = hybrid_route(self.hybrid_cfg, target)
        if idx < 0:
            return -1
        fn = getattr(self.legs[idx], 'link_class_ms', None)
        return fn(target) if callable(fn) else -1

    # --- send -----------------------------------------------------------

    def _leg_for(self, target):
        idx = hybrid_route(self.hybrid_cfg, target)
        if idx < 0:
            raise TransmissionError('Hybrid: no inner matches target=%s (no default configured)'
                                    % target)
        return self.legs[idx]

    def send_peer(self, msg, host):
        self._leg_for(host).send_peer(msg, host)

    def send_group(self, msg, host):
        self._leg_for(host).send_group(msg, host)

    def send_any(self, msg):
        """On every leg, so a gateway's discovery reaches both sides; fails
        only when every leg fails."""
        errors = []
        for idx, leg in enumerate(self.legs):
            try:
                leg.send_any(msg)
            except (TransmissionError, OSError) as err:
                errors.append('[%d] %s' % (idx, err))
        if errors and len(errors) == len(self.legs):
            raise TransmissionError('Hybrid: broadcast failed on every leg: ' + '; '.join(errors))

    def send_on_leg(self, leg_index, msg):
        """A broadcast on one leg only (C's send_on_leg)."""
        if not 0 <= leg_index < len(self.legs):
            raise TransmissionError('Hybrid: no leg %d' % leg_index)
        self.legs[leg_index].send_any(msg)

