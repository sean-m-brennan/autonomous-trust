# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import concurrent.futures
import errno
import json
import uuid as _uuid_mod
import socket
import threading
import time
import traceback
from collections import deque
from datetime import datetime
from queue import Empty, Full
from enum import Enum

import nacl

from ..protocol import Protocol
from ..identity import Identity
from ..identity.protocol import IdentityProtocol, UNENCRYPTED_VERBS, BOOTSTRAP_VERBS
from ..processes import Process, ProcMeta
from ..extensions import load_extensions, run_post_fork
from .. import _probes
from ..identity import Group
from ..system import (CfgIds, PortSource, comm_port, net_cadence, resolve_comm_port,
                      default_annoy_limit, default_mystery_max_age_s, default_recv_poll_ms,
                      resolve_annoy_limit, resolve_mystery_max_age_s, resolve_recv_poll_ms)
from ..config import NetWireFormat
from .network import Network
from .message import Message, WireFormatMismatch
from .ping_at import PingATServer, ping_at
from . import relay as _relay
from . import registry as _registry


class NetworkProtocol(Enum):
    IPV4 = 4
    IPV6 = 6
    MAC = 2
    NONE = 0


class TransmissionError(RuntimeError):
    pass


class _NetProcMeta(ProcMeta):  # so that subclasses inherit meta args
    def __init__(cls, name, bases, namespace, cadence=net_cadence, port=comm_port):
        super().__init__(name, bases, namespace,
                         proc_name=CfgIds.network, description='Network I/O')
        cls.cadence = cadence
        cls.default_port = port


class NetStat(object):
    size = 100

    def __init__(self):
        self.times = deque(maxlen=self.size)
        self.send = deque(maxlen=self.size)
        self.send_total = 0
        self.recv = deque(maxlen=self.size)
        self.recv_total = 0
        self.err_out = 0
        self.err_in = 0

    def sent(self, num_bytes, errors=0):
        self.times.append(datetime.now())
        self.send.append(num_bytes)
        self.send_total += num_bytes
        self.err_out += errors

    def rcvd(self, num_bytes, errors=0):
        self.times.append(datetime.now())
        self.recv.append(num_bytes)
        self.recv_total += num_bytes
        self.err_in += errors


class NetworkProcess(Process, metaclass=_NetProcMeta):
    """
    Handle requests to send Messages over the network and route incoming Messages to the right process
    Abstract class - subclasses must implement send_* and recv_* methods
    """
    enc = Network.encoding
    net_proto = NetworkProtocol.NONE
    unknown_peer = '0'

    # The DEFAULTS layer for the three network tunables, not the tunables
    # themselves. __init__ overwrites each with the env-resolved value, so an
    # AT_NET_* override reaches every consumer; these class attributes remain so
    # a subclass or a test can still pin one directly (several do), and so the
    # names keep working for anything that reads them off the class.
    #
    # C carries the same three knobs with the same names, bounds and defaults
    # (network.h, resolved in net_proc.c). Before 2026-08-10 these were Python
    # class attributes with no C counterpart, so a deployment could tune one
    # runtime and not the other (doc/architecture/networking.md).
    annoy_limit = default_annoy_limit
    socket_timeout = default_recv_poll_ms / 1000.0
    # Wall-clock seconds, replacing the old mystery_max_retries count. The
    # count approximated this bound (60 retries x ~0.5s) but drifted with load,
    # because the loop's cadence is not the loop's period. C always bounded by
    # age; both sides now agree on the quantity as well as the value.
    mystery_max_age_s = default_mystery_max_age_s

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, **kwargs):
        super().__init__(configurations, subsystems, log_q, **kwargs)
        self.net_cfg = configurations[CfgIds.network]
        # One resolution, same order as C's net_port_resolve: a usable config
        # port wins, else AT_COMM_PORT, else the compile-time default. Going
        # through the resolver (rather than `port or default_port`) is what
        # range-checks a bad configured value and logs which layer supplied the
        # result, so an operator can tell an ignored override from an applied one.
        self.port, self.port_source = resolve_comm_port(self.net_cfg.port or 0, self.logger)
        if self.port_source == PortSource.default:
            # The metaclass default is the same defaults layer; keep honoring an
            # explicit subclass override of `port=` in that case only.
            self.port = self.default_port  # noqa
        self.logger.info('network base port %d from %s (group %d)', self.port, self.port_source, self.port + 1)

        # The three tunables, same two-layer resolution and refusal rules as
        # C's net_knob_resolve. Assigned as INSTANCE attributes over the class
        # defaults, so a subclass or test that pins one after construction
        # still wins -- the env layer sits between the compile-time default and
        # an explicit override, exactly where the port's does.
        self.annoy_limit, annoy_src = resolve_annoy_limit(self.logger)
        recv_poll_ms, poll_src = resolve_recv_poll_ms(self.logger)
        self.socket_timeout = recv_poll_ms / 1000.0
        self.mystery_max_age_s, myst_src = resolve_mystery_max_age_s(self.logger)
        self.logger.info(
            'network annoy limit %d from %s, recv poll %d ms from %s, '
            'mystery max age %d s from %s', self.annoy_limit, annoy_src, recv_poll_ms, poll_src, self.mystery_max_age_s, myst_src)

        self.diplomat = True
        self.ping_at_server = None
        self.myself = configurations[CfgIds.identity]
        self.peer_messages = deque()
        self.encrypted_messages = deque()
        self.group_messages = deque()
        self.unknown_messages = deque()
        self.acceptance = acceptance_func
        self.pests = {}
        self.protocol = Protocol(self.name, self.logger, configurations)
        # Reputation cut-off enforcement: ReputationProcess feeds
        # exclude/readmit control messages here as peers cross the
        # communication cut-off. See handle_exclude / handle_readmit and
        # the inbound-drop / outbound-forward gates below.
        self.protocol.register_handler(Network.exclude, self.handle_exclude)
        self.protocol.register_handler(Network.readmit, self.handle_readmit)
        self.protocol.register_handler(Network.relay_route, self.handle_relay_route)
        self.protocol.register_handler(Network.reach_publish, self.handle_reach_publish)
        self.protocol.register_handler(Network.dir_publish, self.handle_dir_publish)
        self.protocol.register_handler(Network.dir_withdraw, self.handle_dir_withdraw)
        self.protocol.register_handler(Network.dir_lookup, self.handle_dir_lookup)
        # Rendezvous relays (network/relay.py). Built in process(), in the
        # child: sockets and threads do not survive the fork.
        self.relay_messages = deque()   # (frame, from_uuid, endpoint)
        self.relay_unreachable = deque()  # (endpoint, to_uuid) a relay refused
        # peer uuid (str) -> [(host, port), ...]: its relays in preference
        # order, the ACTIVE one first. One relay carries a peer's traffic at a
        # time; a failure rotates the next to the front.
        self._relay_routes = {}
        # peer uuid (str) -> (frame, relays tried): the last frame sent to the
        # peer by relay, kept to resend it through the next relay when the
        # active one says it cannot reach the peer (a relay acknowledges
        # nothing, so the refusal is the only signal, and it comes later).
        self._relay_last = {}
        # peer uuid (str) -> (monotonic due time, rounds so far): a frame every
        # relay refused, to walk the route again -- the peer may register a few
        # seconds later (a relay restarting, or it minted its link before its
        # own registration finished).
        self._relay_retry = {}
        self._relay_clients = {}        # (host, port) -> RelayClient
        self._relay_connecting = set()  # endpoints a background connect is on
        self._relay_last_try = {}       # endpoint -> monotonic time of last try
        self._relay_live = {}           # peer uuid -> relay its traffic last came by
        # endpoint -> (uuid, fp): which relay a link or our config says answers
        # there. A client for that endpoint refuses anything else.
        self._relay_pins = {}
        # Who reputation has cut off, by uuid and by signing key (hex), so a
        # distrusted relay or client gains nothing by claiming a new uuid.
        self._excluded_uuids = set()
        self._excluded_keys = set()
        self._relay_queues = None       # set in process(), for relay_identity
        self._own_record = None         # our reachability record (wire dict)
        self.relay_records = deque()    # (record id, wire) answers to lookups
        self._reach_asked = {}          # peer uuid -> monotonic time of last lookup
        self._relay_server = None
        # The directory (network/registry.py): our own entries (handle ->
        # wire), refiled at every registration with our relays; registry
        # answers as they arrive ((endpoint, frame)); and lookups in flight
        # (handle -> _DirLookup), answered to identity once, when the first
        # relay finds the handle or every relay asked has answered.
        self._own_entries = {}
        self.relay_dir = deque()
        self._dir_lookups = {}
        load_extensions(self, self.name)
        self.stop = False
        self.statistics = {}
        self._rejected_addresses: set[str] = set()
        self._crypto_error_counts: dict[str, int] = {}
        # Per-address count of frames dropped for arriving in a wire format
        # this context does not speak. Rate-limits the log the same way
        # _crypto_error_counts does; the probe counter is unconditional.
        self._foreign_format_counts: dict[str, int] = {}
        # Per-(kind, address) count of frames refused by the gateway-boundary
        # gate (_boundary_refuse). Rate-limits the log exactly as
        # _foreign_format_counts does; the probe counter is unconditional.
        self._boundary_counts: dict[str, int] = {}
        # Partition-recovery signal cooldown: per-source-address timestamp of the last
        # signal we forwarded to IdentityProcess. Bounded at one signal per address per
        # 5 seconds so a chatty rejected-group peer can't flood the identity queue. See
        # doc/architecture/partition-recovery.md §5.1.
        self._partition_signal_lru: dict[str, datetime] = {}
        # Lazily created in process(). ThreadPoolExecutor can't be
        # pickled, so creating it here would break the multiprocessing
        # spawn handoff. See `_ensure_ping_at_pool`.
        self._ping_at_pool: concurrent.futures.ThreadPoolExecutor | None = None

    @property
    def my_ip(self):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            return ip_address
        except Exception:
            return '127.0.0.1'
        finally:
            if s:
                s.close()

    @property
    def peers(self):
        return self.protocol.peers

    @property
    def group(self):
        return self.protocol.group

    @property
    def child_groups(self):
        # dict[group-uuid-str -> Group] for cohorts this node gateways.
        # Empty on leaf nodes, so the group-receive fast path below is
        # unchanged for them. See doc/architecture/gateway-reputation-tree.md.
        return getattr(self.protocol, 'child_groups', {}) or {}

    def _group_for_sender(self, from_addr):
        """Return the group (primary or child) whose address map contains
        ``from_addr``, or None. Checks the primary group first so a leaf
        node (no child groups) takes exactly the historical path; only a
        gateway falls through to its child groups, letting it decrypt a
        frame from a cohort below it with that cohort's own key."""
        grp = self.group
        if grp is not None and from_addr in grp.addresses:
            return grp
        # Snapshot the child-group values before iterating: child_groups
        # (self.protocol.child_groups) is mutated by the message-handling
        # thread as groups form/merge while this runs on the receive path, so
        # iterating it live raised "dictionary changed size during iteration"
        # (same class of bug as net_stats above). We only read each child's
        # addresses, so a values snapshot is sufficient.
        for child in list(self.child_groups.values()):
            try:
                if from_addr in child.addresses:
                    return child
            except Exception:
                continue
        return None

    # ---- The gateway boundary -------------------------------------------
    #
    # Two invariants, both normative
    # (doc/architecture/network-wire-format.md, "The gateway boundary"):
    #
    #   G. A GROUP STOPS AT THE GATEWAY. A gateway is a full MEMBER of each
    #      cohort it bridges; no group spans it. So no address other than the
    #      gateway's own may appear in two of the groups it holds, and a
    #      group-addressed frame never leaves the address map of the group that
    #      addressed it.
    #   B. BOOTSTRAP DOES NOT CROSS THE GATEWAY. The pre-admission handshake
    #      (BOOTSTRAP_VERBS) is domain-local. This is what ENFORCES G: the only
    #      way a group comes to span a gateway is for a node on one side to be
    #      admitted by a cohort on the other, and those three verbs are the only
    #      ones that move membership.
    #
    # Together these make wire-format detection unnecessary rather than merely
    # risky: every frame is either from a member of a group we hold (so the
    # format is a lookup) or local bootstrap (so the format is JSON by rule).
    # Relaxing either one puts that back on the table -- R+D.md Sec 2.5.

    def _held_groups(self):
        """Every group whose address map this node holds: the primary plus any
        child cohort it gateways. Empty-to-one-element on a leaf node."""
        grps = []
        if self.group is not None:
            grps.append(self.group)
        grps.extend(list(self.child_groups.values()))
        return grps

    def _groups_containing(self, addr):
        """The held groups listing *addr*, excluding our own address.

        A gateway is by construction a member of BOTH its primary group and
        every child cohort it bridges, so its own address is in every map and
        is never a violation. Any OTHER address in two maps means those two
        groups have merged across this gateway -- invariant G above.
        """
        try:
            if addr == self.myself.address:
                return []
        except AttributeError:
            pass
        found = []
        for grp in self._held_groups():
            try:
                if addr in grp.addresses:
                    found.append(grp)
            except Exception:
                continue
        return found

    def _boundary_refuse(self, kind, addr, detail):
        """Count, rate-limited-log, and report a gateway-boundary refusal.

        Always returns True, so call sites read ``if ...: continue`` /
        ``return``. Logged at ERROR rather than WARNING for the same reason the
        foreign-format drop is: a boundary violation presents downstream as a
        peer having silently gone quiet, and this line is the only thing that
        says why.
        """
        _probes.counter('net.boundary', 'drop', kind)
        key = '%s|%s' % (kind, addr)
        n = self._boundary_counts.get(key, 0) + 1
        self._boundary_counts[key] = n
        if n == 1 or n % 10 == 0:
            self.logger.error(
                'Gateway boundary: refusing %s involving %s -- %s (count: %d)',
                kind, addr, detail, n)
        return True

    def _crosses_gateway(self, addr):
        """True when *addr* sits on the far side of a gateway boundary from our
        primary group: a member of a child cohort we bridge but NOT of our own
        group. On a leaf node (no child groups) this is always False, so the
        historical path is untouched."""
        if not self.child_groups:
            return False
        holding = self._groups_containing(addr)
        if not holding:
            return False
        primary = self.group
        return all(grp is not primary for grp in holding)

    @staticmethod
    def _wire_format_for_group(grp):
        """*grp*'s envelope format, or JSON when there is no group
        (doc/architecture/network-wire-format.md). A node with no group yet is a
        node that has not been admitted anywhere, and all of its traffic is
        bootstrap traffic."""
        return getattr(grp, 'wire_format', None) or NetWireFormat.json

    def _wire_format_for_addr(self, addr):
        """The envelope format traffic with *addr* rides in
        (doc/architecture/network-wire-format.md).

        The format belongs to the GROUP, so this is a group lookup: a peer we
        can place in our primary group or in a child group we gateway speaks
        that group's format. Anything we cannot place -- a stranger, a
        pre-admission newcomer, a peer in a group we do not hold -- is JSON,
        which is the format every AT node can read and therefore the only safe
        answer when we have no group to consult. That is also why bootstrap is
        JSON unconditionally: discovery happens before there is a group to ask.

        Detecting the sender's actual format instead is deliberately not done;
        see doc/architecture/network-wire-format.md.
        """
        grp = self._group_for_sender(addr)
        # Delegate rather than reading grp.wire_format directly: the rule is the
        # group's (Group.wire_format_for_address, mirrored by C's
        # group_wire_format_for_address), and one copy is what keeps the
        # production selection and the conformance-pinned one from drifting.
        return (grp.wire_format_for_address(addr) if grp is not None
                else NetWireFormat.json)

    def track_send_stats(self, uuid, num_bytes):
        if uuid not in self.statistics:
            self.statistics[uuid] = NetStat()
        self.statistics[uuid].sent(num_bytes)

    def track_send_error(self, uuid):
        if uuid not in self.statistics:
            self.statistics[uuid] = NetStat()
        self.statistics[uuid].sent(0, 1)

    def track_recv_stats(self, uuid, num_bytes, errors=0):
        if uuid not in self.statistics:
            self.statistics[uuid] = NetStat()
        self.statistics[uuid].rcvd(num_bytes, errors)

    def track_recv_error(self):
        # Mirror track_send_error: the unknown_peer key may not exist
        # yet on the very first inbound error, and a KeyError here
        # crashes the receiver thread for the rest of the run.
        if self.unknown_peer not in self.statistics:
            self.statistics[self.unknown_peer] = NetStat()
        self.statistics[self.unknown_peer].rcvd(0, 1)

    @property
    def net_stats(self):
        cumulative = {}
        # Snapshot the keys: track_send/recv_* run in the sender/receiver
        # threads and add new peers to self.statistics, so iterating it live
        # raised "dictionary changed size during iteration". Keys are only ever
        # added (never deleted), so a key snapshot is sufficient. Likewise
        # snapshot each NetStat's deques before summing -- a deque mutated by a
        # concurrent send/rcvd mid-iteration raises in the same way.
        for uuid in list(self.statistics):
            stat = self.statistics.get(uuid)
            if stat is None:
                continue
            times = list(stat.times)
            if len(times) < 2:
                continue  # need two samples to span an interval
            elapsed = (times[-1] - times[0]).total_seconds()
            if elapsed <= 0:
                continue  # same-instant samples -> no meaningful rate
            up = sum(list(stat.send)) / elapsed
            down = sum(list(stat.recv)) / elapsed
            cumulative[uuid] = (up, down, stat.send_total, stat.recv_total,
                                stat.err_out, stat.err_in)
        return cumulative

    def send_peer(self, msg, whom):
        raise NotImplementedError

    def send_group(self, msg, whom):
        raise NotImplementedError

    def send_any(self, msg):
        raise NotImplementedError

    def recv_peer(self):
        raise NotImplementedError

    def recv_group(self):
        raise NotImplementedError

    def recv_any(self):
        raise NotImplementedError

    # --- Transport lifecycle hooks -------------------------------------
    # No-ops here; a transport that keeps long-lived connections (the TCP
    # pool) overrides them. They run in the worker subprocess from
    # process(), which matters because threading primitives can't survive
    # the multiprocessing spawn pickle (see _ensure_ping_at_pool).

    def _init_transport(self):
        """Per-worker transport setup that can't be pickled across the
        spawn handoff (e.g. locks). Called once before receiver threads
        start."""
        pass

    def start_receivers(self, queues):
        """Start the point-to-point and group receive threads. The default
        is one accept-read-one thread per channel; a transport with
        persistent readers overrides this."""
        threading.Thread(target=self.peer_receiver, daemon=True).start()
        threading.Thread(target=self.group_receiver, daemon=True).start()

    def reap_idle_conns(self):
        """Close connections idle past their TTL. Called each main-loop
        iteration; rate-limits itself internally."""
        pass

    def close_connections(self):
        """Close any live transport connections at shutdown."""
        pass

    def close_listeners(self):
        """Close the bound receive sockets (peer, group, broadcast/multicast)
        so their ports are released deterministically at shutdown rather than
        whenever the process object is garbage-collected. Safe to call more
        than once; a missing or already-closed socket is ignored."""
        for name in ('recv_ptp_sock', 'recv_grp_sock', 'recv_cast_sock'):
            sock = getattr(self, name, None)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def accept_peer_message(self, address):
        """
        Accept/reject messages based on sender's address
        :param address: Incoming sender
        :return: bool
        """
        if self.reject_message(address):
            return False
        if self.acceptance is not None:
            return self.acceptance(address)
        if self.peers.find_by_address(address) is None:
            return False
        return True

    def accept_group_message(self, address):
        """
        Accept/reject group messages based on sender's address
        :param address: Incoming sender
        :return: bool
        """
        if address not in self.group.addresses:
            return False
        return self.accept_peer_message(address)

    @staticmethod
    def _norm_addr(address):
        """Canonicalize an address to the form used as the peer-listing
        key (strip any '/suffix'), matching Peers.find_by_address so an
        exclusion keyed on a peer's stored address matches the raw
        from_addr seen at recv."""
        if address is None:
            return None
        address = str(address)
        if '/' in address:
            address = address.split('/')[0]
        return address

    def reject_message(self, address):
        """Check if an address is excluded (reputation cut-off) or
        otherwise blacklisted."""
        return self._norm_addr(address) in self._rejected_addresses

    def blacklist_address(self, address):
        """Add an address to the rejection list."""
        self._rejected_addresses.add(self._norm_addr(address))

    @staticmethod
    def _exclusion_spec(message):
        """``(address, uuid)`` from an exclude/readmit: ``{address, uuid}``,
        or a bare address (the older form)."""
        obj = getattr(message, 'obj', None)
        if isinstance(obj, str) and obj.lstrip().startswith('{'):
            try:
                obj = json.loads(obj)
            except ValueError:
                pass
        if isinstance(obj, dict):
            uuid = obj.get('uuid')
            return obj.get('address') or None, str(uuid).lower() if uuid else None
        return obj, None

    def _peer_key(self, uuid):
        """The signing key (hex) this node holds for peer ``uuid``, or None."""
        peer = self.peers.find_by_uuid(uuid) if self.peers is not None else None
        if peer is None:
            return None
        try:
            return _relay._signing_hex(peer).lower()
        except Exception:
            return None

    def _is_distrusted(self, uuid, pubkey_hex):
        """The relay gate, both directions: reputation cut ``uuid`` off, or
        the proven key belongs to someone it cut off, or ``uuid`` is a peer we
        know under a DIFFERENT key (an impostor). Unknown and neutral pass."""
        uuid = str(uuid).lower()
        key = str(pubkey_hex or '').lower()
        if uuid in self._excluded_uuids or (key and key in self._excluded_keys):
            return True
        known = self._peer_key(uuid)
        return known is not None and key != '' and known != key

    def handle_exclude(self, queues, message):
        """Exclude a peer (reputation cut-off): its address's inbound frames
        are dropped and it is filtered out of outbound targets; by uuid and
        key it is refused as a relay client and as a relay. Fed by
        ReputationProcess._publish_exclusion. Local IPC only."""
        if getattr(message, 'from_whom', None) is not None and \
                str(getattr(message.from_whom, 'uuid', '')) != str(getattr(self.myself, 'uuid', '')):
            self.logger.warning('Refusing exclude from the wire')
            return True
        address, uuid = self._exclusion_spec(message)
        addr = self._norm_addr(address) if address else None
        if addr:
            self._rejected_addresses.add(addr)
            _probes.counter('net.exclude', 'add')
            self.logger.info('Reputation cut-off: excluding %s', addr)
        if uuid:
            self._excluded_uuids.add(uuid)
            key = self._peer_key(uuid)
            if key:
                self._excluded_keys.add(key)
            self._drop_distrusted_relays()
        return True

    def _drop_distrusted_relays(self):
        """Act on a new exclusion at once: evict a distrusted client from the
        relay we serve, and hang up on a relay we distrust (its peers' routes
        then fail over)."""
        if self._relay_server is not None:
            for uuid in list(self._relay_server.registered()):
                if uuid in self._excluded_uuids:
                    self._relay_server.evict(uuid)
        for endpoint, client in list(self._relay_clients.items()):
            if client.relay_uuid is not None and client.connected \
                    and self._is_distrusted(client.relay_uuid, client.relay_key):
                self.logger.warning('Relay: %s:%d (%s) is now distrusted; '
                                    'disconnecting', endpoint[0], endpoint[1],
                                    client.relay_uuid[:8])
                client.close()

    def _relay_client(self, endpoint):
        client = self._relay_clients.get(endpoint)
        if client is None:
            client = _relay.RelayClient(
                endpoint, self.myself,
                lambda frm, frame, ep=endpoint:
                    self.relay_messages.append((frame, frm, ep)),
                logger=self.logger,
                on_unreachable=lambda to, ep=endpoint:
                    self.relay_unreachable.append((ep, to)),
                on_record=lambda rid, wire:
                    self.relay_records.append((rid, wire)),
                on_dir=lambda frame, ep=endpoint:
                    self.relay_dir.append((ep, frame)),
                pin=self._relay_pins.get(endpoint),
                distrusted=self._is_distrusted)
            self._relay_clients[endpoint] = client
        return client

    def _pin_relay(self, endpoint, pin):
        """Remember that ``pin`` answers at ``endpoint``. A second, DIFFERENT
        pin for the same endpoint is refused (logged): two links disagreeing
        on who a relay is means one of them is wrong, and the first wins."""
        if pin is None:
            return
        known = self._relay_pins.get(endpoint)
        if known is not None and known != pin:
            self.logger.warning('Relay: %s:%d is pinned to %s already; ignoring a '
                                'pin to %s', endpoint[0], endpoint[1],
                                known[0][:8], pin[0][:8])
            return
        self._relay_pins[endpoint] = pin
        client = self._relay_clients.get(endpoint)
        if client is not None and client.pin != pin:
            client.pin = pin
            proven = client.proven_pin
            if client.connected and proven != pin:
                self.logger.warning('Relay: %s:%d is not the pinned relay; '
                                    'disconnecting', endpoint[0], endpoint[1])
                client.close()

    def _announce_own_relay(self, endpoint):
        """Tell identity that one of our own relays proved who it is, so the
        links it mints pin that relay, and file our reachability record there
        (a relay holds records in memory, so every registration refills it).
        Local IPC."""
        client = self._relay_clients.get(endpoint)
        if client is not None and self._own_record is not None \
                and endpoint in _relay.own_relays():
            try:
                client.publish(self._own_record)
            except (OSError, ConnectionError) as err:
                self.logger.debug('Relay: could not file our record at %s:%d (%s)',
                                  endpoint[0], endpoint[1], err)
        if client is not None and endpoint in _relay.own_relays():
            for wire in list(self._own_entries.values()):
                try:
                    client.dir_publish(wire)
                except (OSError, ConnectionError):
                    pass            # filed again at the next registration
        pin = client.proven_pin if client is not None else None
        queues = self._relay_queues
        if pin is None or queues is None or CfgIds.identity not in queues \
                or endpoint not in _relay.own_relays():
            return
        msg = Message(CfgIds.identity, Network.relay_identity,
                      json.dumps({'relay': '%s:%d' % endpoint,
                                  'uuid': pin[0], 'fp': pin[1]}),
                      to_whom=None, from_whom=None)
        try:
            queues[CfgIds.identity].put(msg, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.warning('Relay: identity queue full; own relay pin not sent')

    def _start_relays(self):
        """Serve as a relay (AT_RELAY) and register with our own relays
        (AT_USE_RELAY). Registration runs in the background and a failure is
        retried by :meth:`_maintain_relays`."""
        for endpoint, pin in _relay.own_relay_hints():
            self._pin_relay(endpoint, pin)
        if _relay.relay_enabled() and self._relay_server is None:
            try:
                registry = None
                if _registry.registry_enabled():
                    registry = _registry.Registry(_registry.load_issuers(),
                                                  distrusted=self._is_distrusted,
                                                  logger=self.logger)
                    self.logger.info('Registry: serving the directory (%d trusted '
                                     'issuer(s))', len(registry.issuers))
                self._relay_server = _relay.RelayServer(
                    self.myself.address or '0.0.0.0', _relay.relay_port(),
                    self.logger, identity=self.myself,
                    distrusted=self._is_distrusted, registry=registry)
            except OSError as err:
                self.logger.error('Relay: cannot serve on port %d (%s)',
                                  _relay.relay_port(), err)
        self._maintain_relays()

    #: Seconds between attempts to (re)register with one relay.
    RELAY_RETRY_SEC = 5.0

    def _relays_to_hold(self):
        """Every relay we stay registered with: our own, and each one a peer's
        route names -- a peer can reach us only through a relay we are
        registered at, and it may fail over to any on its list."""
        held = list(_relay.own_relays())
        for route in self._relay_routes.values():
            for endpoint in route:
                if endpoint not in held:
                    held.append(endpoint)
        return held

    def _maintain_relays(self):
        """Keep our registrations alive. Without them no one can reach us
        through a relay, and a node that only listens never sends -- so
        "retry on the next send" would never come. Each attempt runs on its own
        thread: a dead relay costs a connect timeout, which the network loop
        must not wait out."""
        now = time.monotonic()
        for endpoint in self._relays_to_hold():
            client = self._relay_client(endpoint)
            if client.connected or endpoint in self._relay_connecting:
                continue
            if now - self._relay_last_try.get(endpoint, float('-inf')) < self.RELAY_RETRY_SEC:
                continue
            self._relay_last_try[endpoint] = now
            self._relay_connecting.add(endpoint)
            threading.Thread(target=self._connect_relay, args=(endpoint,),
                             daemon=True, name='relay-connect').start()

    def _connect_relay(self, endpoint):
        client = self._relay_client(endpoint)
        try:
            client.connect()
            self._announce_own_relay(endpoint)
        except (OSError, ConnectionError) as err:
            if client.refused:
                self.logger.warning('Relay: %s:%d refused: %s', endpoint[0],
                                    endpoint[1], client.refused)
            else:
                self.logger.debug('Relay: %s:%d not reachable yet (%s)',
                                  endpoint[0], endpoint[1], err)
        finally:
            self._relay_connecting.discard(endpoint)

    def _relay_send(self, uuid, frame):
        """Send ``frame`` to peer ``uuid`` through its active relay, failing
        over down its route when a relay cannot be reached. Raises
        ConnectionError when none can."""
        key = str(uuid).lower()
        route = self._relay_routes.get(key) or []
        last_err = None
        for _ in range(len(route)):
            endpoint = route[0]
            try:
                self._relay_client(endpoint).send(key, frame)
            except (OSError, ConnectionError) as err:
                last_err = err
                self.logger.info('Relay: %s:%d unusable for %s (%s); trying the '
                                 'next', endpoint[0], endpoint[1], key[:8], err)
                route.append(route.pop(0))
                continue
            self._relay_last[key] = (frame, {endpoint})
            self._relay_retry.pop(key, None)    # a new frame: the old one is moot
            return
        self._lookup_reach(key)
        raise ConnectionError('no relay reaches %s (%s)' % (key[:8], last_err))

    def _drain_relay_unreachable(self):
        """A relay said it cannot reach a peer: fail over to the peer's next
        relay and resend the frame the refusal answers. Each frame is tried at
        most once per relay, so a peer registered nowhere ends the walk."""
        while self.relay_unreachable:
            endpoint, to = self.relay_unreachable.popleft()
            route = self._relay_routes.get(to)
            if not route or route[0] != endpoint:
                continue            # stale: already failed over
            route.append(route.pop(0))
            frame, tried = self._relay_last.get(to, (None, set()))
            if frame is None:
                continue
            while route[0] not in tried:
                endpoint = route[0]
                tried.add(endpoint)
                try:
                    self._relay_client(endpoint).send(to, frame)
                    self.logger.info('Relay: %s now reached through %s:%d',
                                     to[:8], endpoint[0], endpoint[1])
                    break
                except (OSError, ConnectionError):
                    route.append(route.pop(0))
            else:
                rounds = self._relay_retry.get(to, (0.0, 0))[1]
                self._lookup_reach(to)
                if rounds < self.RELAY_RETRY_ROUNDS:
                    self._relay_retry[to] = (time.monotonic() + self.RELAY_RETRY_SEC,
                                             rounds + 1)
                    self.logger.info('Relay: none of %d relay(s) reaches %s yet; '
                                     'retrying in %.0f s', len(route), to[:8],
                                     self.RELAY_RETRY_SEC)
                else:
                    self._relay_retry.pop(to, None)
                    self.logger.warning('Relay: none of %d relay(s) reaches %s',
                                        len(route), to[:8])

    #: How many times a frame every relay refused is walked again.
    RELAY_RETRY_ROUNDS = 3

    def _retry_refused_relayed(self):
        """Resend each frame every relay refused, once its retry is due, as a
        fresh walk down the peer's route."""
        now = time.monotonic()
        for to, (due, _rounds) in list(self._relay_retry.items()):
            if now < due:
                continue
            frame, _tried = self._relay_last.get(to, (None, None))
            route = self._relay_routes.get(to)
            if frame is None or not route:
                self._relay_retry.pop(to, None)
                continue
            # Parked, not dropped, until the walk it starts ends one way or the
            # other (a refusal re-arms it; a delivery says nothing).
            self._relay_retry[to] = (float('inf'), _rounds)
            endpoint = route[0]
            try:
                self._relay_client(endpoint).send(to, frame)
                self._relay_last[to] = (frame, {endpoint})
            except (OSError, ConnectionError):
                self._relay_last[to] = (frame, {endpoint})
                self.relay_unreachable.append((endpoint, to))

    def handle_relay_route(self, queues, message):
        """Identity says: reach peer ``uuid`` through ``relays`` (a list, in
        preference order; ``relay``, one, is also accepted). They go ahead of
        any the route already names. Local IPC only -- a peer must not be able
        to reroute this node's traffic, so anything carrying a sender is
        refused."""
        if getattr(message, 'from_whom', None) is not None:
            self.logger.warning('Refusing relay_route from the wire')
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
            self.logger.warning('relay_route: unusable request %r', message.obj)
            return True
        endpoints = []
        for item in given:
            endpoint, pin = _relay.parse_hint(str(item))
            if endpoint is None:
                self.logger.warning('relay_route: %r is not [uuid:fp@]host:port', item)
            else:
                self._pin_relay(endpoint, pin)
                endpoints.append(endpoint)
        if not endpoints:
            return True
        route = _relay.merge_endpoints(endpoints, self._relay_routes.get(uuid, []))
        self._relay_routes[uuid] = route
        # Register with the first now: the hello that follows goes through it.
        # The rest are registered in the background by _maintain_relays.
        try:
            self._relay_client(route[0]).connect()
            self._announce_own_relay(route[0])
        except (OSError, ConnectionError) as err:
            self.logger.warning('Relay: cannot register with %s:%d (%s)',
                                route[0][0], route[0][1], err)
        self._maintain_relays()
        return True

    def handle_reach_publish(self, queues, message):
        """Identity hands us our own current reachability record: file it at
        each of our relays now (and at every later registration). Local only."""
        if getattr(message, 'from_whom', None) is not None:
            self.logger.warning('Refusing reach_publish from the wire')
            return True
        try:
            wire = json.loads(message.obj) if isinstance(message.obj, str) else message.obj
            if not isinstance(wire, dict) or 'body' not in wire or 'sig' not in wire:
                raise ValueError(wire)
        except (ValueError, TypeError):
            self.logger.warning('reach_publish: unusable record')
            return True
        self._own_record = wire
        for endpoint in _relay.own_relays():
            client = self._relay_clients.get(endpoint)
            if client is not None and client.connected:
                try:
                    client.publish(wire)
                except (OSError, ConnectionError):
                    pass            # filed again at the next registration
        return True

    # -- the directory (network/registry.py) -------------------------------
    #: Seconds a lookup waits for its relays before answering "not found".
    DIR_LOOKUP_TIMEOUT = 10.0

    def _local_only(self, message, verb):
        if getattr(message, 'from_whom', None) is not None:
            self.logger.warning('Refusing %s from the wire', verb)
            return False
        return True

    @staticmethod
    def _payload(message):
        try:
            obj = json.loads(message.obj) if isinstance(message.obj, str) else message.obj
        except (ValueError, TypeError):
            return {}
        return obj if isinstance(obj, dict) else {}

    def _own_registry_clients(self):
        return [(ep, self._relay_clients[ep]) for ep in _relay.own_relays()
                if ep in self._relay_clients and self._relay_clients[ep].connected]

    def handle_dir_publish(self, queues, message):
        """Identity hands us our own directory entry: file it at each of our
        relays now, and at every later registration. Local only."""
        if not self._local_only(message, Network.dir_publish):
            return True
        wire = self._payload(message).get('entry')
        try:
            from ..contacts.directory import DirectoryEntry
            handle = DirectoryEntry.from_wire(wire).handle
        except ValueError:
            self.logger.warning('dir_publish: unusable entry')
            return True
        self._own_entries[handle] = wire
        for _ep, client in self._own_registry_clients():
            try:
                client.dir_publish(wire)
            except (OSError, ConnectionError):
                pass
        return True

    def handle_dir_withdraw(self, queues, message):
        if not self._local_only(message, Network.dir_withdraw):
            return True
        handle = str(self._payload(message).get('handle', ''))
        self._own_entries.pop(handle, None)
        for _ep, client in self._own_registry_clients():
            try:
                client.dir_withdraw(handle)
            except (OSError, ConnectionError):
                pass
        return True

    def handle_dir_lookup(self, queues, message):
        """Ask every relay we are registered at for ``handle``. Local only."""
        if not self._local_only(message, Network.dir_lookup):
            return True
        from ..contacts.directory import normalize_handle
        handle = normalize_handle(self._payload(message).get('handle'))
        if handle is None:
            self._dir_answer(queues, str(self._payload(message).get('handle', '')),
                             None, None, False)
            return True
        asked = set()
        for endpoint, client in list(self._relay_clients.items()):
            if client.connected:
                try:
                    client.dir_lookup(handle)
                    asked.add(endpoint)
                except (OSError, ConnectionError):
                    pass
        if not asked:
            self._dir_answer(queues, handle, None, None, False)
            return True
        self._dir_lookups[handle] = {'asked': asked, 'answered': set(),
                                     'limited': False, 'since': time.monotonic()}
        return True

    def _dir_answer(self, queues, handle, entry, endpoint, limited):
        if CfgIds.identity not in queues:
            return
        body = {'handle': handle, 'entry': entry, 'limited': bool(limited),
                'relay': '%s:%d' % endpoint if endpoint else ''}
        msg = Message(CfgIds.identity, IdentityProtocol.dir_result, json.dumps(body),
                      to_whom=None, from_whom=None)
        try:
            queues[CfgIds.identity].put(msg, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.warning('Registry: identity queue full; answer for %s dropped',
                                handle)

    def _drain_relay_dir(self, queues):
        """Registry answers -> identity: a lookup's one outcome, and the
        registry's word on our publish or withdraw."""
        while self.relay_dir:
            endpoint, frame = self.relay_dir.popleft()
            op = frame.get('op')
            handle = str(frame.get('handle', ''))
            if op in ('dir_entry', 'dir_limited') or (
                    op == 'dir_refused' and handle in self._dir_lookups
                    and frame.get('reason') == 'not_registry'):
                pending = self._dir_lookups.get(handle)
                if pending is None or endpoint not in pending['asked']:
                    continue
                if op == 'dir_entry' and isinstance(frame.get('entry'), dict):
                    del self._dir_lookups[handle]
                    self._dir_answer(queues, handle, frame['entry'], endpoint, False)
                    continue
                pending['answered'].add(endpoint)
                pending['limited'] |= op == 'dir_limited'
                if pending['answered'] >= pending['asked']:
                    del self._dir_lookups[handle]
                    self._dir_answer(queues, handle, None, None, pending['limited'])
                continue
            if op in ('dir_published', 'dir_refused', 'dir_withdrawn') \
                    and CfgIds.identity in queues:
                body = {'op': op, 'handle': handle, 'relay': '%s:%d' % endpoint,
                        'reason': str(frame.get('reason', '') or ''),
                        'seq': frame.get('seq', 0) if isinstance(frame.get('seq'), int) else 0}
                msg = Message(CfgIds.identity, IdentityProtocol.dir_status,
                              json.dumps(body), to_whom=None, from_whom=None)
                try:
                    queues[CfgIds.identity].put(msg, block=True, timeout=self.q_cadence)
                except Full:
                    pass
        now = time.monotonic()
        for handle in [h for h, p in self._dir_lookups.items()
                       if now - p['since'] > self.DIR_LOOKUP_TIMEOUT]:
            pending = self._dir_lookups.pop(handle)
            self._dir_answer(queues, handle, None, None, pending['limited'])

    #: Seconds between lookups of one peer's reachability record.
    REACH_LOOKUP_INTERVAL = 60.0

    def _lookup_reach(self, uuid):
        """We have lost ``uuid`` through every relay we know: ask each relay we
        are registered at for its reachability record (filed under its key's
        fingerprint). Answers go to identity, which verifies them."""
        key = self._peer_key(uuid)
        if not key:
            return
        now = time.monotonic()
        if now - self._reach_asked.get(uuid, float('-inf')) < self.REACH_LOOKUP_INTERVAL:
            return
        self._reach_asked[uuid] = now
        rid = _relay.key_fingerprint(key)
        asked = 0
        for client in list(self._relay_clients.values()):
            if client.connected:
                try:
                    client.lookup(rid)
                    asked += 1
                except (OSError, ConnectionError):
                    pass
        if asked:
            self.logger.info('Relay: looking up where %s is now (%d relay(s))',
                             str(uuid)[:8], asked)

    def _drain_relay_records(self, queues):
        """Hand lookup answers to identity (the single writer of contacts),
        which verifies each against the contact's key before using it."""
        while self.relay_records:
            rid, wire = self.relay_records.popleft()
            if not isinstance(wire, dict) or CfgIds.identity not in queues:
                continue
            msg = Message(CfgIds.identity, IdentityProtocol.reach_record,
                          json.dumps(wire), to_whom=None, from_whom=None)
            try:
                queues[CfgIds.identity].put(msg, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.warning('Relay: identity queue full; record %s dropped',
                                    rid[:8])

    def _drain_relayed(self, queues, budget):
        """Hand relayed frames to the same parse-and-route paths UDP uses,
        attributing each by the uuid the RELAY stamped, not by an address."""
        drained = 0
        while drained < budget and self.relay_messages:
            frame, frm, endpoint = self.relay_messages.popleft()
            drained += 1
            # Replies go back the way this came: that relay becomes the
            # active one, ahead of the rest of the route.
            self._relay_routes[frm] = _relay.merge_endpoints(
                [endpoint], self._relay_routes.get(frm, []))
            try:
                peer = self.peers.find_by_uuid(_uuid_mod.UUID(frm))
            except ValueError:
                continue
            if peer is not None:
                fmt = self._wire_format_for_addr(peer.address)
                try:
                    plain = self.myself.decrypt(frame, peer)
                except Exception:
                    if not self._accept_unencrypted(frame, peer, queues,
                                                    wire_format=fmt):
                        self.logger.error('Relay: frame from %s neither decrypts '
                                          'nor is an unencrypted verb', frm[:8])
                    continue
                if self._relay_live.get(frm) != endpoint:
                    # Once per change, so an operator can see which relay
                    # carries a peer, and when it failed over.
                    self._relay_live[frm] = endpoint
                    self.logger.info('Relay: %s is talking to us through %s:%d',
                                     frm[:8], endpoint[0], endpoint[1])
                self._msg_to_queue(plain, peer, queues, 'relay', wire_format=fmt)
                continue
            # A sender we do not know yet: only plaintext can be read (the
            # first-contact hello). The envelope must name the sender the relay
            # vouched for -- the relay cannot forge `from`, so neither may the
            # frame.
            try:
                probe = Message.parse(frame, None, validate=False)
                claimed = str(getattr(probe.from_whom, 'uuid', '')).lower()
            except Exception:
                self.logger.debug('Relay: unreadable frame from unknown %s', frm[:8])
                continue
            if claimed != frm:
                self.logger.warning('Relay: frame from %s claims to be %s; '
                                    'dropped', frm[:8], claimed[:8])
                continue
            try:
                self._msg_to_queue(frame, 'relay:' + frm, queues, 'relay',
                                   validate=False, opaque=True)
            except (UnicodeDecodeError, WireFormatMismatch):
                self.logger.debug('Relay: undecodable frame from unknown %s', frm[:8])
        return drained

    def handle_readmit(self, queues, message):
        """Reverse an exclusion (explicit rehabilitation). Local IPC."""
        if getattr(message, 'from_whom', None) is not None and \
                str(getattr(message.from_whom, 'uuid', '')) != str(getattr(self.myself, 'uuid', '')):
            self.logger.warning('Refusing readmit from the wire')
            return True
        address, uuid = self._exclusion_spec(message)
        addr = self._norm_addr(address) if address else None
        if addr:
            self._rejected_addresses.discard(addr)
            _probes.counter('net.exclude', 'remove')
            self.logger.info('Reputation readmit: %s', addr)
        if uuid:
            self._excluded_uuids.discard(uuid)
            key = self._peer_key(uuid)
            if key:
                self._excluded_keys.discard(key)
        return True

    _PARTITION_SIGNAL_COOLDOWN = 5.0  # seconds, per from_addr

    def _signal_partition(self, queues, from_addr):
        """Forward a partition-recovery signal to IdentityProcess.

        Called from the group-channel drop site when ``from_addr`` is
        not in our group's address list — a possible split-brain
        indication. We do not validate or decrypt the original message
        (we can't; it was encrypted under another group's key); the
        signal payload is just the source address so IdentityProcess
        can decide whether to emit an unsecured-multicast
        ``partition_probe`` toward that address's group.

        Rate-limited at one signal per ``from_addr`` per 5 seconds —
        a chatty cross-group peer would otherwise let this queue grow
        without bound and starve real identity traffic.

        See doc/architecture/partition-recovery.md §5.1.
        """
        now = datetime.now()
        last = self._partition_signal_lru.get(from_addr)
        if (last is not None
                and (now - last).total_seconds() < self._PARTITION_SIGNAL_COOLDOWN):
            return
        self._partition_signal_lru[from_addr] = now
        target = queues.get(CfgIds.identity)
        if target is None:
            return
        signal = Message(CfgIds.identity,
                         IdentityProtocol.partition_signal,
                         from_addr,
                         encrypt=False)
        try:
            target.put(signal, block=True, timeout=self.q_cadence)
            _probes.counter('net.group', 'partition_signal_emitted', from_addr)
        except Full:
            _probes.counter('net.group', 'partition_signal_drop', 'queue_full')

    def _ensure_ping_at_pool(self):
        """Lazily instantiate the ping thread pool inside the subprocess.
        Created on demand so it doesn't try to ride through a pickle
        handoff. Outbound pings dispatch here so the synchronous ping_at()
        function (which sleeps 1 s per packet × count) doesn't block the
        main process loop.
        """
        if self._ping_at_pool is None:
            self._ping_at_pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=16, thread_name_prefix='netproc-ping')
        return self._ping_at_pool

    def _do_ping_at_async(self, address, count, return_queue, peer=None):
        """Run ping_at() in a worker thread and post stats back to the
        original requester's return queue. Errors are logged but not
        raised — a failed ping is just a missed RTT sample, not a
        process-fatal event.

        The reply carries the pinged peer as `from_whom` so the requester can
        attribute the sample. Without it the reply named nobody: PingATStats
        only knows the address it dialed, and every consumer keys peers by
        Identity UUID, so a sample either landed on a node named for an IP or
        on no node at all.
        """
        try:
            # Pass this node's own address: the reply socket must bind it, not
            # the wildcard, or a co-located node separated only by address
            # receives these replies instead (doc/architecture/networking.md). A wildcard
            # my_address (the TCP listener's 0.0.0.0 fallback) is no address at
            # all -- hand ping_at None and let it derive one from the route.
            local = (getattr(self, 'my_address', None)
                     or getattr(getattr(self, 'net_cfg', None), 'ip4', None))
            if local in ('', '0.0.0.0', '::'):
                local = None
            stats = ping_at(address, count=count, local_address=local)  # noqa
            msg = Message(self.name, Network.ping_at, stats,  # noqa
                          from_whom=peer)
            return_queue.put(msg, block=True, timeout=self.q_cadence)
        except TransmissionError as err:
            self.logger.error('Ping (async): %s', err)
        except Full:
            self.logger.warning('Ping (async): return queue full, dropping stats')
        except Exception as err:
            self.logger.error('Ping (async) unexpected: %s', err)

    def _encr_recv(self, method, msg_queue):
        # Tag counters by recv_peer/recv_group to distinguish ptp vs group.
        layer = 'net.recv.' + method.__name__.replace('recv_', '')
        # Lazy import — only the TCP transport defines PeerDisconnect.
        # UDP-only deployments don't have a tcp module loaded.
        try:
            from .tcp import PeerDisconnect
        except ImportError:  # pragma: no cover
            PeerDisconnect = ()  # type: ignore[assignment]
        while not self.stop:
            try:
                raw_msg, from_addr, from_port = method()
            except PeerDisconnect as err:
                # Clean close before any framing bytes — routine during
                # onboarding/teardown. Counter-only, no error log.
                _probes.counter(layer, 'recv_error', 'peer_disconnect')
                self.logger.debug('Network: %s', err)
                continue
            except TransmissionError as err:
                _probes.counter(layer, 'recv_error', 'transmission')
                self.logger.error('Network: %s', err)
                self.track_recv_error()
                continue
            except TimeoutError:
                continue
            except BlockingIOError:
                # Socket fell into non-blocking mode — observed under
                # forkserver when default-timeout inheritance doesn't
                # take. Tracked but quiet; sleep keeps the thread off
                # the CPU until the next recv has a real chance.
                _probes.counter(layer, 'recv_error', 'blocking_io')
                time.sleep(self.socket_timeout)
                continue
            except Exception as err:
                if isinstance(err, OSError) and err.errno == errno.EBADF and self.stop:
                    # Teardown race, not a fault: shutdown sets self.stop and
                    # only then calls close_listeners(), so a thread already
                    # past its stop check and inside recv_* takes EBADF exactly
                    # once before the loop exits. Logging it at error made every
                    # clean shutdown look like a failure.
                    _probes.counter(layer, 'recv_error', 'closed_at_stop')
                    self.logger.debug('Network: listener closed at shutdown')
                    continue
                # Belt-and-suspenders: a single malformed frame should
                # not kill the listener thread for the rest of the run.
                # (Used to lose every subsequent inbound after the first
                # encrypted message because tcp._recv .decode'd raw
                # bytes and crashed the thread.)
                _probes.counter(layer, 'recv_error', err.__class__.__name__)
                self.logger.error('Network recv crashed: %s', err)
                self.track_recv_error()
                continue
            if raw_msg is not None:
                msg_queue.append((raw_msg, from_addr))
                who = self.peers.find_by_address(from_addr)
                if who is not None:
                    self.track_recv_stats(who.uuid, len(raw_msg))
                else:
                    self.track_recv_stats(self.unknown_peer, len(raw_msg))
            elif from_addr is not None:
                who = self.peers.find_by_address(from_addr)
                if who is not None:
                    if who not in self.pests:
                        self.pests[who] = 0
                    self.pests[who] += 1
                    if self.pests[who] > self.annoy_limit:
                        self.peers.demote(who)
                        del self.pests[who]

    def peer_receiver(self):
        """
        Receive thread for point-to-point
        Track peers not on whitelist (accept_peer_message), demote if they persist
        :return: None
        """
        self._encr_recv(self.recv_peer, self.peer_messages)

    def group_receiver(self):
        """
        Receive thread for pseudo-multicast with a single encryption key
        Track peers not on whitelist (accept_peer_message), demote if they persist
        :return: None
        """
        self._encr_recv(self.recv_group, self.group_messages)

    def unknown_receiver(self):
        """
        Receive thread for one-to_many
        :return: None
        """
        while not self.stop:
            try:
                raw_msg, from_addr, from_port = self.recv_any()
            except TransmissionError as err:
                _probes.counter('net.recv.any', 'recv_error', 'transmission')
                self.logger.error('Network: %s', err)
                continue
            except TimeoutError:
                continue
            except BlockingIOError:
                _probes.counter('net.recv.any', 'recv_error', 'blocking_io')
                time.sleep(self.socket_timeout)
                continue
            except Exception as err:
                if isinstance(err, OSError) and err.errno == errno.EBADF and self.stop:
                    # Same teardown race as _encr_recv; see the note there.
                    _probes.counter('net.recv.any', 'recv_error', 'closed_at_stop')
                    self.logger.debug('Network: listener closed at shutdown')
                    continue
                # Mirror _encr_recv: never let a malformed inbound kill
                # the listener thread for the rest of the run.
                _probes.counter('net.recv.any', 'recv_error', err.__class__.__name__)
                self.logger.error('Network recv_any crashed: %s', err)
                continue
            if raw_msg is not None:
                self.unknown_messages.append((raw_msg, from_addr))

    def mystery_handler(self, queues):
        """
        Handle encrypted messages sent before the peer is known

        A deferral whose sender never becomes a known peer is reclaimed once it
        is `mystery_max_age_s` seconds old. This used to count retries instead
        (60 of them, at a cadence that made it roughly 30 s), which meant the
        real bound moved with load: the loop's cadence is not the loop's
        period, so a busy node aged entries out later than a quiet one, and the
        number in the config did not name a duration anyone could reason about.
        C bounded the same queue by age from the start, because its retry is
        event-driven rather than polled and a count there would have measured
        peer admissions rather than time. Both sides now agree on the quantity
        as well as the value (doc/architecture/networking.md).
        :return: None
        """
        while not self.stop:
            remaining = deque()
            now = time.monotonic()
            while True:
                try:
                    raw_msg, from_addr, deferred_at = self.encrypted_messages.popleft()
                except IndexError:
                    break
                peer = self.peers.find_by_address(from_addr)
                decrypt_msg = None
                if peer is not None:
                    try:
                        decrypt_msg = self.myself.decrypt(raw_msg, peer)
                    except Exception as err:
                        # Not this peer's ciphertext after all -- unrelated
                        # noise from that address, a frame under a key that has
                        # since rotated, or a plaintext frame that only looked
                        # opaque. An unguarded decrypt here KILLED this thread
                        # (both loops are inside the `while not self.stop`),
                        # which silently retired the whole out-of-order queue
                        # for the life of the node. Retained rather than
                        # dropped, matching C's replay pass, which keeps a
                        # deferred entry whose decrypt fails and lets the age
                        # bound below reclaim it.
                        _probes.counter('net.mystery', 'decrypt_failed')
                        self.logger.debug(
                            'Deferred message from %s still does not decrypt '
                            '(%s); retaining until it ages out', from_addr, err)
                if decrypt_msg is not None:
                    self._msg_to_queue(decrypt_msg, peer, queues, 'point-to-point',
                                       wire_format=self._wire_format_for_addr(from_addr))
                    _probes.counter('net.mystery', 'resolved')
                    _probes.emit('net.mystery', 'resolved',
                                 from_addr=from_addr,
                                 peer_uuid=str(peer.uuid),
                                 waited_s=round(now - deferred_at, 3))
                    self.logger.debug('Out-of-order message from %s handled', peer.nickname)
                else:
                    age = now - deferred_at
                    # >= matches C's _deferred_sweep_stale_locked, so a message
                    # deferred at the same second on both sides is reclaimed on
                    # the same side of the boundary.
                    if age >= self.mystery_max_age_s:
                        # Was ('drop', 'max_retries'); renamed with the switch to
                        # an age bound so both runtimes emit the SAME probe for
                        # the same event -- C already emitted this triple. The
                        # `aged_out` emit below was always the aligned one, which
                        # is why scripts/probe-flow.py keys on it.
                        _probes.counter('net.mystery', 'aged_out', 'max_age')
                        _probes.emit('net.mystery', 'aged_out',
                                     from_addr=from_addr,
                                     age_s=round(age, 3))
                        self.logger.debug('Spurious encrypted message from %s dropped', from_addr)
                    else:
                        remaining.append((raw_msg, from_addr, deferred_at))
            self.encrypted_messages.extend(remaining)
            time.sleep(self.cadence + self.q_cadence)  # curiously, does not sleep if exactly cadence

    def _accept_unencrypted(self, raw_msg, from_whom, queues,
                            wire_format=NetWireFormat.json):
        """Deliver a plaintext frame from a KNOWN peer, but only an allowlisted
        verb that declares itself unencrypted.

        Three conditions, all required: the bytes parse as an envelope, the
        envelope's own `encrypt` flag is false, and the verb is in
        UNENCRYPTED_VERBS. A frame that merely fails to decrypt is NOT accepted
        -- corrupt ciphertext, a stale group key, or a forged frame all land in
        the caller's drop path as before.

        Returns True only if the frame was handed on. Parsing happens twice (here
        to inspect, then inside _msg_to_queue to deliver); this is an error-path
        branch, and the alternative is duplicating the dispatch logic.
        """
        try:
            probe = Message.parse(raw_msg, from_whom, validate=False,
                                  wire_format=wire_format)
        except Exception:
            # Not a parseable envelope -- almost certainly real ciphertext.
            _probes.counter('net.ptp', 'unencrypted_refused', 'unparseable')
            return False
        if getattr(probe, 'encrypt', True):
            # Claims to be encrypted but would not decrypt. Genuinely broken or
            # hostile; do not accept the plaintext reading of it.
            _probes.counter('net.ptp', 'unencrypted_refused', 'claims_encrypted')
            return False
        verb = getattr(probe, 'function', None)
        if verb not in UNENCRYPTED_VERBS:
            _probes.counter('net.ptp', 'unencrypted_refused', str(verb))
            self.logger.warning(
                'Refusing plaintext %s from known peer %s: not an unencrypted '
                'verb', verb, getattr(from_whom, 'nickname', from_whom))
            return False
        self._msg_to_queue(raw_msg, from_whom, queues, 'point-to-point',
                           validate=False, wire_format=wire_format)
        _probes.counter('net.ptp', 'unencrypted_accepted', str(verb))
        return True

    def _msg_to_queue(self, msg, from_whom, queues, rcvd_by, validate=True,
                      wire_format=NetWireFormat.json, opaque=False):
        """Parse *msg* in *wire_format* and route it.

        *opaque* says the caller does not yet know whether these bytes are an
        envelope at all -- the unknown-sender point-to-point path, where the
        frame is just as likely to be ciphertext awaiting the sender's
        admission. There, a format-marker refusal is NOT the diagnosis "a
        misprovisioned cohort is talking proto at us": ciphertext is uniform
        bytes, so one frame in 256 opens with NET_WIRE_PROTO_MAGIC by chance.
        The refusal is re-raised instead of being counted and logged as a
        foreign-format drop, so the caller defers the frame exactly as it does
        for ciphertext that fails to decode -- which is what C's
        handle_inbound_peer already does (every parse failure on that path
        reaches defer_message).
        """
        try:
            message = Message.parse(msg, from_whom, validate=validate,
                                    wire_format=wire_format)
        except WireFormatMismatch as err:
            if opaque:
                raise
            # The frame is in a format this context does not speak (doc/architecture/network-wire-format.md). The
            # parser for that format was never run over it, which is the point.
            # Counted and logged rate-limited rather than silently dropped: a
            # cohort misprovisioned into two formats presents as total silence
            # from one peer, and this counter is the only thing that says why.
            _probes.counter('net.wire', 'drop', 'foreign_format')
            _addr = from_whom.address if isinstance(from_whom, Identity) else from_whom
            _n = self._foreign_format_counts.get(str(_addr), 0) + 1
            self._foreign_format_counts[str(_addr)] = _n
            if _n == 1 or _n % 10 == 0:
                self.logger.error(
                    'Dropping %s frame from %s: %s (expected %s; count: %d)',
                    rcvd_by, _addr, err, wire_format, _n)
            return
        except TypeError as err:
            _probes.counter('net.parse', 'drop', 'type_error')
            self.logger.error('Error parsing %s: %s', msg, err)
            return
        from_addr = from_whom
        if isinstance(from_whom, Identity):
            from_addr = from_whom.address

        # Gateway boundary, invariant B (see the block above _held_groups):
        # bootstrap is domain-local. Two refusals, and neither can fire on a
        # leaf node -- the first because the pre-admission verbs are never
        # group-addressed in the first place (announce is broadcast, accept and
        # history are point-to-point to an unplaced identity), the second
        # because _crosses_gateway is False without child groups.
        if message.function in BOOTSTRAP_VERBS:
            if rcvd_by == 'group':
                self._boundary_refuse(
                    'bootstrap_on_group_channel', from_addr,
                    '%s arrived group-encrypted; the pre-admission handshake '
                    'is never a group message' % message.function)
                return
            if self._crosses_gateway(from_addr):
                self._boundary_refuse(
                    'bootstrap_across_gateway', from_addr,
                    '%s from a cohort we gateway; admitting across the boundary '
                    'would make a group span it' % message.function)
                return

        # Deliver to any known process queue, not just subsystems.
        # Cross-instance request/response patterns (e.g. an inspector
        # bridge soliciting peer-to-peer reputation: rep_req carries
        # req_proc='main', the peer's rep_resp comes back addressed to
        # 'main') need 'main' as a valid destination. Restricting to
        # subsystems silently dropped those responses with "Recvd
        # message for unknown main process".
        target = message.process
        if target in queues:
            try:
                queues[target].put(
                    message, block=True, timeout=self.q_cadence)
                _probes.counter('net.dispatch', 'delivered', target)
                _probes.trace_msg(message, 'dispatched',
                                  target=target, rcvd_by=rcvd_by, from_addr=str(from_addr))
                self.logger.debug('Recvd %s message for %s:%s from %s', rcvd_by, target, message.function, from_addr)
            except Full:
                _probes.counter('net.dispatch', 'queue_full', target)
                _probes.trace_msg(message, 'queue_full', target=target)
                self.logger.error('Network: %s queue is full', target)
        else:
            _probes.counter('net.dispatch', 'unknown_target', target)
            _probes.trace_msg(message, 'unknown_target', target=target)
            self.logger.error('Recvd message for unknown %s process from %s. Ignoring.', target, from_addr)
            self.logger.debug('Message: %s', str(message))

    def process(self, queues, signal):
        """
        Network processing main loop
        Two channels:
            open, one-to-any - requires enhanced security
            encrypted, one-to-n, 1 <= n <= all peers
        :param queues: Interprocess communication queues
        :param signal: IPC queue for signalling halt
        :return:
        """
        run_post_fork(self)
        # Re-establish receiver-socket timeouts here, in the worker
        # subprocess. The sockets are created in __init__ (which runs
        # in the parent) and transferred via fd-passing during the
        # forkserver pickle. The OS-level non-blocking flag survives,
        # but the Python-level timeout tracking does not — without
        # this rebinding, recvfrom raises BlockingIOError on the very
        # first call. (Surfaced 2026-05-01 by tests/diag/harness.py.)
        for _sock in (self.recv_ptp_sock, self.recv_grp_sock,
                      self.recv_cast_sock):
            try:
                _sock.settimeout(self.socket_timeout)
            except (OSError, AttributeError):
                pass
        self._init_transport()
        self.start_receivers(queues)
        self._relay_queues = queues
        self._start_relays()
        threading.Thread(target=self.unknown_receiver, daemon=True).start()
        threading.Thread(target=self.mystery_handler, args=(queues,), daemon=True).start()
        while self.keep_running(signal):
            try:
                self.reap_idle_conns()
                self._maintain_relays()
                self._drain_relay_unreachable()
                self._retry_refused_relayed()
                self._drain_relay_records(queues)
                self._drain_relay_dir(queues)
                if self.diplomat:
                    if self.ping_at_server is None:
                        self.ping_at_server = PingATServer(self.net_cfg.ip4, self.logger)
                        self.ping_at_server.start()
                elif self.ping_at_server is not None:
                    self.ping_at_server.stop()
                    self.ping_at_server = None
                try:
                    message = queues[self.name].get(block=True, timeout=self.q_cadence)  # noqa
                    _probes.counter('net.dequeue', 'got')
                    if isinstance(message, Message):
                        _probes.counter('net.dequeue', 'msg', message.function)
                    else:
                        _probes.counter('net.dequeue', 'non_msg', type(message).__name__)
                except Empty:
                    _probes.counter('net.dequeue', 'empty')
                    message = None
                if message and not self.protocol.run_message_handlers(queues, message):
                    if isinstance(message, Message):
                        # Extract recipient address for grouping. to_whom
                        # may be a list of Identities, a single Identity,
                        # a Group, or Network.broadcast.
                        to_whom = getattr(message, 'to_whom', None)
                        if isinstance(to_whom, list) and to_whom:
                            to_addr = getattr(to_whom[0], 'address', None) or '?'
                        elif hasattr(to_whom, 'address'):
                            to_addr = to_whom.address or '?'
                        elif hasattr(to_whom, 'addresses'):
                            to_addr = 'group'
                        elif to_whom == Network.broadcast:
                            to_addr = 'broadcast'
                        else:
                            to_addr = '?'
                        _probes.trace_msg(message, 'outbound_routed',
                                          encrypt=message.encrypt,
                                          to_addr=to_addr,
                                          to=str(to_whom)[:80])
                        self.logger.debug('Send network message: %s:%s', message.process, message.function)
                        try:
                            if message.function == Network.stats_req:
                                msg = Message(CfgIds.network, Network.stats_resp, self.net_stats)
                                queues[message.process].put(msg, block=True, timeout=self.q_cadence)
                            elif message.function == Network.ping_at:
                                # Message.__init__ wraps a single Identity
                                # to_whom in a list; pull the head out
                                # before dereferencing .address.
                                target = message.to_whom
                                if isinstance(target, list):
                                    target = target[0] if target else None
                                if target is None:
                                    self.logger.warning(
                                        'Ping: empty to_whom; skipping')
                                elif message.return_to not in queues:
                                    self.logger.warning(
                                        'Ping: unknown return_to %r '
                                        '(expected a queue key); skipping', message.return_to)
                                else:
                                    # Dispatch to a worker thread; ping_at()
                                    # is synchronous and sleeps 1 s per
                                    # packet (count=5 → ≥5 s). Running it
                                    # inline blocks the netproc main loop
                                    # and starves all other outbound.
                                    self._ensure_ping_at_pool().submit(
                                        self._do_ping_at_async,
                                        target.address, message.obj,
                                        queues[message.return_to], target)
                            elif message.to_whom == Network.broadcast:
                                # Broadcast is discovery: it goes to nodes we
                                # cannot place in any group, so JSON
                                # unconditionally (doc/architecture/network-wire-format.md). `bytes(message)` IS
                                # the JSON form.
                                msg = bytes(message)
                                try:
                                    self.send_any(msg)
                                    self.track_send_stats(self.unknown_peer, len(msg))
                                except TransmissionError as err:
                                    self.logger.error('Network: %s', err)
                                    self.track_send_error(self.unknown_peer)
                            elif isinstance(message.to_whom, Group):
                                # Encrypt with the TARGET group's key when
                                # we hold its private half (e.g. a gateway
                                # addressing one of its child cohorts);
                                # otherwise fall back to the primary group,
                                # which is the historical single-group
                                # behaviour for a leaf node.
                                enc_grp = self.group
                                tgt = message.to_whom
                                try:
                                    if (not getattr(tgt, '_public_only', True)
                                            and getattr(tgt.encryptor, 'private', None) is not None):
                                        enc_grp = tgt
                                except Exception:
                                    enc_grp = self.group
                                # Format follows the ADDRESSED group, which
                                # for a gateway is the child cohort, not our
                                # own (doc/architecture/network-wire-format.md). Note this is a different question
                                # from which key encrypts it (enc_grp above):
                                # the key is about what we HOLD, the format
                                # about what the recipients SPEAK.
                                tgt_fmt = getattr(tgt, 'wire_format', None) or \
                                    self._wire_format_for_group(self.group)
                                wire = message.to_wire(tgt_fmt)
                                if message.encrypt and enc_grp is not None:
                                    msg = enc_grp.encrypt(wire, enc_grp)
                                else:
                                    msg = wire
                                for addr in message.to_whom.addresses:
                                    if addr == self.myself.address:
                                        continue
                                    # Gateway boundary, invariant G: a group's
                                    # traffic never reaches an address that also
                                    # belongs to another group we hold.
                                    if len(self._groups_containing(addr)) > 1:
                                        self._boundary_refuse(
                                            'group_spans_gateway', addr,
                                            'target is a member of more than one '
                                            'group we hold')
                                        continue
                                    # Reputation cut-off: do not forward
                                    # to/for an excluded member (a gateway
                                    # thus stops relaying toward it).
                                    if self.reject_message(addr):
                                        _probes.counter('net.group', 'skip', 'excluded_target')
                                        continue
                                    try:
                                        self.send_group(msg, addr)
                                        self.track_send_stats(self.unknown_peer, len(msg))
                                    except TransmissionError as err:
                                        self.logger.error('Network: %s', err)
                                        self.track_send_error(self.unknown_peer)
                            else:  # defaults to pseudo-multicast
                                for who in message.to_whom:  # Message ensures this is list  # noqa
                                    address = who.address
                                    if '/' in address:
                                        address = address.split('/')[0]
                                    # Gateway boundary, invariant B: the
                                    # pre-admission handshake stays inside the
                                    # domain it started in.
                                    if (message.function in BOOTSTRAP_VERBS
                                            and self._crosses_gateway(address)):
                                        self._boundary_refuse(
                                            'bootstrap_across_gateway', address,
                                            'refusing to send %s to a cohort we '
                                            'gateway' % message.function)
                                        continue
                                    # Reputation cut-off: skip an excluded
                                    # recipient.
                                    if self.reject_message(address):
                                        _probes.counter('net.ptp', 'skip', 'excluded_target')
                                        continue
                                    # A peer we can place speaks its group's
                                    # format; one we cannot place gets JSON,
                                    # which is what makes pre-admission traffic
                                    # work in a proto cohort (doc/architecture/network-wire-format.md).
                                    wire = message.to_wire(
                                        self._wire_format_for_addr(address))
                                    if message.encrypt:
                                        msg = self.myself.encrypt(wire, who)
                                    else:
                                        msg = wire
                                    route = self._relay_routes.get(str(who.uuid).lower())
                                    try:
                                        if route:
                                            # Behind a relay: the frame is
                                            # already sealed for `who`.
                                            self._relay_send(who.uuid, msg)
                                        else:
                                            self.send_peer(msg, address)
                                        self.track_send_stats(who.uuid, len(msg))
                                    except TransmissionError as err:
                                        self.logger.error('Network: %s', err)
                                        self.track_send_error(who.uuid)
                                    except (OSError, ConnectionError) as err:
                                        # Only a relayed send is caught here; a
                                        # direct one raises as it always has.
                                        if not route:
                                            raise
                                        self.logger.error('Network: relay: %s', err)
                                        self.track_send_error(who.uuid)
                        except BrokenPipeError as err:
                            self.logger.error('Network: %s', err)
                    else:
                        _probes.counter('net.outbound', 'drop', 'not_a_message')
                        self.logger.error('Net process recvd message of type %s - Message required. Ignoring.', type(message))
                        self.logger.debug('Ignored message: %s', str(message))

                # Drain inbound deques. Each receiver thread can only
                # push ~1 msg/0.1s per channel (recv-socket timeout),
                # but during welcome bursts all three channels run hot
                # and the old 1-popleft-per-iter pattern left messages
                # in the deque for whole iters. Per-channel budget caps
                # any single channel at INBOUND_BUDGET pops per iter so
                # one noisy channel can't starve the others.
                INBOUND_BUDGET = 32
                total_inbound = 0

                # async recv point-to-point messages
                drained_ptp = 0
                while drained_ptp < INBOUND_BUDGET:
                    try:
                        raw_msg, from_addr = self.peer_messages.popleft()
                    except IndexError:
                        break
                    drained_ptp += 1
                    # Reputation cut-off: an excluded sender is ignored --
                    # drop its frame before any decrypt/delivery.
                    if self.reject_message(from_addr):
                        _probes.counter('net.ptp', 'drop', 'excluded')
                        continue
                    # Use the LIVE roster (self.peers), not the original bootstrap
                    # Peers object in self.configs[CfgIds.peers] (only the welcomer's
                    # address). Every other attribution site uses self.peers; using
                    # the stale config here missed ~100% of inbound ptp msgs, which
                    # then churned through mystery_handler + retries (CPU + drops).
                    peers = self.peers
                    from_whom = peers.find_by_address(from_addr)
                    if from_whom is not None:
                        try:
                            decrypt_msg = self.myself.decrypt(raw_msg, from_whom)
                            self._msg_to_queue(decrypt_msg, from_whom, queues, 'point-to-point',
                                               wire_format=self._wire_format_for_addr(from_addr))
                        except Exception:
                            # Decrypt failed. Some protocol verbs are sent in
                            # PLAINTEXT by design (encrypt=False), and once a
                            # peer is in the listing this is the branch its
                            # frames take -- so those verbs were dropped here,
                            # which is what cost 3-peer convergence. Accept a
                            # plaintext parse only for an allowlisted verb; a
                            # known peer must not be able to downgrade anything
                            # else. See identity.protocol.UNENCRYPTED_VERBS.
                            if not self._accept_unencrypted(
                                    raw_msg, from_whom, queues,
                                    wire_format=self._wire_format_for_addr(from_addr)):
                                _probes.counter('net.ptp', 'drop', 'decrypt_failed_known_peer')
                                self.logger.error('Decryption failed for known peer %s, rejecting message', from_whom.nickname)
                    else:
                        # Unknown sender — bootstrap (empty peers) or a
                        # late joiner welcoming us. Try unencrypted parse;
                        # legitimate handshake messages (identity:accept)
                        # are encrypt=False. If bytes don't decode, it's
                        # an encrypted message from a peer we don't know
                        # yet — defer to mystery_handler.
                        #
                        # CHURN DIAGNOSTIC: attribution misses on ~every
                        # inbound (deferred_encrypted == accepted). Is it a
                        # format mismatch (from_addr shape != listing keys)
                        # or a timing race (address registered a beat later)? Categorize
                        # cheaply always, and capture a bounded sample of from_addr vs
                        # listing keys to compare shapes. See
                        # doc/architecture/network-connection-pooling.md (the
                        # attribution-miss item).
                        _listing = getattr(self.peers, 'listing', None) or {}
                        _probes.counter('net.ptp', 'attrib_miss',
                                        'listing_empty' if not _listing
                                        else 'addr_not_in_listing')
                        _dn = getattr(self, '_attrib_miss_diag_n', 0)
                        if _dn < 25:
                            self._attrib_miss_diag_n = _dn + 1
                            try:
                                _keys = sorted(str(k) for k in _listing)[:8]
                            except Exception:
                                _keys = ['<unavailable>']
                            _probes.emit('net.ptp', 'attrib_miss_sample',
                                         from_addr=repr(from_addr),
                                         listing_size=len(_listing),
                                         listing_keys=_keys)
                        try:
                            # JSON, not a lookup: we could not place this sender
                            # in any group, and a frame from an unplaced sender
                            # is bootstrap traffic by definition (doc/architecture/network-wire-format.md).
                            # `opaque`: these bytes are as likely to be
                            # ciphertext as an envelope, so a format-marker
                            # refusal means "not a plaintext JSON envelope"
                            # (defer it), not "foreign cohort" (drop it).
                            self._msg_to_queue(raw_msg, from_addr, queues, 'point-to-point',
                                               validate=False, opaque=True)
                            _probes.counter('net.ptp', 'unknown_sender', 'parsed_unencrypted')
                        except (UnicodeDecodeError, WireFormatMismatch):
                            _probes.counter('net.ptp', 'unknown_sender', 'deferred_encrypted')
                            self.logger.debug('Out-of-order message from %s detected, retry later', from_addr)
                            # Stamp the deferral time here, as C does in
                            # defer_message: the age-out window runs from when
                            # the message was deferred, not from when the
                            # handler happens to look at it. Monotonic, so a
                            # clock step cannot age the queue out at once.
                            self.encrypted_messages.append((raw_msg, from_addr, time.monotonic()))
                total_inbound += drained_ptp
                total_inbound += self._drain_relayed(queues, INBOUND_BUDGET)

                # async recv group messages
                drained_grp = 0
                while drained_grp < INBOUND_BUDGET:
                    if self.group is None:
                        break  # otherwise, skip for now
                    try:
                        raw_msg, from_addr = self.group_messages.popleft()
                    except IndexError:
                        break
                    drained_grp += 1
                    # Reputation cut-off: drop an excluded sender's group
                    # frame before decrypt/delivery (a gateway thus does
                    # not relay it onward either).
                    if self.reject_message(from_addr):
                        _probes.counter('net.group', 'drop', 'excluded')
                        continue
                    # Resolve which group this sender belongs to. For a leaf node this
                    # is always the primary group (or None), so the path is identical to
                    # before. A gateway additionally matches its child groups,
                    # decrypting a cohort-below frame with that cohort's own key. See
                    # doc/architecture/gateway-reputation-tree.md.
                    # Gateway boundary, invariant G: an address in two of the
                    # groups we hold means those groups have merged across this
                    # gateway. Refuse rather than let _group_for_sender resolve
                    # it primary-first, which would pick a group -- and so a
                    # decrypt key AND a wire format -- on map-ordering alone.
                    if len(self._groups_containing(from_addr)) > 1:
                        self._boundary_refuse(
                            'group_spans_gateway', from_addr,
                            'sender is a member of more than one group we hold')
                        continue
                    sender_group = self._group_for_sender(from_addr)
                    if sender_group is not None:
                        from_whom = self.peers.find_by_address(from_addr)
                        try:
                            decrypt_msg = sender_group.decrypt(raw_msg, sender_group)
                            if from_whom is not None:
                                # The group that decrypted it names the format
                                # it is encoded in (doc/architecture/network-wire-format.md) -- for a gateway that
                                # is the child cohort's format, not its own.
                                self._msg_to_queue(decrypt_msg, from_whom, queues, 'group',
                                                   wire_format=sender_group.wire_format)
                            else:
                                _probes.counter('net.group', 'drop', 'sender_not_in_peers')
                                self.logger.warning(
                                    'Recvd transmission from %s - not in peers. Ignoring.', from_addr)
                                self.logger.debug('Ignored payload: %d bytes from %s', len(raw_msg), from_addr)
                        except nacl.exceptions.CryptoError as e:
                            _probes.counter('net.group', 'drop', 'crypto_error')
                            name = from_addr
                            if from_whom is not None:
                                name = '%s (%s)' % (from_whom.nickname, name)
                            count = self._crypto_error_counts.get(name, 0) + 1
                            self._crypto_error_counts[name] = count
                            if count == 1 or count % 10 == 0:
                                self.logger.error('CryptoError decrypting message from %s (count: %d)', name, count)
                    else:
                        _probes.counter('net.group', 'drop', 'sender_not_in_group')
                        self.logger.error('Recvd transmission from %s - not in group. Ignoring.', from_addr)
                        self.logger.debug('Ignored payload: %d bytes from %s', len(raw_msg), from_addr)
                        # Forward a partition-recovery signal to IdentityProcess
                        # so it can probe the foreign group and, if larger,
                        # initiate a normal request_access against it. The
                        # actual merge runs through the existing _merge_to_mesh
                        # path; this signal only kicks the probe.
                        #   See doc/architecture/partition-recovery.md §5.1.
                        self._signal_partition(queues, from_addr)
                total_inbound += drained_grp

                # async recv stranger messages (separate channel)
                drained_unk = 0
                while drained_unk < INBOUND_BUDGET:
                    try:
                        raw_msg, from_addr = self.unknown_messages.popleft()
                    except IndexError:
                        break
                    drained_unk += 1
                    # Reputation cut-off: ignore an excluded peer even on
                    # the stranger/multicast channel.
                    if self.reject_message(from_addr):
                        _probes.counter('net.multicast', 'drop', 'excluded')
                        continue
                    # The stranger/multicast channel is discovery, so JSON
                    # unconditionally (doc/architecture/network-wire-format.md) -- there is no group to consult.
                    self._msg_to_queue(raw_msg, from_addr, queues, 'multicast', validate=False)
                total_inbound += drained_unk

                _probes.counter('proc.network', 'iter_drained', str(total_inbound))
            except Exception as err:
                self.logger.error(err)
                self.logger.error(traceback.format_exc())

        self.stop = True
        self.close_connections()
        self.close_listeners()
        # The PingAT server holds a bound port too, and only the diplomat
        # branch above ever stopped it -- so a node that was the diplomat at
        # shutdown left it bound for the life of the process. That denies the
        # port to the next node on this address (no SO_REUSEADDR on it, by
        # design), which is only invisible when the process exits immediately
        # afterward and the kernel cleans up.
        # getattr, like close_listeners above: this runs on the way out of
        # process(), which partial instances also reach.
        ping_server = getattr(self, 'ping_at_server', None)
        if ping_server is not None:
            ping_server.stop()
            self.ping_at_server = None
