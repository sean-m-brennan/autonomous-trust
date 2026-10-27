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
import socket
import threading
import time
import traceback
import uuid as _uuid_mod
from collections import deque
from datetime import datetime
from queue import Empty, Full
from enum import Enum

import nacl

from ..protocol import Protocol
from ..identity import Identity
from ..identity.identity import public_identity_to_canonical
from ..identity.protocol import IdentityProtocol, BOOTSTRAP_VERBS
from ..plaintext_verbs import is_broadcast, is_unencrypted
from ..app_verbs import is_local_app_verb, refuse_remote_app_verb
from ..processes import Process, ProcMeta
from ..extensions import (configure_plaintext_verbs, load_extensions,
                          network_hooks, network_wire_verbs, process_alias,
                          run_post_fork)
from .. import _probes
from ..identity import Group
from ..identity.peers import strip_cidr
from ..system import (CfgIds, PortSource, comm_port, net_cadence, resolve_comm_port,
                      default_annoy_limit, default_mystery_max_age_s, default_recv_poll_ms,
                      resolve_annoy_limit, resolve_mystery_max_age_s, resolve_recv_poll_ms)
from ..config import NetWireFormat
from .network import Network
from .message import Message, WireFormatMismatch
from .ping_at import PingATServer, ping_at
from .liveness import TransportLiveness
from .presence import PRESENCE_FUNCTION, PRESENCE_PROCESS, PresenceTracker

#: ReputationProtocol.app_roster_request (C AT_APP_ROSTER_REQUEST), spelled out:
#: importing the reputation package from here would be circular.
app_roster_request = 'app_roster_request'


#: The receive paths _msg_to_queue tells apart (ISSUES §2.17). Mirrors C
#: net_route_path_t.
PATH_PEER = 'peer'
PATH_STRANGER = 'stranger-plaintext'
PATH_RELAY_STRANGER = 'relayed-stranger'
PATH_BROADCAST = 'broadcast'
PATH_GROUP = 'group'

# Group frames held for a key change (NetProcess._hold_group_frame); the same
# bounds as C's NET_HELD_GROUP_FRAMES / NET_HELD_GROUP_FRAME_SEC.
NET_HELD_GROUP_FRAMES = 16
NET_HELD_GROUP_FRAME_SEC = 10


def wire_verb_admitted(process, function, path):
    """``(True, None)`` when a wire frame for ``process`` / ``function`` may be
    routed after arriving on ``path``, else ``(False, reason)``.

    Never an ``app_*`` verb (the local app's commands, which never travel),
    never a command to the network process but a remote stats_req (and the
    verbs an extension declares, from a peer or the group only), and from a
    sender we do not hold only the plaintext verbs (or, on the broadcast
    channel, the broadcast ones). Checked on the frame's NAMES, never on its
    claimed sender, which a stranger chooses. Mirrors C net_wire_verb_admitted.
    """
    if not isinstance(process, str) or not isinstance(function, str):
        return False, 'no process or function'
    if function.startswith('app_'):
        return False, "app verbs are the local app's and never travel"
    if process == CfgIds.network and function != Network.stats_req and not (
            path in (PATH_PEER, PATH_GROUP) and function in network_wire_verbs()):
        return False, 'the network process takes only stats_req from the wire'
    if path in (PATH_STRANGER, PATH_RELAY_STRANGER) and not is_unencrypted(function):
        return False, 'not a plaintext verb, and the sender is not a peer we hold'
    if path == PATH_BROADCAST and not is_broadcast(function):
        return False, 'not a verb the broadcast channel carries'
    return True, None


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
        # Admissions this node is partway through as the JOINER: admitter
        # address -> monotonic deadline, set when its access_granted arrives,
        # and the outbound frames held for it meanwhile (_hold_for_admission).
        self._admission_pending = {}
        self._held_for_admission = deque()
        self.group_messages = deque()
        # Group frames that did not open, kept for a key change
        # (_hold_group_frame).
        self._held_group_frames = deque()
        self.unknown_messages = deque()
        # Transport liveness holds a lock and this instance is pickled across
        # the fork, so the tracker is created in process(). _via_ext marks a
        # frame an extension injected, which never stamps it. It is per
        # thread (the receivers and mystery_handler route frames while the
        # main loop injects), held in a threading.local that also cannot be
        # pickled, so it too is created in process().
        self._liveness = None
        self._via_ext_tls = None
        self.acceptance = acceptance_func
        self.pests = {}
        self.protocol = Protocol(self.name, self.logger, configurations)
        # Reputation cut-off enforcement: ReputationProcess feeds
        # exclude/readmit control messages here as peers cross the
        # communication cut-off. See handle_exclude / handle_readmit and
        # the inbound-drop / outbound-forward gates below.
        self.protocol.register_handler(Network.exclude, self.handle_exclude)
        self.protocol.register_handler(Network.readmit, self.handle_readmit)
        # The relay's local verbs (relay_route, reach_publish, the directory and
        # area-hub verbs) are registered by the rendezvous extension
        # (network/rendezvous.py) in load_extensions below.
        # Who reputation has cut off, by uuid and by signing key (hex), so a
        # distrusted relay or client gains nothing by claiming a new uuid.
        self._excluded_uuids = set()
        self._excluded_keys = set()
        # Rendezvous (network/rdv_net.py) and first contact keep their own
        # state here, set up as their extensions register.
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

    def rebind_socket_timeouts(self):
        """Give the bound receive sockets their timeout again, in the worker
        (see process()). A transport without them -- DTN, the hybrid -- has
        nothing to rebind; reading them inside the loop's tuple, outside any
        try, used to raise AttributeError there and end the network process."""
        for name in ('recv_ptp_sock', 'recv_grp_sock', 'recv_cast_sock'):
            sock = getattr(self, name, None)
            if sock is None:
                continue
            try:
                sock.settimeout(self.socket_timeout)
            except OSError:
                pass

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
        return strip_cidr(str(address))

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
            return public_identity_to_canonical(peer.publish())['signature']['hex_seed'].lower()
        except Exception:
            return None

    def _inbound_group(self, queues, raw_msg, from_addr, retry=False):
        """One group-channel frame. ``retry``: the frame was held after it did
        not open and is being tried under a new key; one that still does not
        open is dropped rather than held again. Twin of C _inbound_group."""
        # Reputation cut-off: drop an excluded sender's group
        # frame before decrypt/delivery (a gateway thus does
        # not relay it onward either).
        if self.reject_message(from_addr):
            _probes.counter('net.group', 'drop', 'excluded')
            return
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
            return
        sender_group = self._group_for_sender(from_addr)
        if sender_group is not None:
            from_whom = self.peers.find_by_address(from_addr)
            try:
                decrypt_msg = sender_group.decrypt(raw_msg, sender_group)
                if from_whom is not None:
                    # The group that decrypted it names the format
                    # it is encoded in (doc/architecture/network-wire-format.md) -- for a gateway that
                    # is the child cohort's format, not its own.
                    if retry:
                        self.logger.info('A held group frame from %s opened under '
                                         'the new key', from_addr)
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
                if retry:
                    self.logger.info('Held group frame from %s still does not open '
                                     'after a key change; dropped', name)
                else:
                    self._hold_group_frame(raw_msg, from_addr, sender_group)
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
            if getattr(self, '_via_ext', False):
                # Heard some other way (a radio): a foreign cohort's frame on
                # the air must not start partition recovery.
                _probes.counter('net.ext', 'group_decrypt_fail')
            else:
                self._signal_partition(queues, from_addr)

    @staticmethod
    def _group_key_fp(group):
        """Which key a group holds now: epoch and public key."""
        return (group.key_epoch, group.encryptor.publish()) if group is not None else None

    def _hold_group_frame(self, raw_msg, from_addr, group):
        """Keep a group frame that did not open under the key we hold, for
        NET_HELD_GROUP_FRAME_SEC, to try again once a different key is
        installed. Identity adopts a rotated key before the network process
        installs it, and a one-shot group send in that gap was lost for good
        (Stele tm-3882043, the team roster). The frame keeps whether an
        extension injected it, so its retry is still marked so. Twin of C
        _hold_group_frame; oldest dropped past NET_HELD_GROUP_FRAMES."""
        self._held_group_frames.append(
            (raw_msg, from_addr, time.monotonic(), self._group_key_fp(group),
             bool(getattr(self, '_via_ext', False))))
        while len(self._held_group_frames) > NET_HELD_GROUP_FRAMES:
            self._held_group_frames.popleft()

    def _retry_held_group_frames(self, queues) -> int:
        """Try again every held group frame whose sender's group now holds a
        different key; drop those held past NET_HELD_GROUP_FRAME_SEC. Called
        every pass of the main loop. Returns how many were retried. Twin of C
        net_retry_held_group_frames."""
        if not self._held_group_frames:
            return 0
        now_s = time.monotonic()
        due, kept, aged = [], deque(), 0
        for held in self._held_group_frames:
            _raw, from_addr, held_at, fp, _ext = held
            if self._group_key_fp(self._group_for_sender(from_addr)) != fp:
                due.append(held)
            elif now_s - held_at >= NET_HELD_GROUP_FRAME_SEC:
                aged += 1
            else:
                kept.append(held)
        self._held_group_frames = kept
        if aged:
            self.logger.info('Dropped %d held group frame(s): no new key in %d s',
                             aged, NET_HELD_GROUP_FRAME_SEC)
        if due:
            self.logger.info('Retrying %d held group frame(s) under a new key', len(due))
        was = getattr(self, '_via_ext', False)
        try:
            for raw_msg, from_addr, _at, _fp, via_ext in due:
                # An injected frame stays injected: no liveness stamp and no
                # partition signal on its retry either.
                self._via_ext = via_ext
                self._inbound_group(queues, raw_msg, from_addr, retry=True)
        finally:
            self._via_ext = was
        return len(due)

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
            self._tell_exclusion(uuid, True)
        return True

    @property
    def _via_ext(self) -> bool:
        """Whether the frame this thread is routing was injected by an
        extension. Twin of C's thread-local _net_ext_inbound."""
        tls = self.__dict__.get('_via_ext_tls')
        return bool(getattr(tls, 'on', False))

    @_via_ext.setter
    def _via_ext(self, value) -> None:
        tls = self.__dict__.get('_via_ext_tls')
        if tls is None:
            # Only a stand-in that never ran process() gets here.
            tls = self.__dict__['_via_ext_tls'] = threading.local()
        tls.on = bool(value)

    def _note_transport_heard(self, peer_uuid, rcvd_by=None) -> None:
        """Stamp transport liveness, unless this frame was injected by an
        extension (``_via_ext``) or relayed by a rendezvous (``rcvd_by`` is
        'relay'): neither came through the transport. Twin of C
        route_to_process's stamp, which handle_inbound_relayed suppresses."""
        lv = getattr(self, '_liveness', None)
        if lv is not None and rcvd_by != 'relay' \
                and not getattr(self, '_via_ext', False):
            lv.heard(peer_uuid, time.monotonic())

    def transport_quiet_for(self, peer_uuid) -> float:
        """Seconds since ``peer_uuid`` was last heard through the transport,
        or since the network process started for a peer never heard; 0.0
        before it starts. Twin of C net_liveness_quiet_for."""
        lv = getattr(self, '_liveness', None)
        return 0.0 if lv is None else lv.quiet_for(peer_uuid, time.monotonic())

    def is_excluded(self, uuid, pubkey_hex=None) -> bool:
        """Whether reputation cut ``uuid`` off, or the peer holding the key
        ``pubkey_hex``, and has not readmitted it. Recorded by uuid and by the
        key held for the peer at the time, so a distrusted peer gains nothing
        by claiming a new uuid. Mirrors C's net_is_excluded."""
        key = str(pubkey_hex or '').lower()
        return (str(uuid).lower() in self._excluded_uuids
                or (key != '' and key in self._excluded_keys))

    def _tell_exclusion(self, uuid, excluded) -> None:
        for hooks in network_hooks(self):
            if hooks.on_exclusion is not None:
                hooks.on_exclusion(self, uuid, excluded)

    def _unicast_carrier(self, peer_uuid):
        """The NetworkHooks that carry a unicast to ``peer_uuid``, or None for
        the transport."""
        for hooks in network_hooks(self):
            if hooks.reaches is not None and hooks.unicast is not None \
                    and hooks.reaches(self, peer_uuid):
                return hooks
        return None

    def _also_unicast(self, peer_uuid, process, function, frame) -> None:
        """Every extension that watches transport unicasts sees this one. A
        hook that raises is logged and ignored: it never stops the send."""
        for hooks in network_hooks(self):
            if hooks.also_unicast is None:
                continue
            try:
                hooks.also_unicast(self, peer_uuid, frame, process, function)
            except Exception as err:  # noqa: BLE001 -- isolation is the point
                self.logger.error('Network: also_unicast hook failed: %s', err)

    def _fanout(self, channel, process, function, group, frame) -> None:
        """Every extension that watches group/broadcast sends sees this one,
        after the transport was asked to send it, whether or not that
        succeeded: a fallback radio is for when the transport fails. A
        broadcast whose send raises BrokenPipeError never gets here. A hook
        that raises is logged and ignored."""
        for hooks in network_hooks(self):
            if hooks.fanout is None:
                continue
            try:
                hooks.fanout(self, channel, frame, process, function, group)
            except Exception as err:  # noqa: BLE001
                self.logger.error('Network: fanout hook failed: %s', err)

    def inject_inbound(self, queues, channel, frame, peer_uuid) -> bool:
        """Deliver a frame an extension received some other way (a radio) on
        ``channel`` ('peer', 'group' or 'broadcast'), attributed to the peer
        ``peer_uuid`` we hold. The frame does not stamp transport liveness
        (``_via_ext``), and a group frame from a sender outside our group is
        counted, never a partition signal. Returns True when handed on.
        Twin of C handle_inbound_ext."""
        try:
            peer = self.peers.find_by_uuid(_uuid_mod.UUID(str(peer_uuid)))
        except ValueError:
            peer = None
        if peer is None:
            _probes.counter('net.ext', 'drop', 'unknown_peer')
            return False
        if self.reject_message(peer.address) or self.is_excluded(peer.uuid):
            _probes.counter('net.ext', 'drop', 'excluded')
            return False
        # Restored, not cleared: a hook may inject while this thread is
        # already routing an injected frame.
        was = self._via_ext
        self._via_ext = True
        try:
            if channel == 'peer':
                fmt = self._wire_format_for_addr(peer.address)
                try:
                    plain = self.myself.decrypt(frame, peer)
                except Exception:  # noqa: BLE001 -- maybe a plaintext verb
                    return bool(self._accept_unencrypted(frame, peer, queues,
                                                         wire_format=fmt))
                self._msg_to_queue(plain, peer, queues, 'relay', wire_format=fmt)
                return True
            if channel == 'group':
                if self._group_for_sender(peer.address) is None:
                    _probes.counter('net.ext', 'group_decrypt_fail')
                    return False
                self._inbound_group(queues, frame, peer.address)
                return True
            if channel == 'broadcast':
                self._msg_to_queue(frame, peer.address, queues, 'multicast',
                                   validate=False)
                return True
            raise ValueError('unknown channel %r' % (channel,))
        finally:
            self._via_ext = was

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
            self._tell_exclusion(uuid, False)
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
                # Not routed: a known peer we still cannot place, whose frame
                # is in a format we cannot read yet (_route_decrypted).
                if decrypt_msg is not None and self._route_decrypted(
                        decrypt_msg, peer, from_addr, queues):
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

    def _route_decrypted(self, plain, peer, from_addr, queues) -> bool:
        """Route a point-to-point frame that decrypted from a known *peer*.
        Returns False, having routed nothing, when the caller should defer it.

        A peer we can place in a group we hold speaks that group's format, and
        a refusal there is a foreign-format drop like any other. A peer we
        cannot place yet is read as JSON, and the one legitimate sender of
        anything else is our admitter: the moment it admits us it is talking
        its cohort's format, while we learn that format only when our group
        arrives a beat later. So on that path a refusal defers the frame, to
        be read in the group's format once the sender can be placed, or
        reclaimed by the out-of-order queue's age bound if it never can. The
        foreign parser is still never run over the bytes: deferral re-reads
        them only after a group says which format they are in.
        """
        if self._group_for_sender(from_addr) is not None:
            self._msg_to_queue(plain, peer, queues, 'point-to-point',
                               wire_format=self._wire_format_for_addr(from_addr))
            return True
        try:
            self._msg_to_queue(plain, peer, queues, 'point-to-point', opaque=True)
        except WireFormatMismatch:
            _probes.counter('net.wire', 'defer', 'unplaced_peer')
            return False
        return True

    def _note_admission(self, message, from_addr):
        """An access_granted from a sender we cannot place: we are being
        admitted, and until our group arrives we cannot know the format the
        admitter now expects from us. Point-to-point traffic to it is held
        (_hold_for_admission) until it can be placed, or until the
        out-of-order age bound passes, after which it goes as the lookup says."""
        if (message.process != CfgIds.identity
                or message.function != IdentityProtocol.accept):
            return
        addr = strip_cidr(str(from_addr))
        if self._group_for_sender(addr) is None:
            self._admission_pending[addr] = time.monotonic() + self.mystery_max_age_s

    def _admission_settled(self, addr) -> bool:
        """True once a pending admission from *addr* is over: the admitter can
        be placed in a group we hold, or the wait has run out."""
        deadline = self._admission_pending.get(addr)
        if deadline is None:
            return True
        if self._group_for_sender(addr) is not None or time.monotonic() >= deadline:
            self._admission_pending.pop(addr, None)
            return True
        return False

    def _hold_for_admission(self, message, who, address) -> bool:
        """Hold a non-bootstrap frame to an admitter whose admission of us is
        still settling. Sent now it would be JSON, and the admitter, which
        already counts us as a member of its cohort, expects that cohort's
        format. Bootstrap is JSON by rule and is never held."""
        if message.function in BOOTSTRAP_VERBS or self._admission_settled(address):
            return False
        _probes.counter('net.ptp', 'hold', 'admission_pending')
        self._held_for_admission.append((message, who))
        return True

    def _release_admission_holds(self, queues):
        """Send, in order, the held frames whose admission has settled. Runs
        before each new outbound message, so a held frame never goes out after
        one queued behind it."""
        if not self._held_for_admission:
            return
        still = deque()
        while self._held_for_admission:
            message, who = self._held_for_admission.popleft()
            address = strip_cidr(who.address)
            if not self._admission_settled(address) or any(
                    strip_cidr(w.address) == address for _m, w in still):
                still.append((message, who))
                continue
            try:
                self._unicast(message, who)
            except BrokenPipeError as err:
                self.logger.error('Network: %s', err)
        self._held_for_admission = still

    def _accept_unencrypted(self, raw_msg, from_whom, queues,
                            wire_format=NetWireFormat.json):
        """Deliver a plaintext frame from a KNOWN peer, but only an allowlisted
        verb that declares itself unencrypted.

        Three conditions, all required: the bytes parse as an envelope, the
        envelope's own `encrypt` flag is false, and the verb is accepted in
        plaintext (:func:`..plaintext_verbs.is_unencrypted`: the core's own, or
        one unencrypted_verbs.cfg.json grants a loaded extension). A frame that merely fails to decrypt is NOT accepted
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
        if not is_unencrypted(verb):
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

        # ISSUES §2.17: what this frame may carry, by the path it came in on.
        # A stranger's from_whom is an address (or 'relay:<uuid>'), never an
        # Identity; on the multicast channel anyone may speak.
        if rcvd_by == 'multicast':
            path = PATH_BROADCAST
        elif rcvd_by == 'group':
            path = PATH_GROUP
        elif isinstance(from_whom, Identity):
            path = PATH_PEER
        elif rcvd_by == 'relay':
            path = PATH_RELAY_STRANGER
        else:
            path = PATH_STRANGER

        # Every frame from the wire is routed here, so this is where a peer is
        # heard (doc/architecture/peer-presence.md). A uuid not on the roster
        # is ignored by the tracker. A presence frame has said everything it
        # carries by arriving: consumed here, never routed. Transport liveness
        # is stamped only on the member paths, where the sender is a peer we
        # hold: a stranger or the broadcast channel names any uuid it likes.
        sender = from_whom if isinstance(from_whom, Identity) \
            else getattr(message, 'from_whom', None)
        presence = getattr(self, '_presence', None)
        if presence is not None:
            presence.heard(getattr(sender, 'uuid', None), time.time())
        if path in (PATH_PEER, PATH_GROUP):
            self._note_transport_heard(getattr(sender, 'uuid', None), rcvd_by)
        if message.process == PRESENCE_PROCESS and message.function == PRESENCE_FUNCTION:
            self.logger.debug('Presence from %s', from_addr)
            return

        admitted, why = wire_verb_admitted(message.process, message.function, path)
        if not admitted:
            _probes.counter('net.dispatch', 'refused', path)
            self._route_refusals = getattr(self, '_route_refusals', 0) + 1
            n = self._route_refusals
            if n <= 20 or n % 100 == 0:
                self.logger.info('Refusing %s.%s from %s on the %s path: %s '
                                 '(%d refused)', message.process,
                                 message.function, from_addr, path, why, n)
            return

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
            if rcvd_by != 'multicast':
                self._note_admission(message, from_addr)

        # Deliver to any known process queue, not just subsystems.
        # Cross-instance request/response patterns (e.g. an inspector
        # bridge soliciting peer-to-peer reputation: rep_req carries
        # req_proc='main', the peer's rep_resp comes back addressed to
        # 'main') need 'main' as a valid destination. Restricting to
        # subsystems silently dropped those responses with "Recvd
        # message for unknown main process".
        target = message.process
        if target not in queues:
            # A C process Python runs inside another one (ZTA's zta_verify
            # rides identity): renamed, since a handler answers only frames
            # addressed to its own process.
            alias = process_alias(target)
            if alias in queues:
                message.process = target = alias
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

    def _emit_presence(self, queues, presence):
        """Hand one :class:`PeerPresence` to negotiation (which stops or resumes
        inviting the peer) and to main (which forwards it to the app, as for
        any AppEvent). Best effort per queue, like :meth:`update`."""
        for name in (CfgIds.negotiation, CfgIds.main):
            if name not in queues:
                continue
            try:
                queues[name].put(presence, block=True, timeout=self.q_cadence)
            except Full:
                _probes.counter('net.presence', 'queue_full', name)

    def _emit_all_presence(self, queues):
        """The presence half of the app's roster pull: every peer, to main."""
        if CfgIds.main not in queues:
            return
        for row in self._presence.snapshot([p.uuid for p in self.peers.all]):
            try:
                queues[CfgIds.main].put(row, block=True, timeout=self.q_cadence)
            except Full:
                _probes.counter('net.presence', 'queue_full', CfgIds.main)

    def _presence_step(self, queues):
        """Once a second: evaluate presence, tell negotiation and the app what
        changed, and when this node has been silent toward some member for the
        heartbeat interval, queue one presence frame to the group. It goes out
        through our own queue so it takes exactly the path of any other group
        message. A node without the group's private key cannot send one, and
        has nothing to say to a roster of none. Mirrors C net_presence_step."""
        now_s = time.time()
        if int(now_s) == self._presence_last_step:
            return
        self._presence_last_step = int(now_s)
        members = list(self.peers.all)
        due, changes = self._presence.tick([p.uuid for p in members], now_s)
        for change in changes:
            if change.present:
                self.logger.info('Network: peer %s is present again', change.peer_uuid[:8])
            else:
                self.logger.info('Network: peer %s is absent: nothing heard for %.0f s (last %s)',
                                 change.peer_uuid[:8], self._presence.absent_sec,
                                 'frame recorded' if change.last_heard else 'none ever')
            self._emit_presence(queues, change)
        group = self.group
        if not due or not members or group is None or getattr(group, '_public_only', True):
            return
        beat = Message(PRESENCE_PROCESS, PRESENCE_FUNCTION, '', to_whom=group)
        try:
            # One try: a full queue means traffic is going out anyway, and the
            # next second asks again. Stamped on success so a slow drain cannot
            # queue one heartbeat per second.
            queues[self.name].put(beat, block=False)
            self._presence.sent(None, now_s)
        except Full:
            pass

    def _unicast(self, message, who):
        """Send *message* point-to-point to one recipient *who*."""
        address = strip_cidr(who.address)
        # Gateway boundary, invariant B: the pre-admission handshake stays
        # inside the domain it started in.
        if (message.function in BOOTSTRAP_VERBS
                and self._crosses_gateway(address)):
            self._boundary_refuse(
                'bootstrap_across_gateway', address,
                'refusing to send %s to a cohort we '
                'gateway' % message.function)
            return
        # Reputation cut-off: skip an excluded recipient.
        if self.reject_message(address):
            _probes.counter('net.ptp', 'skip', 'excluded_target')
            return
        # Held while an admission of us settles; released in order by
        # _release_admission_holds once we can say which format to use.
        if self._hold_for_admission(message, who, address):
            return
        # A peer we can place speaks its group's format; one we cannot place
        # gets JSON, which is what makes pre-admission traffic work in a proto
        # cohort (doc/architecture/network-wire-format.md).
        wire = message.to_wire(self._wire_format_for_addr(address))
        if message.encrypt:
            msg = self.myself.encrypt(wire, who)
        else:
            msg = wire
        # An extension that reaches `who` some other way (rendezvous: behind
        # a relay) carries it; the frame is already sealed.
        carrier = self._unicast_carrier(who.uuid)
        try:
            if carrier is not None:
                carrier.unicast(self, who.uuid, msg)
            else:
                self._also_unicast(who.uuid, message.process,
                                   message.function, msg)
                self.send_peer(msg, address)
            self.track_send_stats(who.uuid, len(msg))
            self._presence.sent(who.uuid, time.time())
        except TransmissionError as err:
            self.logger.error('Network: %s', err)
            self.track_send_error(who.uuid)
        except (OSError, ConnectionError) as err:
            # Only a carried send is caught here; a direct one raises as it
            # always has.
            if carrier is None:
                raise
            self.logger.error('Network: relay: %s', err)
            self.track_send_error(who.uuid)

    def _send_to_group_members(self, msg, addresses):
        """Send one encrypted group frame to each member address.

        A member that cannot be reached costs only its own copy. In
        particular an address that fails to resolve (a container hostname
        whose container has not started yet raises socket.gaierror, an
        OSError) must not stop the fan-out to the members after it."""
        for addr in addresses:
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
                member = self.peers.find_by_address(addr)
                if member is not None:
                    self._presence.sent(member.uuid, time.time())
            except (TransmissionError, OSError) as err:
                self.logger.error('Network: group send to %s failed: %s',
                                  addr, err)
                self.track_send_error(self.unknown_peer)

    def _send_broadcast_message(self, message):
        """Send one outbound broadcast Message, then show it to the fanout
        hooks whether or not the transport send succeeded. A BrokenPipeError
        propagates to the caller and skips the hooks."""
        # Broadcast is discovery: it goes to nodes we
        # cannot place in any group, so JSON
        # unconditionally (doc/architecture/network-wire-format.md). `bytes(message)` IS
        # the JSON form.
        msg = bytes(message)
        try:
            self.send_any(msg)
            self.track_send_stats(self.unknown_peer, len(msg))
            self._presence.sent(None, time.time())
        except TransmissionError as err:
            self.logger.error('Network: %s', err)
            self.track_send_error(self.unknown_peer)
        self._fanout('broadcast', message.process, message.function,
                     self.group, msg)

    def _send_group_message(self, message):
        """Seal one outbound group Message, send it to each member, then show
        it to the fanout hooks with the group whose key sealed it."""
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
        self._send_to_group_members(msg, message.to_whom.addresses)
        self._fanout('group', message.process, message.function,
                     enc_grp, msg)

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
        # The receive policy's optional half (unencrypted_verbs.cfg.json): the
        # node's start already checked it (extensions.check_config), but module
        # state does not survive the forkserver, so apply it again here.
        configure_plaintext_verbs(logger=self.logger)
        # Re-establish receiver-socket timeouts here, in the worker
        # subprocess. The sockets are created in __init__ (which runs
        # in the parent) and transferred via fd-passing during the
        # forkserver pickle. The OS-level non-blocking flag survives,
        # but the Python-level timeout tracking does not — without
        # this rebinding, recvfrom raises BlockingIOError on the very
        # first call. (Surfaced 2026-05-01 by tests/diag/harness.py.)
        self.rebind_socket_timeouts()
        self._init_transport()
        # Created here, in the worker, not in __init__: the instance is pickled
        # across the fork and the tracker holds a lock.
        self._presence = PresenceTracker()
        self._liveness = TransportLiveness(time.monotonic())
        self._via_ext_tls = threading.local()
        self._presence_last_step = 0
        self.start_receivers(queues)
        for hooks in network_hooks(self):
            if hooks.on_start is not None:
                hooks.on_start(self, queues)
        threading.Thread(target=self.unknown_receiver, daemon=True).start()
        threading.Thread(target=self.mystery_handler, args=(queues,), daemon=True).start()
        while self.keep_running(signal):
            try:
                self.reap_idle_conns()
                self._presence_step(queues)
                self._release_admission_holds(queues)
                for hooks in network_hooks(self):
                    if hooks.periodic is not None:
                        hooks.periodic(self, queues)
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
                            if (message.function == app_roster_request
                                    and message.process == CfgIds.network):
                                # The app's roster pull, presence half. Local
                                # only: never leaves on the wire, and never
                                # taken from it (ISSUES §2.17).
                                if is_local_app_verb(self, message):
                                    self._emit_all_presence(queues)
                                else:
                                    refuse_remote_app_verb(self, message,
                                                           message.function)
                            elif message.function == Network.stats_req:
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
                                self._send_broadcast_message(message)
                            elif isinstance(message.to_whom, Group):
                                self._send_group_message(message)
                            else:  # defaults to pseudo-multicast
                                for who in message.to_whom:  # Message ensures this is list  # noqa
                                    self._unicast(message, who)
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
                            if not self._route_decrypted(decrypt_msg, from_whom, from_addr, queues):
                                self.encrypted_messages.append(
                                    (raw_msg, from_addr, time.monotonic()))
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
                for hooks in network_hooks(self):
                    if hooks.drain_inbound is not None:
                        total_inbound += hooks.drain_inbound(self, queues,
                                                             INBOUND_BUDGET)

                # async recv group messages; first, any held for a key change
                self._retry_held_group_frames(queues)
                drained_grp = 0
                while drained_grp < INBOUND_BUDGET:
                    if self.group is None:
                        break  # otherwise, skip for now
                    try:
                        raw_msg, from_addr = self.group_messages.popleft()
                    except IndexError:
                        break
                    drained_grp += 1
                    self._inbound_group(queues, raw_msg, from_addr)
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
