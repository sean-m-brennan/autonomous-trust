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
from ..identity.protocol import IdentityProtocol, UNENCRYPTED_VERBS
from ..processes import Process, ProcMeta
from .. import _probes
from ..identity import Group
from ..system import (CfgIds, PortSource, comm_port, net_cadence, resolve_comm_port,
                      default_annoy_limit, default_mystery_max_age_s, default_recv_poll_ms,
                      resolve_annoy_limit, resolve_mystery_max_age_s, resolve_recv_poll_ms)
from ..config import NetWireFormat
from .network import Network
from .message import Message, WireFormatMismatch
from .ping_at import PingATServer, ping_at


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
        self.stop = False
        self.statistics = {}
        self._rejected_addresses: set[str] = set()
        self._crypto_error_counts: dict[str, int] = {}
        # Per-address count of frames dropped for arriving in a wire format
        # this context does not speak. Rate-limits the log the same way
        # _crypto_error_counts does; the probe counter is unconditional.
        self._foreign_format_counts: dict[str, int] = {}
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
        return grp.wire_format if grp is not None else NetWireFormat.json

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

    def handle_exclude(self, queues, message):
        """Exclude a peer's address (reputation cut-off): its inbound
        frames are dropped and it is filtered out of outbound targets.
        Fed by ReputationProcess._publish_exclusion. Local IPC only."""
        addr = self._norm_addr(getattr(message, 'obj', None))
        if addr:
            self._rejected_addresses.add(addr)
            _probes.counter('net.exclude', 'add')
            self.logger.info('Reputation cut-off: excluding %s', addr)
        return True

    def handle_readmit(self, queues, message):
        """Reverse an exclusion (explicit rehabilitation). Local IPC."""
        addr = self._norm_addr(getattr(message, 'obj', None))
        if addr:
            self._rejected_addresses.discard(addr)
            _probes.counter('net.exclude', 'remove')
            self.logger.info('Reputation readmit: %s', addr)
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
                if peer is not None:
                    decrypt_msg = self.myself.decrypt(raw_msg, peer)
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
                      wire_format=NetWireFormat.json):
        try:
            message = Message.parse(msg, from_whom, validate=validate,
                                    wire_format=wire_format)
        except WireFormatMismatch as err:
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
        threading.Thread(target=self.unknown_receiver, daemon=True).start()
        threading.Thread(target=self.mystery_handler, args=(queues,), daemon=True).start()
        while self.keep_running(signal):
            try:
                self.reap_idle_conns()
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
                                    try:
                                        self.send_peer(msg, address)
                                        self.track_send_stats(who.uuid, len(msg))
                                    except TransmissionError as err:
                                        self.logger.error('Network: %s', err)
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
                            self._msg_to_queue(raw_msg, from_addr, queues, 'point-to-point', validate=False)
                            _probes.counter('net.ptp', 'unknown_sender', 'parsed_unencrypted')
                        except UnicodeDecodeError:
                            _probes.counter('net.ptp', 'unknown_sender', 'deferred_encrypted')
                            self.logger.debug('Out-of-order message from %s detected, retry later', from_addr)
                            # Stamp the deferral time here, as C does in
                            # defer_message: the age-out window runs from when
                            # the message was deferred, not from when the
                            # handler happens to look at it. Monotonic, so a
                            # clock step cannot age the queue out at once.
                            self.encrypted_messages.append((raw_msg, from_addr, time.monotonic()))
                total_inbound += drained_ptp

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
