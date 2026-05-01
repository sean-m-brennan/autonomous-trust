# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
from ..processes import Process, ProcMeta
from .. import _probes
from ..identity import Group
from ..system import CfgIds, comm_port, net_cadence
from .network import Network
from .message import Message
from .ping import PingServer, ping


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
    annoy_limit = 5
    net_proto = NetworkProtocol.NONE
    mystery_max_retries = 60  # 30 seconds
    socket_timeout = 0.1
    unknown_peer = '0'

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, **kwargs):
        super().__init__(configurations, subsystems, log_q, **kwargs)
        self.net_cfg = configurations[CfgIds.network]
        port = self.net_cfg.port
        self.port = port
        if port is None:
            self.port = self.default_port  # noqa
        self.diplomat = True
        self.ping = None
        self.myself = configurations[CfgIds.identity]
        self.peer_messages = deque()
        self.encrypted_messages = deque()
        self.group_messages = deque()
        self.unknown_messages = deque()
        self.acceptance = acceptance_func
        self.pests = {}
        self.protocol = Protocol(self.name, self.logger, configurations)
        self.stop = False
        self.statistics = {}
        self._rejected_addresses: set[str] = set()
        self._crypto_error_counts: dict[str, int] = {}
        # Lazily created in process(). ThreadPoolExecutor can't be
        # pickled, so creating it here would break the multiprocessing
        # spawn handoff. See `_ensure_ping_pool`.
        self._ping_pool: concurrent.futures.ThreadPoolExecutor | None = None

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
        for uuid in self.statistics:
            elapsed = self.statistics[uuid].times[-1] - self.statistics[uuid].times[0]
            up, down = sum(self.statistics[uuid].send) / elapsed, sum(self.statistics[uuid].recv) / elapsed
            cumulative[uuid] = (up, down, self.statistics[uuid].send_total, self.statistics[uuid].recv_total,
                                self.statistics[uuid].err_out, self.statistics[uuid].err_in)
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

    def accept_peer_message(self, address):
        """
        Accept/reject messages based on sender's address
        :param address: Incoming sender
        :return: bool
        """
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

    def reject_message(self, address):
        """Check if an address has been blacklisted."""
        return address in self._rejected_addresses

    def blacklist_address(self, address):
        """Add an address to the rejection list."""
        self._rejected_addresses.add(address)

    def _ensure_ping_pool(self):
        """Lazily instantiate the ping thread pool inside the subprocess.
        Created on demand so it doesn't try to ride through a pickle
        handoff. Outbound pings dispatch here so the synchronous ping()
        function (which sleeps 1 s per packet × count) doesn't block the
        main process loop.
        """
        if self._ping_pool is None:
            self._ping_pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=16, thread_name_prefix='netproc-ping')
        return self._ping_pool

    def _do_ping_async(self, address, count, return_queue):
        """Run ping() in a worker thread and post stats back to the
        original requester's return queue. Errors are logged but not
        raised — a failed ping is just a missed RTT sample, not a
        process-fatal event.
        """
        try:
            stats = ping(address, count=count)  # noqa
            msg = Message(self.name, Network.ping, stats)  # noqa
            return_queue.put(msg, block=True, timeout=self.q_cadence)
        except TransmissionError as err:
            self.logger.error('Ping (async): %s' % err)
        except Full:
            self.logger.warning('Ping (async): return queue full, dropping stats')
        except Exception as err:
            self.logger.error('Ping (async) unexpected: %s' % err)

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
                self.logger.debug('Network: %s' % err)
                continue
            except TransmissionError as err:
                _probes.counter(layer, 'recv_error', 'transmission')
                self.logger.error('Network: %s' % err)
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
                # Belt-and-suspenders: a single malformed frame should
                # not kill the listener thread for the rest of the run.
                # (Used to lose every subsequent inbound after the first
                # encrypted message because tcp._recv .decode'd raw
                # bytes and crashed the thread.)
                _probes.counter(layer, 'recv_error', err.__class__.__name__)
                self.logger.error('Network recv crashed: %s' % err)
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
                self.logger.error('Network: %s' % err)
                continue
            except TimeoutError:
                continue
            except BlockingIOError:
                _probes.counter('net.recv.any', 'recv_error', 'blocking_io')
                time.sleep(self.socket_timeout)
                continue
            except Exception as err:
                # Mirror _encr_recv: never let a malformed inbound kill
                # the listener thread for the rest of the run.
                _probes.counter('net.recv.any', 'recv_error', err.__class__.__name__)
                self.logger.error('Network recv_any crashed: %s' % err)
                continue
            if raw_msg is not None:
                self.unknown_messages.append((raw_msg, from_addr))

    def mystery_handler(self, queues):
        """
        Handle encrypted messages sent before the peer is known
        :return: None
        """
        try_count = {}
        while not self.stop:
            remaining = deque()
            while True:
                try:
                    raw_msg, from_addr = self.encrypted_messages.popleft()
                except IndexError:
                    break
                peer = self.peers.find_by_address(from_addr)
                if peer is not None:
                    decrypt_msg = self.myself.decrypt(raw_msg, peer)
                    self._msg_to_queue(decrypt_msg, peer, queues, 'point-to-point')
                    _probes.counter('net.mystery', 'resolved')
                    _probes.emit('net.mystery', 'resolved',
                                 from_addr=from_addr,
                                 peer_uuid=str(peer.uuid),
                                 retries=try_count.get(from_addr, 0))
                    self.logger.debug('Out-of-order message from %s handled' % peer.nickname)
                else:
                    if from_addr not in try_count:
                        try_count[from_addr] = 0
                    try_count[from_addr] += 1
                    if try_count[from_addr] > self.mystery_max_retries:
                        _probes.counter('net.mystery', 'drop', 'max_retries')
                        _probes.emit('net.mystery', 'aged_out',
                                     from_addr=from_addr,
                                     retries=try_count[from_addr])
                        self.logger.debug('Spurious encrypted message from %s dropped' % from_addr)
                    else:
                        remaining.append((raw_msg, from_addr))
            self.encrypted_messages.extend(remaining)
            time.sleep(self.cadence + self.q_cadence)  # curiously, does not sleep if exactly cadence

    def _msg_to_queue(self, msg, from_whom, queues, rcvd_by, validate=True):
        try:
            message = Message.parse(msg, from_whom, validate=validate)
        except TypeError as err:
            _probes.counter('net.parse', 'drop', 'type_error')
            self.logger.error('Error parsing %s: %s' % (msg, err))
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
                self.logger.debug('Recvd %s message for %s:%s from %s' %
                                  (rcvd_by, target, message.function, from_addr))
            except Full:
                _probes.counter('net.dispatch', 'queue_full', target)
                _probes.trace_msg(message, 'queue_full', target=target)
                self.logger.error('Network: %s queue is full' % target)
        else:
            _probes.counter('net.dispatch', 'unknown_target', target)
            _probes.trace_msg(message, 'unknown_target', target=target)
            self.logger.error('Recvd message for unknown %s process from %s. Ignoring.' %
                              (target, from_addr))
            self.logger.debug('Message: %s' % str(message))

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
        threading.Thread(target=self.peer_receiver, daemon=True).start()
        threading.Thread(target=self.group_receiver, daemon=True).start()
        threading.Thread(target=self.unknown_receiver, daemon=True).start()
        threading.Thread(target=self.mystery_handler, args=(queues,), daemon=True).start()
        while self.keep_running(signal):
            try:
                if self.diplomat:
                    if self.ping is None:
                        self.ping = PingServer(self.net_cfg.ip4, self.logger)
                        self.ping.start()
                elif self.ping is not None:
                    self.ping.stop()
                    self.ping = None
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
                        self.logger.debug('Send network message: %s:%s' % (message.process, message.function))
                        try:
                            if message.function == Network.stats_req:
                                msg = Message(CfgIds.network, Network.stats_resp, self.net_stats)
                                queues[message.process].put(msg, block=True, timeout=self.q_cadence)
                            elif message.function == Network.ping:
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
                                        '(expected a queue key); skipping' %
                                        message.return_to)
                                else:
                                    # Dispatch to a worker thread; ping()
                                    # is synchronous and sleeps 1 s per
                                    # packet (count=5 → ≥5 s). Running it
                                    # inline blocks the netproc main loop
                                    # and starves all other outbound.
                                    self._ensure_ping_pool().submit(
                                        self._do_ping_async,
                                        target.address, message.obj,
                                        queues[message.return_to])
                            elif message.to_whom == Network.broadcast:
                                msg = bytes(message)
                                try:
                                    self.send_any(msg)
                                    self.track_send_stats(self.unknown_peer, len(msg))
                                except TransmissionError as err:
                                    self.logger.error('Network: %s' % err)
                                    self.track_send_error(self.unknown_peer)
                            elif isinstance(message.to_whom, Group):
                                if message.encrypt and self.group is not None:
                                    msg = self.group.encrypt(bytes(message), self.group)
                                else:
                                    msg = bytes(message)
                                for addr in message.to_whom.addresses:
                                    if addr == self.myself.address:
                                        continue
                                    try:
                                        self.send_group(msg, addr)
                                        self.track_send_stats(self.unknown_peer, len(msg))
                                    except TransmissionError as err:
                                        self.logger.error('Network: %s' % err)
                                        self.track_send_error(self.unknown_peer)
                            else:  # defaults to pseudo-multicast
                                for who in message.to_whom:  # Message ensures this is list  # noqa
                                    address = who.address
                                    if '/' in address:
                                        address = address.split('/')[0]
                                    if message.encrypt:
                                        msg = self.myself.encrypt(bytes(message), who)
                                    else:
                                        msg = bytes(message)
                                    try:
                                        self.send_peer(msg, address)
                                        self.track_send_stats(who.uuid, len(msg))
                                    except TransmissionError as err:
                                        self.logger.error('Network: %s' % err)
                                        self.track_send_error(who.uuid)
                        except BrokenPipeError as err:
                            self.logger.error('Network: %s' % err)
                    else:
                        _probes.counter('net.outbound', 'drop', 'not_a_message')
                        self.logger.error('Net process recvd message of type %s - Message required. Ignoring.' %
                                          type(message))
                        self.logger.debug('Ignored message: %s' % str(message))

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
                    peers = self.configs[CfgIds.peers]
                    from_whom = peers.find_by_address(from_addr)
                    if from_whom is not None:
                        try:
                            decrypt_msg = self.myself.decrypt(raw_msg, from_whom)
                            self._msg_to_queue(decrypt_msg, from_whom, queues, 'point-to-point')
                        except Exception:
                            _probes.counter('net.ptp', 'drop', 'decrypt_failed_known_peer')
                            self.logger.error('Decryption failed for known peer %s, rejecting message' %
                                              from_whom.nickname)
                    else:
                        # Unknown sender — bootstrap (empty peers) or a
                        # late joiner welcoming us. Try unencrypted parse;
                        # legitimate handshake messages (identity:accept)
                        # are encrypt=False. If bytes don't decode, it's
                        # an encrypted message from a peer we don't know
                        # yet — defer to mystery_handler.
                        try:
                            self._msg_to_queue(raw_msg, from_addr, queues, 'point-to-point', validate=False)
                            _probes.counter('net.ptp', 'unknown_sender', 'parsed_unencrypted')
                        except UnicodeDecodeError:
                            _probes.counter('net.ptp', 'unknown_sender', 'deferred_encrypted')
                            self.logger.debug('Out-of-order message from %s detected, retry later' % from_addr)
                            self.encrypted_messages.append((raw_msg, from_addr))
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
                    if from_addr in self.group.addresses:
                        from_whom = self.peers.find_by_address(from_addr)
                        try:
                            decrypt_msg = self.group.decrypt(raw_msg, self.group)
                            if from_whom is not None:
                                self._msg_to_queue(decrypt_msg, from_whom, queues, 'group')
                            else:
                                _probes.counter('net.group', 'drop', 'sender_not_in_peers')
                                self.logger.warning(
                                    'Recvd transmission from %s - not in peers. Ignoring.' % from_addr)
                                self.logger.debug('Ignored payload: %d bytes from %s' % (len(raw_msg), from_addr))
                        except nacl.exceptions.CryptoError as e:
                            _probes.counter('net.group', 'drop', 'crypto_error')
                            name = from_addr
                            if from_whom is not None:
                                name = '%s (%s)' % (from_whom.nickname, name)
                            count = self._crypto_error_counts.get(name, 0) + 1
                            self._crypto_error_counts[name] = count
                            if count == 1 or count % 10 == 0:
                                self.logger.error('CryptoError decrypting message from %s (count: %d)' % (name, count))
                    else:
                        _probes.counter('net.group', 'drop', 'sender_not_in_group')
                        self.logger.error('Recvd transmission from %s - not in group. Ignoring.' % from_addr)
                        self.logger.debug('Ignored payload: %d bytes from %s' % (len(raw_msg), from_addr))
                        # TODO: Query other group members for the unknown sender's
                        # identity — they may have admitted this peer while we were
                        # partitioned. Requires a group-level identity gossip protocol.
                total_inbound += drained_grp

                # async recv stranger messages (separate channel)
                drained_unk = 0
                while drained_unk < INBOUND_BUDGET:
                    try:
                        raw_msg, from_addr = self.unknown_messages.popleft()
                    except IndexError:
                        break
                    drained_unk += 1
                    self._msg_to_queue(raw_msg, from_addr, queues, 'multicast', validate=False)
                total_inbound += drained_unk

                _probes.counter('proc.network', 'iter_drained', str(total_inbound))
            except Exception as err:
                self.logger.error(err)
                self.logger.error(traceback.format_exc())

        self.stop = True
