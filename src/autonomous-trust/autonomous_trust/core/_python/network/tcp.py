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

import socket
import struct
import threading
import time

from .netprocess import NetworkProtocol, TransmissionError
from .udp import UDPNetworkProcess
from .. import _probes
from .. import system


class PeerDisconnect(TransmissionError):
    """Peer closed the TCP connection cleanly before sending any bytes
    of the length prefix. A normal protocol event (e.g. during onboarding
    when peers cycle accept/connect), surfaced as a distinct exception
    type so the listener can log it at debug rather than error."""
    pass


class _PooledConn:
    """One reusable outbound socket plus the wall-clock time it was last
    used, so the idle reaper can age it out."""
    __slots__ = ('sock', 'last_used')

    def __init__(self, sock, last_used):
        self.sock = sock
        self.last_used = last_used


class TCPNetworkProcess(UDPNetworkProcess):
    """
    Implementation of NetworkProcess that uses TCP for point-to-point, and UDP for one-to-many
    Can use either multicast or broadcast for UDP
    """
    mcast_ttl = 2
    # Listen-queue depth. The protocol does per-message connect/send/close,
    # so during onboarding (9 peers simultaneously welcoming a new joiner)
    # or bilateral O(N²) reputation rounds the kernel sees a burst of
    # SYNs. With 5, the 6th SYN got RST/connection-refused — measured
    # 16k+ "Network: Connect" errors per peer and inspector-onboarding
    # accept frames silently dropped. 128 absorbs the burst comfortably.
    rcv_backlog = 128
    net_proto = NetworkProtocol.IPV4

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, use_mcast=False, **kwargs):
        super().__init__(configurations, subsystems, log_q, acceptance_func, udp=False, **kwargs)
        # Listener sockets inherit the global default timeout set by
        # UDPNetworkProcess.__init__ (socket_timeout, currently 0.1s).
        # Per-socket settimeout(positive) on Python 3.13 leaves the
        # socket in non-blocking mode and the receiver thread crashes
        # immediately with BlockingIOError.
        bind_address = self.net_cfg.ip4
        self.recv_ptp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recv_ptp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.recv_ptp_sock.bind((bind_address, self.port))
        except OSError as err1:
            self.logger.warning('Address %s:%s error: %s' % (bind_address, self.port, str(err1)))
            bind_address = '0.0.0.0'
            self.recv_ptp_sock.bind((bind_address, self.port))
        self.my_address, self.port = self.recv_ptp_sock.getsockname()
        self.logger.info('Bound peer recv to %s:%s' % (self.my_address, self.port))
        self.recv_ptp_sock.listen(self.rcv_backlog)

        self.recv_grp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recv_grp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.group_port = self.port + 1
        try:
            self.recv_grp_sock.bind((bind_address, self.group_port))
        except OSError as err1:
            self.logger.warning('Address %s:%s error: %s' % (bind_address, self.group_port, str(err1)))
            bind_address = '0.0.0.0'
            self.recv_grp_sock.bind((bind_address, self.group_port))
        self.logger.info('Bound group recv to %s:%s' % (self.my_address, self.group_port))
        self.recv_grp_sock.listen(self.rcv_backlog)

        self._init_mcast(use_mcast)

        # Persistent-connection state. When pooling is off (the default),
        # none of this is touched and the transport behaves exactly as the
        # historical connect/send/close-per-message path.
        #
        # Everything here must survive the multiprocessing spawn pickle:
        # empty dict/set and None are fine, but a threading.Lock is not, so
        # the locks are created later in _init_transport() (which runs in
        # the worker subprocess). This mirrors the lazy _ping_pool.
        self._pool_enabled = system.net_persistent_conn
        self._conn_idle_ttl = system.net_conn_idle_ttl
        self._max_live_conns = system.net_max_live_conns
        self._conn_pool = {}          # (host, port) -> _PooledConn
        self._pool_lock = None        # created in _init_transport
        self._reader_threads = set()  # live inbound reader threads
        self._reader_lock = None      # created in _init_transport
        self._last_reap = 0.0
        # Sweep for idle connections at most this often (well under the TTL,
        # so a stale connection is closed within ~TTL + one sweep interval).
        self._reap_interval = max(1.0, self._conn_idle_ttl / 6.0)

    # Generous explicit timeout for outbound TCP. Was inheriting the
    # 100ms global default, which under bursty cross-container load
    # connect()-failed thousands of times per peer per minute. We swap
    # the process-wide default rather than per-socket settimeout(),
    # because Python 3.13's settimeout(positive) appears to leave the
    # socket in non-blocking mode (BlockingIOError on first I/O).
    send_timeout = 5.0

    def _channel(self, port):
        return 'peer' if port == self.port else 'group'

    def _write_frame(self, sock, msg):
        """Write one length-prefixed frame. ``msg`` is bytes. Raises
        socket.error on a broken connection so the caller can decide
        whether to reconnect (pooled) or give up (solo)."""
        sent = sock.send(struct.pack('!I', len(msg)))
        if sent == 0:
            raise TransmissionError("Socket connection broken (no bytes sent)")
        total_sent = 0
        while total_sent < len(msg):
            sent = sock.send(msg[total_sent:])
            if sent == 0:
                raise TransmissionError("Socket connection broken (no bytes sent)")
            total_sent += sent
        self.logger.debug('Sent %s bytes' % total_sent)

    def _open_conn(self, host, port):
        """Open one outbound TCP connection with the send timeout, enabling
        TCP keepalive so a dead peer is eventually detected. Raises
        TransmissionError on connect failure."""
        old_default = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.send_timeout)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old_default)
        try:
            sock.connect((host, port))
        except socket.error as err:
            _probes.counter('net.tcp.send', 'connect_failed', err.__class__.__name__)
            try:
                sock.close()
            except OSError:
                pass
            raise TransmissionError('Connect - ' + str(err))
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Idle/interval/count where the platform exposes them (Linux).
            for opt_name, opt_val in (('TCP_KEEPIDLE', 30),
                                      ('TCP_KEEPINTVL', 10),
                                      ('TCP_KEEPCNT', 3)):
                opt = getattr(socket, opt_name, None)
                if opt is not None:
                    sock.setsockopt(socket.IPPROTO_TCP, opt, opt_val)
        except OSError:
            pass  # keepalive tuning is best-effort
        return sock

    def _send_tcp(self, msg, host, port):
        if not isinstance(msg, bytes):
            msg = msg.encode(self.enc)
        # getattr default so a spec-mock (unit tests) without the instance
        # attribute takes the solo path.
        if getattr(self, '_pool_enabled', False):
            self._send_tcp_pooled(msg, host, port)
            return
        # Solo path: per-message connect/send/close (msg already bytes).
        # The default when pooling is off, and the behaviour the pooled path
        # degrades to against a peer that accepts one message per connection.
        # Kept inline and byte-for-byte as the historical implementation --
        # it is the battle-tested default, and the unit tests drive this body
        # directly on a spec-mock, so delegating to a helper would no-op it.
        old_default = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.send_timeout)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old_default)
        with sock:
            self.logger.debug('Solo connect to %s:%s' % (host, port))
            try:
                sock.connect((host, port))
            except socket.error as err:
                _probes.counter('net.tcp.send', 'connect_failed',
                                err.__class__.__name__)
                raise TransmissionError('Connect - ' + str(err))
            # Churn metric: one TCP connection per message, so this
            # counter's RATE is handshakes/sec/node.
            _probes.counter('net.tcp.send', 'connect',
                            'peer' if port == self.port else 'group')
            try:
                sent = sock.send(struct.pack('!I', len(msg)))
            except socket.error as err:
                raise TransmissionError('Send - ' + str(err))
            if sent == 0:
                raise TransmissionError("Socket connection broken (no bytes sent)")
            total_sent = 0
            while total_sent < len(msg):
                try:
                    sent = sock.send(msg[total_sent:])
                except socket.error as err:
                    raise TransmissionError(str(err))
                if sent == 0:
                    raise TransmissionError("Socket connection broken (no bytes sent)")
                total_sent += sent
            self.logger.debug('Sent %s bytes' % total_sent)

    # --- Connection pool (send side) -----------------------------------

    def _ensure_pool(self):
        # Idempotent; _init_transport creates the locks in the worker
        # before any thread runs, so this only actually constructs them
        # when _send_tcp is exercised directly (e.g. in unit tests).
        if self._pool_lock is None:
            self._pool_lock = threading.Lock()
        if self._reader_lock is None:
            self._reader_lock = threading.Lock()

    def _get_pooled(self, key, channel):
        """Return (sock, reused). Reuses the pooled socket for ``key`` if
        present, else connects a new one (evicting the oldest first if the
        cap is reached). Runs under the pool lock; sends come from the net
        main loop, so contention is only the group/ping paths."""
        with self._pool_lock:
            pc = self._conn_pool.get(key)
            if pc is not None:
                return pc.sock, True
            if len(self._conn_pool) >= self._max_live_conns:
                self._evict_oldest_locked()
            sock = self._open_conn(key[0], key[1])  # may raise TransmissionError
            self._conn_pool[key] = _PooledConn(sock, time.time())
            return sock, False

    def _evict(self, key, sock):
        with self._pool_lock:
            pc = self._conn_pool.get(key)
            if pc is not None and pc.sock is sock:
                del self._conn_pool[key]
        try:
            sock.close()
        except OSError:
            pass

    def _evict_oldest_locked(self):
        # Caller holds the pool lock.
        if not self._conn_pool:
            return
        oldest = min(self._conn_pool, key=lambda k: self._conn_pool[k].last_used)
        pc = self._conn_pool.pop(oldest)
        _probes.counter('net.tcp.pool', 'evict_cap')
        try:
            pc.sock.close()
        except OSError:
            pass

    def _send_tcp_pooled(self, msg, host, port):
        self._ensure_pool()
        key = (host, port)
        channel = self._channel(port)
        # Attempt 0 reuses (or connects); on a broken socket, evict and try
        # exactly once more with a fresh connection. A second failure raises,
        # matching the solo path the caller already handles.
        for attempt in (0, 1):
            sock, reused = self._get_pooled(key, channel)
            try:
                self._write_frame(sock, msg)
            except socket.error as err:
                self._evict(key, sock)
                if attempt == 0:
                    _probes.counter('net.tcp.send', 'reconnect', channel)
                    continue
                raise TransmissionError('Send - ' + str(err))
            with self._pool_lock:
                pc = self._conn_pool.get(key)
                if pc is not None and pc.sock is sock:
                    pc.last_used = time.time()
            _probes.counter('net.tcp.send', 'reuse' if reused else 'connect', channel)
            return

    # --- Transport lifecycle hooks -------------------------------------

    def _init_transport(self):
        # Create the locks in the worker subprocess (they can't be pickled
        # across the spawn handoff). Single-threaded here, before any
        # receiver/reader thread starts.
        self._pool_lock = threading.Lock()
        self._reader_lock = threading.Lock()

    def reap_idle_conns(self):
        if not self._pool_enabled or self._pool_lock is None:
            return
        now = time.time()
        if now - self._last_reap < self._reap_interval:
            return
        self._last_reap = now
        dead = []
        with self._pool_lock:
            for key in list(self._conn_pool):
                pc = self._conn_pool[key]
                if now - pc.last_used > self._conn_idle_ttl:
                    dead.append(pc.sock)
                    del self._conn_pool[key]
        for sock in dead:
            try:
                sock.close()
            except OSError:
                pass
        if dead:
            _probes.counter('net.tcp.pool', 'evict_idle', n=len(dead))

    def close_connections(self):
        if self._pool_lock is None:
            return
        with self._pool_lock:
            socks = [pc.sock for pc in self._conn_pool.values()]
            self._conn_pool.clear()
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass

    def send_peer(self, msg, host):
        self._send_tcp(msg, host, self.port)

    def send_group(self, msg, host):
        self._send_tcp(msg, host, self.group_port)

    def _recv(self, sock):
        size_data = b''
        while len(size_data) < 4:
            chunk = sock.recv(4 - len(size_data))
            if chunk == b'':
                # A clean close before any bytes is a normal protocol
                # event during onboarding (peers reset connections as
                # they cycle accept/connect). A close *after* partial
                # length-prefix bytes indicates a broken peer. The
                # listener side classifies the two differently so
                # routine resets don't surface as ERROR-level noise.
                if len(size_data) == 0:
                    raise PeerDisconnect("Peer closed before length prefix")
                raise TransmissionError(
                    "Socket connection broken reading length prefix "
                    "(got %d/4 bytes)" % len(size_data))
            size_data += chunk
        msg_len = struct.unpack('!I', size_data)[0]
        max_msg_size = 64 * 1024 * 1024  # 64 MB
        if msg_len > max_msg_size:
            raise TransmissionError("Message size %d exceeds maximum allowed size %d" % (msg_len, max_msg_size))
        chunks = []
        bytes_recvd = 0
        while bytes_recvd < msg_len:
            chunk = sock.recv(min(msg_len - bytes_recvd, 2048))
            if chunk == b'':
                raise TransmissionError("Socket connection broken (no bytes sent)")
            chunks.append(chunk)
            bytes_recvd += len(chunk)
        # Return raw bytes — encrypted point-to-point payloads are not
        # valid UTF-8. The peer_receiver thread used to crash on the
        # first encrypted inbound (.decode(self.enc) raised
        # UnicodeDecodeError uncaught), leaving the listener dead for
        # the rest of the run. UDP's _recv_udp returns bytes too;
        # downstream dispatch already handles bytes-vs-str correctly
        # (Message.parse + the UnicodeDecodeError branch in
        # netprocess.process for unknown senders).
        return b''.join(chunks)

    def recv_peer(self):
        # Mirror UDP's _recv_udp acceptance policy: take everything
        # except own-address and blacklisted senders. The original
        # accept_peer_message gate rejected any sender not already
        # in self.peers, which broke bootstrap — a joining peer
        # could never receive the unencrypted identity:accept that
        # tells it who the welcomer is. The downstream dispatcher
        # in netprocess.process() decides what to do with unknown
        # senders (bootstrap path / mystery_handler retry).
        (clientsock, (addr, port)) = self.recv_ptp_sock.accept()
        # NB: don't call clientsock.settimeout(positive) here — Python
        # 3.13 puts it in non-blocking mode and _recv crashes with
        # BlockingIOError. clientsock inherits the listener's timeout,
        # which is the global default (0.1s) — tight, but works.
        if addr == self.my_address:
            _probes.counter('net.tcp.peer', 'drop', 'own_address')
            return None, None, None  # my own message
        if self.reject_message(addr):
            _probes.counter('net.tcp.peer', 'drop', 'blacklisted')
            clientsock.close()
            return None, addr, port  # blacklisted
        _probes.counter('net.tcp.peer', 'accepted')
        return self._recv(clientsock), addr, port

    def recv_group(self):
        # Same relaxation as recv_peer: blacklist-only at the socket
        # gate. Group decryption downstream still requires the sender
        # to be a known group member (group.decrypt + group.addresses
        # check), so this can't leak unencrypted group payloads to a
        # stranger.
        (clientsock, (addr, port)) = self.recv_grp_sock.accept()
        if addr == self.my_address:
            _probes.counter('net.tcp.group', 'drop', 'own_address')
            return None, None, None  # my own message
        if self.reject_message(addr):
            _probes.counter('net.tcp.group', 'drop', 'blacklisted')
            clientsock.close()
            return None, addr, port  # blacklisted
        _probes.counter('net.tcp.group', 'accepted')
        return self._recv(clientsock), addr, port

    # --- Persistent readers (receive side) -----------------------------
    # When pooling is on, a sender keeps its connection open and sends many
    # frames back-to-back, so the receiver can't go back to accept after one
    # read. Instead the acceptor hands each accepted socket to a reader
    # thread that loops _recv until the peer disconnects, errors, or goes
    # idle. Accept-time gates (own-address / blacklist) match recv_peer /
    # recv_group; downstream attribution is unchanged because readers feed
    # the same deque with the same (raw, from_addr) tuples.

    @staticmethod
    def _close_quiet(sock):
        try:
            sock.close()
        except OSError:
            pass

    def start_receivers(self, queues):
        if self._pool_enabled:
            threading.Thread(target=self.peer_acceptor,
                             args=(self.peer_messages,), daemon=True).start()
            threading.Thread(target=self.group_acceptor,
                             args=(self.group_messages,), daemon=True).start()
        else:
            super().start_receivers(queues)

    def peer_acceptor(self, msg_queue):
        self._accept_loop(self.recv_ptp_sock, msg_queue, 'peer')

    def group_acceptor(self, msg_queue):
        self._accept_loop(self.recv_grp_sock, msg_queue, 'group')

    def _accept_loop(self, listen_sock, msg_queue, channel):
        layer = 'net.tcp.' + channel
        while not self.stop:
            try:
                (clientsock, (addr, port)) = listen_sock.accept()
            except (TimeoutError, socket.timeout):
                continue
            except BlockingIOError:
                time.sleep(self.socket_timeout)
                continue
            except OSError as err:
                _probes.counter(layer, 'accept_error', err.__class__.__name__)
                continue
            if addr == self.my_address:
                _probes.counter(layer, 'drop', 'own_address')
                self._close_quiet(clientsock)
                continue
            if self.reject_message(addr):
                _probes.counter(layer, 'drop', 'blacklisted')
                self._close_quiet(clientsock)
                continue
            with self._reader_lock:
                at_cap = len(self._reader_threads) >= self._max_live_conns
            if at_cap:
                _probes.counter(layer, 'drop', 'max_conns')
                self._close_quiet(clientsock)
                continue
            _probes.counter(layer, 'accepted')
            reader = threading.Thread(
                target=self._reader,
                args=(clientsock, addr, msg_queue, channel), daemon=True)
            with self._reader_lock:
                self._reader_threads.add(reader)
            reader.start()

    def _reader(self, clientsock, addr, msg_queue, channel):
        _probes.counter('net.tcp.reader', 'open', channel)
        reason = 'eof'
        last = time.time()
        try:
            while not self.stop:
                try:
                    raw = self._recv(clientsock)
                except PeerDisconnect:
                    reason = 'disconnect'
                    break
                except (TimeoutError, socket.timeout):
                    # Idle between frames. _recv times out on the first recv
                    # (before any prefix byte), so no partial frame is lost.
                    if time.time() - last > self._conn_idle_ttl:
                        reason = 'idle'
                        break
                    continue
                except BlockingIOError:
                    time.sleep(self.socket_timeout)
                    continue
                except TransmissionError:
                    reason = 'error'
                    self.track_recv_error()
                    break
                except OSError:
                    reason = 'error'
                    break
                # Deliver + stats, mirroring _encr_recv's success branch so
                # downstream dispatch and rate tracking are unchanged.
                msg_queue.append((raw, addr))
                who = self.peers.find_by_address(addr)
                if who is not None:
                    self.track_recv_stats(who.uuid, len(raw))
                else:
                    self.track_recv_stats(self.unknown_peer, len(raw))
                last = time.time()
        finally:
            self._close_quiet(clientsock)
            with self._reader_lock:
                self._reader_threads.discard(threading.current_thread())
            _probes.counter('net.tcp.reader', 'close', reason)
