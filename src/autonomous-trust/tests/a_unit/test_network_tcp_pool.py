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

"""Unit tests for persistent / pooled TCP connections.

Covers the send-side connection pool (reuse, reconnect-once, cap eviction,
idle reaping) and the receive-side persistent reader (many frames over one
connection). The flag-off path is exercised by test_network_tcp.py and by
the flag-off case here.

Procs are built with __new__ + manual attribute assignment (as in
test_repprocess_exclusion.py) so the real pooled methods run without going
through __init__ or opening real listener sockets. Socket I/O is either
patched (send side) or a real socketpair (reader side).
"""
import socket
import struct
import threading
import time
from collections import deque
from unittest.mock import MagicMock, patch

import pytest

from autonomous_trust.core.network.tcp import TCPNetworkProcess, _PooledConn
from autonomous_trust.core.network.netprocess import TransmissionError


def _pooled_proc(pool_enabled=True, max_conns=64, idle_ttl=30.0):
    proc = TCPNetworkProcess.__new__(TCPNetworkProcess)
    proc._pool_enabled = pool_enabled
    proc._conn_idle_ttl = idle_ttl
    proc._max_live_conns = max_conns
    proc._conn_pool = {}
    proc._pool_lock = threading.Lock()
    proc._reader_threads = set()
    proc._reader_lock = threading.Lock()
    proc._last_reap = 0.0
    proc._reap_interval = 0.0
    proc.port = 8000
    proc.group_port = 8001
    proc.enc = 'utf-8'
    proc.send_timeout = 5.0
    proc.socket_timeout = 0.1
    proc.stop = False
    proc.my_address = '10.0.0.1'
    proc.unknown_peer = '0'
    proc.logger = MagicMock()
    # peers is a read-only property backed by protocol; drive it via protocol.
    proc.protocol = MagicMock()
    proc.protocol.peers.find_by_address.return_value = None
    proc.track_recv_stats = MagicMock()
    proc.track_recv_error = MagicMock()
    # The send-side tests drive the pool with mock sockets, which are not real
    # file descriptors, so the reuse health probe cannot select() on them.
    # Stub it healthy here; the probe itself is covered against real
    # socketpairs in TestPeerClosedDetection below, which is where its
    # behaviour actually matters.
    proc._peer_gone = lambda _sock: False
    return proc


def _byte_counting_sock():
    """A mock socket whose send() reports the full length of its argument
    (i.e. every frame goes out in one call)."""
    s = MagicMock()
    s.send.side_effect = lambda b: len(b)
    return s


# ---------------------------------------------------------------------------
# Send-side pool: reuse
# ---------------------------------------------------------------------------

class TestPoolReuse:
    def test_two_sends_reuse_one_connection(self):
        made = []

        def fake_socket(*_a, **_k):
            s = _byte_counting_sock()
            made.append(s)
            return s

        proc = _pooled_proc()
        with patch('socket.socket', side_effect=fake_socket):
            proc._send_tcp_pooled(b'hello', '10.0.0.9', 8000)
            proc._send_tcp_pooled(b'world', '10.0.0.9', 8000)

        assert len(made) == 1                       # connected exactly once
        assert made[0].connect.call_count == 1
        assert len(proc._conn_pool) == 1
        # two frames, prefix + body each => four send() calls on one socket
        assert made[0].send.call_count == 4

    def test_distinct_peers_get_distinct_connections(self):
        made = []

        def fake_socket(*_a, **_k):
            s = _byte_counting_sock()
            made.append(s)
            return s

        proc = _pooled_proc()
        with patch('socket.socket', side_effect=fake_socket):
            proc._send_tcp_pooled(b'a', '10.0.0.9', 8000)
            proc._send_tcp_pooled(b'b', '10.0.0.8', 8000)

        assert len(made) == 2
        assert len(proc._conn_pool) == 2

    def test_keepalive_enabled_on_new_connection(self):
        proc = _pooled_proc()
        sock = _byte_counting_sock()
        with patch('socket.socket', return_value=sock):
            proc._send_tcp_pooled(b'hello', '10.0.0.9', 8000)
        opt_calls = [c.args[:2] for c in sock.setsockopt.call_args_list]
        assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE) in opt_calls


# ---------------------------------------------------------------------------
# Send-side pool: reconnect-once on a broken socket
# ---------------------------------------------------------------------------

class TestPoolReconnect:
    def test_reset_triggers_evict_and_single_reconnect(self):
        sock0 = MagicMock()
        # msg1: prefix(4) + body(5) OK; msg2: prefix send raises reset
        sock0.send.side_effect = [4, 5, socket.error('connection reset')]
        sock1 = _byte_counting_sock()

        proc = _pooled_proc()
        with patch('socket.socket', side_effect=[sock0, sock1]):
            proc._send_tcp_pooled(b'hello', '10.0.0.9', 8000)   # uses sock0
            proc._send_tcp_pooled(b'world', '10.0.0.9', 8000)   # reset -> reconnect

        assert sock0.close.called                       # dead socket evicted
        assert sock1.connect.call_count == 1            # reconnected once
        assert proc._conn_pool[('10.0.0.9', 8000)].sock is sock1

    def test_second_failure_raises_transmission_error(self):
        # Every fresh socket fails its first send, so the single retry also
        # fails and the error surfaces to the caller.
        def failing_sock(*_a, **_k):
            s = MagicMock()
            s.send.side_effect = socket.error('broken pipe')
            return s

        proc = _pooled_proc()
        with patch('socket.socket', side_effect=failing_sock):
            with pytest.raises(TransmissionError, match='Send'):
                proc._send_tcp_pooled(b'hello', '10.0.0.9', 8000)
        # nothing left pooled after both attempts evicted
        assert proc._conn_pool == {}


# ---------------------------------------------------------------------------
# Send-side pool: cap + idle reaping
# ---------------------------------------------------------------------------

class TestPoolBounds:
    def test_cap_evicts_oldest(self):
        proc = _pooled_proc(max_conns=2)
        old = MagicMock()
        mid = MagicMock()
        proc._conn_pool[('a', 8000)] = _PooledConn(old, 100.0)
        proc._conn_pool[('b', 8000)] = _PooledConn(mid, 200.0)
        new = _byte_counting_sock()
        with patch('socket.socket', return_value=new):
            proc._send_tcp_pooled(b'x', 'c', 8000)
        assert ('a', 8000) not in proc._conn_pool       # oldest evicted
        assert old.close.called
        assert ('b', 8000) in proc._conn_pool
        assert ('c', 8000) in proc._conn_pool

    def test_reaper_evicts_idle(self):
        proc = _pooled_proc(idle_ttl=30.0)
        sock = MagicMock()
        proc._conn_pool[('h', 8000)] = _PooledConn(sock, time.time() - 100)
        proc.reap_idle_conns()
        assert ('h', 8000) not in proc._conn_pool
        assert sock.close.called

    def test_reaper_keeps_fresh(self):
        proc = _pooled_proc(idle_ttl=30.0)
        sock = MagicMock()
        proc._conn_pool[('h', 8000)] = _PooledConn(sock, time.time())
        proc.reap_idle_conns()
        assert ('h', 8000) in proc._conn_pool
        assert not sock.close.called

    def test_close_connections_drains_pool(self):
        proc = _pooled_proc()
        s1, s2 = MagicMock(), MagicMock()
        proc._conn_pool[('a', 8000)] = _PooledConn(s1, time.time())
        proc._conn_pool[('b', 8000)] = _PooledConn(s2, time.time())
        proc.close_connections()
        assert proc._conn_pool == {}
        assert s1.close.called and s2.close.called


# ---------------------------------------------------------------------------
# Flag-off: pooling disabled leaves the historical per-message path
# ---------------------------------------------------------------------------

class TestFlagOff:
    def test_disabled_does_not_pool(self):
        proc = _pooled_proc(pool_enabled=False)
        sock = _byte_counting_sock()
        with patch('socket.socket', return_value=sock):
            TCPNetworkProcess._send_tcp(proc, b'hello', 'h', 8000)
            TCPNetworkProcess._send_tcp(proc, b'again', 'h', 8000)
        assert proc._conn_pool == {}                     # nothing retained
        assert sock.connect.call_count == 2              # connect per message


# ---------------------------------------------------------------------------
# Receive-side persistent reader: many frames over one connection
# ---------------------------------------------------------------------------

class TestPersistentReader:
    def test_reader_reads_multiple_frames_one_connection(self):
        proc = _pooled_proc()
        left, right = socket.socketpair()
        left.settimeout(0.1)
        q = deque()
        for payload in (b'first', b'second', b'third'):
            right.sendall(struct.pack('!I', len(payload)) + payload)

        reader = threading.Thread(
            target=proc._reader, args=(left, '10.0.0.9', q, 'peer'), daemon=True)
        reader.start()
        deadline = time.time() + 3.0
        while len(q) < 3 and time.time() < deadline:
            time.sleep(0.02)
        proc.stop = True
        right.close()
        reader.join(timeout=2.0)

        assert [raw for raw, _ in q] == [b'first', b'second', b'third']
        assert all(addr == '10.0.0.9' for _, addr in q)

    def test_reader_exits_on_peer_disconnect(self):
        proc = _pooled_proc()
        left, right = socket.socketpair()
        left.settimeout(0.1)
        q = deque()
        proc._reader_threads.add(threading.current_thread())  # sanity: discard is safe
        reader = threading.Thread(
            target=proc._reader, args=(left, '10.0.0.9', q, 'peer'), daemon=True)
        with proc._reader_lock:
            proc._reader_threads.add(reader)
        reader.start()
        right.close()                       # clean disconnect before any frame
        reader.join(timeout=2.0)
        assert not reader.is_alive()
        with proc._reader_lock:
            assert reader not in proc._reader_threads   # reader removed itself


# ---------------------------------------------------------------------------
# Send-side pool: the peer closed between sends (ISSUES §3.6)
# ---------------------------------------------------------------------------

class TestPeerClosedDetection:
    """A write into a socket whose peer has closed SUCCEEDS -- the RST comes
    back after send() returns -- so without a pre-reuse probe that frame is
    lost silently and only the NEXT send raises. These use real socketpairs;
    a mock cannot reproduce the kernel behaviour that makes the bug possible.
    """

    def test_live_peer_is_not_gone(self):
        proc = TCPNetworkProcess.__new__(TCPNetworkProcess)
        near, far = socket.socketpair()
        try:
            assert proc._peer_gone(near) is False
        finally:
            near.close()
            far.close()

    def test_closed_peer_is_gone(self):
        proc = TCPNetworkProcess.__new__(TCPNetworkProcess)
        near, far = socket.socketpair()
        try:
            far.close()  # what a one-frame-per-connection peer does after reading
            assert proc._peer_gone(near) is True
        finally:
            near.close()

    def test_unexpected_inbound_bytes_are_gone(self):
        """Nothing ever arrives on an outbound connection; bytes here mean the
        far end is out of step with our framing, so the socket is not reusable."""
        proc = TCPNetworkProcess.__new__(TCPNetworkProcess)
        near, far = socket.socketpair()
        try:
            far.send(b'unexpected')
            assert proc._peer_gone(near) is True
        finally:
            near.close()
            far.close()

    def test_closed_socket_is_gone(self):
        proc = TCPNetworkProcess.__new__(TCPNetworkProcess)
        near, far = socket.socketpair()
        near.close()
        far.close()
        assert proc._peer_gone(near) is True

    def test_reuse_after_peer_close_reconnects_and_delivers(self):
        """The regression: peer accepted one frame and hung up. The second
        send must land on a NEW connection, not vanish into the old one."""
        proc = _pooled_proc()
        del proc._peer_gone  # exercise the real probe

        near, far = socket.socketpair()
        far.close()  # peer took frame 1 and closed
        proc._conn_pool[('10.0.0.9', 8000)] = _PooledConn(near, time.time())

        fresh = _byte_counting_sock()
        with patch.object(TCPNetworkProcess, '_open_conn', return_value=fresh) as opened:
            proc._send_tcp_pooled(b'frame two', '10.0.0.9', 8000)

        opened.assert_called_once_with('10.0.0.9', 8000)
        assert fresh.send.called, 'frame two must go out on the new connection'
        sent = b''.join(c.args[0] for c in fresh.send.call_args_list)
        assert sent == struct.pack('!I', len(b'frame two')) + b'frame two'
        # and the dead socket is out of the pool, replaced by the live one
        assert proc._conn_pool[('10.0.0.9', 8000)].sock is fresh
        near.close()
