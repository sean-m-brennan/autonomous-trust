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
"""
Source-address binding on the send paths (both transports).

AT binds its receive sockets to the node's configured address but historically
left the send sockets unbound, so the kernel chose a source from the route to the
destination. On any node with more than one candidate source address (loopback
aliases, multi-homed hosts, containers on several networks) a peer therefore saw
frames arrive from an address that is not in its listing, and
`netprocess.peers.find_by_address()` missed every one -- measured as 220
`from 127.0.0.1` log lines and 108 dropped frames across a 2-peer harness run,
against 0 and 0 with the source bound.

Two behaviours are pinned here:
  1. the source a peer OBSERVES equals the address the node is known by, and
  2. binding cannot collide with the port the node is listening on.

(2) is the load-bearing safety property. Send sockets bind port 0 and must NEVER
set SO_REUSEADDR: the recv sockets hold (my_address, comm_port) WITH
SO_REUSEADDR, and UDP grants a second socket the same addr:port only when BOTH
set it, so omitting it is exactly what stops the kernel's autobind from handing
out the listening port -- even with AT_COMM_PORT configured inside the ephemeral
range, the one arrangement where a collision is otherwise reachable.
"""
from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from autonomous_trust.core.network.udp import (
    UDPNetworkProcess,
    bind_source_address,
)
from autonomous_trust.core.network.tcp import TCPNetworkProcess


LOCAL_A = '127.0.0.2'
LOCAL_B = '127.0.0.3'


def _ephemeral_range():
    with open('/proc/sys/net/ipv4/ip_local_port_range') as fh:
        lo, hi = fh.read().split()
    return int(lo), int(hi)


def _aliases_available():
    for addr in (LOCAL_A, LOCAL_B):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((addr, 0))
        except OSError:
            return False
        finally:
            s.close()
    return True


_needs_alias = pytest.mark.skipif(
    not _aliases_available(),
    reason='needs bindable 127.0.0.2/127.0.0.3 loopback aliases')


# ---------------------------------------------------------------------------
# The helper's contract
# ---------------------------------------------------------------------------

class TestBindSourceAddress:
    @_needs_alias
    def test_binds_requested_address_on_ephemeral_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            assert bind_source_address(sock, LOCAL_A) is True
            bound_addr, bound_port = sock.getsockname()
            assert bound_addr == LOCAL_A
            assert bound_port != 0  # kernel picked one
        finally:
            sock.close()

    @_needs_alias
    def test_never_sets_so_reuseaddr(self):
        """The collision guarantee. With SO_REUSEADDR the helper could bind the
        very port the node listens on and steal its inbound datagrams."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            bind_source_address(sock, LOCAL_A)
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
        finally:
            sock.close()

    @pytest.mark.parametrize('address', ['', '0.0.0.0', '::', None, 12345])
    def test_skips_wildcard_and_non_str(self, address):
        """Called as getattr(self, 'my_address', None), and the send-path unit
        tests drive those bodies on spec-mocks whose attributes are Mock objects
        -- a non-str must be a no-op, not a crash."""
        sock = MagicMock()
        assert bind_source_address(sock, address) is False
        sock.bind.assert_not_called()

    def test_spec_mock_attribute_is_a_noop(self):
        """`my_address` is set in __init__, so a spec-mock does not carry it and
        the call sites' getattr(..., None) yields None -- the send-path unit
        tests in test_network_udp.py therefore bind nothing, which is why this
        module sets the address explicitly to exercise the bind at all."""
        proc = MagicMock(spec=UDPNetworkProcess)
        assert getattr(proc, 'my_address', None) is None
        sock = MagicMock()
        assert bind_source_address(sock, getattr(proc, 'my_address', None)) is False
        sock.bind.assert_not_called()

    def test_bind_failure_is_not_fatal_and_warns_once(self):
        """A bad address must not take the node off the air; it degrades to the
        old unbound behaviour and says so once."""
        from autonomous_trust.core.network import udp as udp_mod
        sock = MagicMock()
        sock.bind.side_effect = OSError('cannot assign requested address')
        logger = MagicMock()
        with patch.object(udp_mod, '_bind_warned', False):
            assert bind_source_address(sock, '203.0.113.7', logger) is False
            assert bind_source_address(sock, '203.0.113.7', logger) is False
        assert logger.warning.call_count == 1, 'should warn once, not per send'

    @_needs_alias
    def test_stream_sets_bind_address_no_port_when_available(self):
        """TCP: pin the ADDRESS without reserving a port ahead of connect(), so
        the per-message connect/send/close path keeps 4-tuple uniqueness instead
        of exhausting the ephemeral range."""
        opt = getattr(socket, 'IP_BIND_ADDRESS_NO_PORT', None)
        if opt is None:
            pytest.skip('IP_BIND_ADDRESS_NO_PORT not available')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            assert bind_source_address(sock, LOCAL_A, stream=True) is True
            assert sock.getsockopt(socket.IPPROTO_IP, opt) == 1
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# Port-collision safety, against a live listener
# ---------------------------------------------------------------------------

class TestNoPortCollision:
    @_needs_alias
    def test_autobind_never_takes_the_listening_port(self):
        """The dangerous arrangement: comm_port configured INSIDE the ephemeral
        range, so autobind could plausibly select it."""
        lo, _hi = _ephemeral_range()
        comm_port = lo + 1
        recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            recv.bind((LOCAL_A, comm_port))  # as udp.py:54-56 does
        except OSError:
            pytest.skip('could not reserve a port inside the ephemeral range')
        held = []
        try:
            for _ in range(600):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                bind_source_address(s, LOCAL_A)
                held.append(s)
                assert s.getsockname()[1] != comm_port, \
                    'send socket stole the port the node listens on'
        finally:
            for s in held:
                s.close()
            recv.close()

    @_needs_alias
    def test_explicit_collision_is_refused_without_reuseaddr(self):
        """Why omitting SO_REUSEADDR is the guarantee, not merely tidy: the
        kernel refuses the collision outright, which is what makes autobind
        unable to produce it."""
        lo, _hi = _ephemeral_range()
        comm_port = lo + 2
        recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            recv.bind((LOCAL_A, comm_port))
        except OSError:
            pytest.skip('could not reserve a port inside the ephemeral range')
        plain = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(OSError):
                plain.bind((LOCAL_A, comm_port))
        finally:
            plain.close()
            recv.close()


# ---------------------------------------------------------------------------
# The send paths actually bind
# ---------------------------------------------------------------------------

class TestSendPathsBind:
    def _proc(self, cls, my_address=LOCAL_B):
        proc = MagicMock(spec=cls)
        proc.enc = 'utf-8'
        proc.my_address = my_address
        proc.logger = MagicMock()  # set in Process.__init__, so not in the spec
        proc.port = 8000
        proc.group_port = 8001
        proc.manycast_addr = '127.255.255.255'
        proc.sock_options = (socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return proc

    def test_send_udp_binds_source(self):
        proc = self._proc(UDPNetworkProcess)
        with patch('socket.socket') as mk:
            sock = mk.return_value.__enter__.return_value
            sock.sendto.return_value = 5
            UDPNetworkProcess._send_udp(proc, b'hello', 'remotehost', 9000)
        sock.bind.assert_called_once_with((LOCAL_B, 0))

    def test_send_any_binds_source(self):
        """The self-filter half: _recv_udp drops our own broadcast only when its
        source matches my_address, and a node receives its own send_any."""
        proc = self._proc(UDPNetworkProcess)
        with patch('socket.socket') as mk:
            sock = mk.return_value.__enter__.return_value
            sock.sendto.return_value = 5
            UDPNetworkProcess.send_any(proc, b'hello')
        sock.bind.assert_called_once_with((LOCAL_B, 0))

    def test_open_conn_binds_source(self):
        proc = self._proc(TCPNetworkProcess)
        proc.send_timeout = 1.0
        with patch('socket.socket') as mk:
            sock = mk.return_value
            TCPNetworkProcess._open_conn(proc, 'remotehost', 9000)
        sock.bind.assert_called_once_with((LOCAL_B, 0))

    def test_solo_send_tcp_binds_source(self):
        """The DEFAULT path (pooling off), kept inline in _send_tcp."""
        proc = self._proc(TCPNetworkProcess)
        proc.send_timeout = 1.0
        proc._pool_enabled = False
        with patch('socket.socket') as mk:
            # `with sock:` has no `as`, so the body operates on the socket
            # itself, not on __enter__'s return value.
            sock = mk.return_value
            sock.send.return_value = 4
            TCPNetworkProcess._send_tcp(proc, b'data', 'remotehost', 9000)
        sock.bind.assert_called_once_with((LOCAL_B, 0))


# ---------------------------------------------------------------------------
# End to end on real sockets: what does the PEER observe?
# ---------------------------------------------------------------------------

class TestObservedSourceAddress:
    @_needs_alias
    def test_peer_observes_our_configured_address(self):
        """The behaviour the whole change exists for. Unbound, the receiver sees
        127.0.0.1 and find_by_address misses; bound, it sees LOCAL_B and hits."""
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rx.bind((LOCAL_A, 0))
        rx.settimeout(2.0)
        port = rx.getsockname()[1]
        try:
            unbound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            unbound.sendto(b'x', (LOCAL_A, port))
            _m, (src_unbound, _p) = rx.recvfrom(64)
            unbound.close()

            bound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bind_source_address(bound, LOCAL_B)
            bound.sendto(b'x', (LOCAL_A, port))
            _m, (src_bound, _p) = rx.recvfrom(64)
            bound.close()
        finally:
            rx.close()
        assert src_unbound != LOCAL_B, \
            'expected the kernel to pick a different source when unbound'
        assert src_bound == LOCAL_B, \
            'peer must observe the address it knows us by'

    @_needs_alias
    def test_own_broadcast_is_recognisable_as_ours(self):
        """udp.py:131's `addr == self.my_address` self-filter can only work if
        our broadcast carries our own address as its source."""
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rx.bind(('127.255.255.255', 0))
        rx.settimeout(2.0)
        port = rx.getsockname()[1]
        try:
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            bind_source_address(tx, LOCAL_B)
            tx.sendto(b'announce', ('127.255.255.255', port))
            _m, (src, _p) = rx.recvfrom(64)
            tx.close()
        finally:
            rx.close()
        assert src == LOCAL_B, 'own broadcast must be attributable to us'
