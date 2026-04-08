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

"""
Unit tests for UDPNetworkProcess._send_udp, .send_peer, .send_group,
.send_any, ._recv_udp, .recv_peer, .recv_group, .recv_any, and the
_init_udp_ptp / _init_udp_grp / _init_mcast initialisation helpers.

All mocked tests use a MagicMock instance in place of a real
UDPNetworkProcess object, then call the unbound methods directly
(Class.method(mock, ...)) so that __init__ and real network I/O are
never triggered.

The original integration tests (which require a live config) are
preserved at the bottom of this file.
"""

import socket
import struct
import pytest
from unittest.mock import patch, MagicMock, call

from autonomous_trust.core.network.udp import UDPNetworkProcess
from autonomous_trust.core.network.netprocess import TransmissionError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proc(my_address='192.168.1.10', port=8000, group_port=8001,
               enc='utf-8', packet_size=65507, manycast_packet_size=65507,
               manycast_addr='192.168.1.255', reject=False,
               sock_options=None):
    """Return a minimal mock satisfying UDPNetworkProcess method contracts."""
    proc = MagicMock(spec=UDPNetworkProcess)
    proc.enc = enc
    proc.my_address = my_address
    proc.port = port
    proc.group_port = group_port
    proc.packet_size = packet_size
    proc.manycast_packet_size = manycast_packet_size
    proc.manycast_addr = manycast_addr
    proc.logger = MagicMock()
    proc.my_ip = my_address
    proc.reject_message.return_value = reject
    proc.acceptance = None
    if sock_options is None:
        proc.sock_options = (socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    else:
        proc.sock_options = sock_options
    # Bind real sockets as attributes so recv_* tests can replace them
    proc.recv_ptp_sock = MagicMock()
    proc.recv_grp_sock = MagicMock()
    proc.recv_cast_sock = MagicMock()
    return proc


def _make_context_sock(sendto_return=None, sendto_side_effect=None):
    """Return a MagicMock socket usable as a context manager."""
    sock = MagicMock()
    sock.__enter__ = lambda s: sock
    sock.__exit__ = MagicMock(return_value=False)
    if sendto_side_effect is not None:
        sock.sendto.side_effect = sendto_side_effect
    elif sendto_return is not None:
        sock.sendto.return_value = sendto_return
    return sock


# ---------------------------------------------------------------------------
# _send_udp
# ---------------------------------------------------------------------------

class TestSendUdp:
    def test_bytes_msg_sent_to_host_port(self):
        """_send_udp calls sendto with the bytes message and (host, port)."""
        proc = _make_proc()
        mock_sock = _make_context_sock(sendto_return=5)

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._send_udp(proc, b'hello', 'remotehost', 9000)

        mock_sock.sendto.assert_called_once_with(b'hello', ('remotehost', 9000))

    def test_string_msg_encoded_before_send(self):
        """_send_udp encodes str messages using proc.enc before calling sendto."""
        proc = _make_proc()
        mock_sock = _make_context_sock(sendto_return=5)

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._send_udp(proc, 'hello', 'remotehost', 9000)

        sent_data = mock_sock.sendto.call_args[0][0]
        assert isinstance(sent_data, bytes)
        assert sent_data == b'hello'

    def test_string_encoding_uses_proc_enc(self):
        """_send_udp uses proc.enc (not hardcoded utf-8) for encoding."""
        proc = _make_proc(enc='ascii')
        mock_sock = _make_context_sock(sendto_return=5)

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._send_udp(proc, 'hi', 'remotehost', 9000)

        sent_data = mock_sock.sendto.call_args[0][0]
        assert sent_data == 'hi'.encode('ascii')

    def test_sendto_returns_zero_raises_transmission_error(self):
        """sendto() returning 0 raises TransmissionError."""
        proc = _make_proc()
        mock_sock = _make_context_sock(sendto_return=0)

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(TransmissionError, match='no bytes sent'):
                UDPNetworkProcess._send_udp(proc, b'data', 'remotehost', 9000)

    def test_uses_udp_socket(self):
        """_send_udp creates an AF_INET/SOCK_DGRAM/IPPROTO_UDP socket."""
        proc = _make_proc()
        mock_sock = _make_context_sock(sendto_return=4)

        with patch('socket.socket', return_value=mock_sock) as mock_cls:
            UDPNetworkProcess._send_udp(proc, b'data', 'remotehost', 9000)

        mock_cls.assert_called_once_with(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    def test_non_ascii_string_encoded_correctly(self):
        """_send_udp encodes non-ASCII characters using proc.enc."""
        proc = _make_proc(enc='utf-8')
        msg = 'café'
        encoded = msg.encode('utf-8')
        mock_sock = _make_context_sock(sendto_return=len(encoded))

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._send_udp(proc, msg, 'remotehost', 9000)

        sent_data = mock_sock.sendto.call_args[0][0]
        assert sent_data == encoded


# ---------------------------------------------------------------------------
# send_peer
# ---------------------------------------------------------------------------

class TestSendPeer:
    def test_normal_msg_sent_to_self_port(self):
        """send_peer delegates to _send_udp using self.port for normal-length messages."""
        proc = _make_proc(port=8000, packet_size=65507)
        proc._send_udp = MagicMock()
        msg = b'short message'
        UDPNetworkProcess.send_peer(proc, msg, '10.0.0.1')
        proc._send_udp.assert_called_once_with(msg, '10.0.0.1', 8000)

    def test_oversized_msg_raises_error(self):
        """send_peer raises TransmissionError for messages longer than packet_size."""
        proc = _make_proc(port=8000, packet_size=10)
        proc._send_udp = MagicMock()
        msg = b'x' * 20   # 20 bytes > packet_size of 10
        with pytest.raises(TransmissionError):
            UDPNetworkProcess.send_peer(proc, msg, '10.0.0.1')
        proc._send_udp.assert_not_called()

    def test_msg_exactly_packet_size_is_sent(self):
        """send_peer sends a message of exactly packet_size bytes."""
        proc = _make_proc(port=8000, packet_size=10)
        proc._send_udp = MagicMock()
        msg = b'x' * 10
        UDPNetworkProcess.send_peer(proc, msg, '10.0.0.1')
        sent_arg = proc._send_udp.call_args[0][0]
        assert len(sent_arg) == 10


# ---------------------------------------------------------------------------
# send_group
# ---------------------------------------------------------------------------

class TestSendGroup:
    def test_send_group_uses_group_port(self):
        """send_group delegates to _send_udp using self.group_port."""
        proc = _make_proc(port=8000, group_port=8001)
        proc._send_udp = MagicMock()
        msg = b'group msg'
        UDPNetworkProcess.send_group(proc, msg, '10.0.0.1')
        proc._send_udp.assert_called_once_with(msg, '10.0.0.1', 8001)

    def test_send_group_does_not_truncate(self):
        """send_group has no truncation logic — message is passed unchanged."""
        proc = _make_proc(port=8000, group_port=8001, packet_size=5)
        proc._send_udp = MagicMock()
        msg = b'x' * 100
        UDPNetworkProcess.send_group(proc, msg, '10.0.0.1')
        sent_arg = proc._send_udp.call_args[0][0]
        assert len(sent_arg) == 100


# ---------------------------------------------------------------------------
# send_any
# ---------------------------------------------------------------------------

class TestSendAny:
    def test_send_any_uses_sock_options_and_manycast(self):
        """send_any calls setsockopt with self.sock_options and sendto to manycast_addr."""
        proc = _make_proc(manycast_addr='192.168.1.255', port=8000)
        mock_sock = _make_context_sock(sendto_return=5)

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess.send_any(proc, b'broadcast')

        mock_sock.setsockopt.assert_called_once_with(*proc.sock_options)
        mock_sock.sendto.assert_called_once_with(b'broadcast', ('192.168.1.255', 8000))

    def test_send_any_encodes_string_msg(self):
        """send_any encodes a str message before sending."""
        proc = _make_proc()
        mock_sock = _make_context_sock(sendto_return=5)

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess.send_any(proc, 'text')

        sent_data = mock_sock.sendto.call_args[0][0]
        assert isinstance(sent_data, bytes)
        assert sent_data == b'text'

    def test_send_any_returns_zero_raises_transmission_error(self):
        """send_any raises TransmissionError when sendto returns 0."""
        proc = _make_proc()
        mock_sock = _make_context_sock(sendto_return=0)

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(TransmissionError, match='no bytes sent'):
                UDPNetworkProcess.send_any(proc, b'data')

    def test_send_any_uses_udp_socket(self):
        """send_any creates an AF_INET/SOCK_DGRAM/IPPROTO_UDP socket."""
        proc = _make_proc()
        mock_sock = _make_context_sock(sendto_return=4)

        with patch('socket.socket', return_value=mock_sock) as mock_cls:
            UDPNetworkProcess.send_any(proc, b'data')

        mock_cls.assert_called_once_with(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    def test_send_any_bytes_passed_directly(self):
        """send_any passes bytes messages directly to sendto without encoding."""
        proc = _make_proc()
        mock_sock = _make_context_sock(sendto_return=5)
        msg = b'\x00\x01\x02'

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess.send_any(proc, msg)

        sent_data = mock_sock.sendto.call_args[0][0]
        assert sent_data == msg


# ---------------------------------------------------------------------------
# _recv_udp
# ---------------------------------------------------------------------------

class TestRecvUdp:
    def _sock_returning(self, msg, addr, port):
        """Return a mock socket whose recvfrom() returns (msg, (addr, port))."""
        sock = MagicMock()
        sock.recvfrom.return_value = (msg, (addr, port))
        return sock

    def test_normal_message_returned(self):
        """_recv_udp returns (msg, addr, port) for a valid, non-self, non-rejected message."""
        proc = _make_proc(my_address='192.168.1.10', reject=False)
        sock = self._sock_returning(b'hello', '10.0.0.5', 9000)
        result = UDPNetworkProcess._recv_udp(proc, sock, 65507)
        assert result == (b'hello', '10.0.0.5', 9000)

    def test_recvfrom_called_with_packet_size(self):
        """_recv_udp calls sock.recvfrom with the given packet_size."""
        proc = _make_proc(my_address='192.168.1.10', reject=False)
        sock = self._sock_returning(b'data', '10.0.0.5', 9000)
        UDPNetworkProcess._recv_udp(proc, sock, 1024)
        sock.recvfrom.assert_called_once_with(1024)

    def test_own_address_returns_none_triple(self):
        """_recv_udp returns (None, None, None) when sender == self.my_address."""
        proc = _make_proc(my_address='192.168.1.10', reject=False)
        sock = self._sock_returning(b'self msg', '192.168.1.10', 9000)
        result = UDPNetworkProcess._recv_udp(proc, sock, 65507)
        assert result == (None, None, None)

    def test_rejected_msg_returns_none_addr_port(self):
        """_recv_udp returns (None, addr, port) when reject_message returns True."""
        proc = _make_proc(my_address='192.168.1.10', reject=True)
        sock = self._sock_returning(b'bad msg', '10.0.0.5', 9000)
        result = UDPNetworkProcess._recv_udp(proc, sock, 65507)
        assert result == (None, '10.0.0.5', 9000)

    def test_reject_message_called_with_sender_addr(self):
        """_recv_udp calls reject_message with the sender's IP address."""
        proc = _make_proc(my_address='192.168.1.10', reject=False)
        sock = self._sock_returning(b'msg', '10.0.0.5', 9000)
        UDPNetworkProcess._recv_udp(proc, sock, 65507)
        proc.reject_message.assert_called_once_with('10.0.0.5')

    def test_own_address_does_not_call_reject(self):
        """_recv_udp does not call reject_message when the message is from self."""
        proc = _make_proc(my_address='192.168.1.10', reject=False)
        sock = self._sock_returning(b'self msg', '192.168.1.10', 9000)
        UDPNetworkProcess._recv_udp(proc, sock, 65507)
        proc.reject_message.assert_not_called()


# ---------------------------------------------------------------------------
# recv_peer / recv_group / recv_any — delegation
# ---------------------------------------------------------------------------

class TestRecvDelegation:
    def test_recv_peer_uses_recv_ptp_sock_and_packet_size(self):
        """recv_peer calls _recv_udp with recv_ptp_sock and packet_size."""
        proc = _make_proc(packet_size=65507)
        proc._recv_udp.return_value = (b'msg', '10.0.0.1', 9000)
        UDPNetworkProcess.recv_peer(proc)
        proc._recv_udp.assert_called_once_with(proc.recv_ptp_sock, 65507)

    def test_recv_group_uses_recv_grp_sock_and_packet_size(self):
        """recv_group calls _recv_udp with recv_grp_sock and packet_size."""
        proc = _make_proc(packet_size=65507)
        proc._recv_udp.return_value = (b'msg', '10.0.0.1', 9001)
        UDPNetworkProcess.recv_group(proc)
        proc._recv_udp.assert_called_once_with(proc.recv_grp_sock, 65507)

    def test_recv_any_uses_recv_cast_sock_and_manycast_packet_size(self):
        """recv_any calls _recv_udp with recv_cast_sock and manycast_packet_size."""
        proc = _make_proc(manycast_packet_size=65527)
        proc._recv_udp.return_value = (b'msg', '192.168.1.255', 9000)
        UDPNetworkProcess.recv_any(proc)
        proc._recv_udp.assert_called_once_with(proc.recv_cast_sock, 65527)

    def test_recv_peer_returns_recv_udp_result(self):
        """recv_peer passes through the result from _recv_udp unchanged."""
        proc = _make_proc()
        proc._recv_udp.return_value = (b'hello', '1.2.3.4', 9000)
        result = UDPNetworkProcess.recv_peer(proc)
        assert result == (b'hello', '1.2.3.4', 9000)

    def test_recv_group_returns_recv_udp_result(self):
        """recv_group passes through the result from _recv_udp unchanged."""
        proc = _make_proc()
        proc._recv_udp.return_value = (None, '1.2.3.4', 9001)
        result = UDPNetworkProcess.recv_group(proc)
        assert result == (None, '1.2.3.4', 9001)

    def test_recv_any_returns_recv_udp_result(self):
        """recv_any passes through the result from _recv_udp unchanged."""
        proc = _make_proc()
        proc._recv_udp.return_value = (None, None, None)
        result = UDPNetworkProcess.recv_any(proc)
        assert result == (None, None, None)


# ---------------------------------------------------------------------------
# _init_udp_ptp
# ---------------------------------------------------------------------------

class TestInitUdpPtp:
    def test_binds_to_my_address_and_port(self):
        """_init_udp_ptp binds the PTP socket to (my_address, port)."""
        proc = _make_proc(my_address='192.168.1.10', port=8000)
        mock_sock = MagicMock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_udp_ptp(proc)

        mock_sock.bind.assert_called_once_with(('192.168.1.10', 8000))

    def test_setsockopt_reuseaddr(self):
        """_init_udp_ptp sets SO_REUSEADDR on the socket."""
        proc = _make_proc()
        mock_sock = MagicMock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_udp_ptp(proc)

        mock_sock.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def test_bind_failure_propagates(self):
        """_init_udp_ptp re-raises OSError from bind."""
        proc = _make_proc()
        mock_sock = MagicMock()
        mock_sock.bind.side_effect = OSError('address in use')

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(OSError):
                UDPNetworkProcess._init_udp_ptp(proc)

    def test_bind_failure_logs_error(self):
        """_init_udp_ptp logs an error message before re-raising."""
        proc = _make_proc()
        mock_sock = MagicMock()
        mock_sock.bind.side_effect = OSError('fail')

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(OSError):
                UDPNetworkProcess._init_udp_ptp(proc)

        proc.logger.error.assert_called_once()

    def test_assigns_recv_ptp_sock(self):
        """_init_udp_ptp assigns the new socket to proc.recv_ptp_sock."""
        proc = _make_proc()
        mock_sock = MagicMock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_udp_ptp(proc)

        assert proc.recv_ptp_sock is mock_sock


# ---------------------------------------------------------------------------
# _init_udp_grp
# ---------------------------------------------------------------------------

class TestInitUdpGrp:
    def test_binds_to_my_address_and_group_port(self):
        """_init_udp_grp binds the group socket to (my_address, group_port)."""
        proc = _make_proc(my_address='192.168.1.10', group_port=8001)
        mock_sock = MagicMock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_udp_grp(proc)

        mock_sock.bind.assert_called_once_with(('192.168.1.10', 8001))

    def test_setsockopt_reuseaddr(self):
        """_init_udp_grp sets SO_REUSEADDR on the group socket."""
        proc = _make_proc()
        mock_sock = MagicMock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_udp_grp(proc)

        mock_sock.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def test_bind_failure_propagates(self):
        """_init_udp_grp re-raises OSError from bind."""
        proc = _make_proc()
        mock_sock = MagicMock()
        mock_sock.bind.side_effect = OSError('fail')

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(OSError):
                UDPNetworkProcess._init_udp_grp(proc)

    def test_bind_failure_logs_error(self):
        """_init_udp_grp logs an error message before re-raising."""
        proc = _make_proc()
        mock_sock = MagicMock()
        mock_sock.bind.side_effect = OSError('fail')

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(OSError):
                UDPNetworkProcess._init_udp_grp(proc)

        proc.logger.error.assert_called_once()

    def test_assigns_recv_grp_sock(self):
        """_init_udp_grp assigns the new socket to proc.recv_grp_sock."""
        proc = _make_proc()
        mock_sock = MagicMock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_udp_grp(proc)

        assert proc.recv_grp_sock is mock_sock


# ---------------------------------------------------------------------------
# _init_mcast — broadcast path (use_mcast=False)
# ---------------------------------------------------------------------------

class TestInitMcastBroadcast:
    """Tests for the broadcast (non-multicast) branch of _init_mcast."""

    def _net_cfg(self, ip4='192.168.1.10', broadcast='192.168.1.255',
                 mcast='239.0.0.1'):
        cfg = MagicMock()
        cfg.ip4 = ip4
        cfg.ip4_broadcast = broadcast
        cfg.multicast_v4_address = mcast
        return cfg

    def _sock(self, bind_side_effect=None, getsockname_addr='192.168.1.255', port=8000):
        """Return a mock socket with getsockname() returning a real 2-tuple."""
        sock = MagicMock()
        sock.getsockname.return_value = (getsockname_addr, port)
        if bind_side_effect is not None:
            sock.bind.side_effect = bind_side_effect
        return sock

    def test_broadcast_binds_to_broadcast_addr(self):
        """Broadcast path binds recv_cast_sock to (ip4_broadcast, port)."""
        proc = _make_proc(my_address='192.168.1.10', port=8000)
        proc.net_cfg = self._net_cfg()
        mock_sock = self._sock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=False)

        mock_sock.bind.assert_called_once_with(('192.168.1.255', 8000))

    def test_broadcast_sets_sock_options_to_broadcast(self):
        """Broadcast path sets proc.sock_options to SO_BROADCAST tuple."""
        proc = _make_proc()
        proc.net_cfg = self._net_cfg()
        mock_sock = self._sock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=False)

        assert proc.sock_options == (socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def test_broadcast_sets_manycast_addr(self):
        """Broadcast path sets proc.manycast_addr to net_cfg.ip4_broadcast."""
        proc = _make_proc()
        proc.net_cfg = self._net_cfg(broadcast='10.255.255.255')
        mock_sock = self._sock(getsockname_addr='10.255.255.255')

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=False)

        assert proc.manycast_addr == '10.255.255.255'

    def test_broadcast_sets_manycast_packet_size(self):
        """Broadcast path sets manycast_packet_size to 65507."""
        proc = _make_proc()
        proc.net_cfg = self._net_cfg()
        mock_sock = self._sock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=False)

        assert proc.manycast_packet_size == 65507

    def test_broadcast_bind_failure_propagates(self):
        """Broadcast path re-raises OSError from bind."""
        proc = _make_proc()
        proc.net_cfg = self._net_cfg()
        mock_sock = self._sock(bind_side_effect=OSError('fail'))

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(OSError):
                UDPNetworkProcess._init_mcast(proc, use_mcast=False)

    def test_broadcast_bind_failure_logs_error(self):
        """Broadcast path logs error before re-raising on bind failure."""
        proc = _make_proc()
        proc.net_cfg = self._net_cfg()
        mock_sock = self._sock(bind_side_effect=OSError('fail'))

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(OSError):
                UDPNetworkProcess._init_mcast(proc, use_mcast=False)

        proc.logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# _init_mcast — multicast path (use_mcast=True)
# ---------------------------------------------------------------------------

class TestInitMcastMulticast:
    """Tests for the multicast branch of _init_mcast."""

    def _net_cfg(self, ip4='192.168.1.10', mcast='239.0.0.1',
                 broadcast='192.168.1.255'):
        cfg = MagicMock()
        cfg.ip4 = ip4
        cfg.ip4_broadcast = broadcast
        cfg.multicast_v4_address = mcast
        return cfg

    def _sock(self, bind_side_effect=None, getsockname_addr='239.0.0.1', port=8000):
        """Return a mock socket with getsockname() returning a real 2-tuple."""
        sock = MagicMock()
        sock.getsockname.return_value = (getsockname_addr, port)
        if bind_side_effect is not None:
            sock.bind.side_effect = bind_side_effect
        return sock

    def test_multicast_binds_to_mcast_addr(self):
        """Multicast path binds recv_cast_sock to (multicast_v4_address, port)."""
        proc = _make_proc(my_address='192.168.1.10', port=8000)
        proc.net_cfg = self._net_cfg(mcast='239.0.0.1')
        mock_sock = self._sock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=True)

        mock_sock.bind.assert_called_once_with(('239.0.0.1', 8000))

    def test_multicast_sets_sock_options_to_multicast_ttl(self):
        """Multicast path sets proc.sock_options to IP_MULTICAST_TTL tuple."""
        proc = _make_proc(my_address='192.168.1.10')
        proc.net_cfg = self._net_cfg()
        # mcast_ttl is a class attribute; the mock must expose it as a plain int.
        proc.mcast_ttl = UDPNetworkProcess.mcast_ttl
        mock_sock = self._sock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=True)

        assert proc.sock_options == (
            socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, UDPNetworkProcess.mcast_ttl)

    def test_multicast_sets_manycast_addr(self):
        """Multicast path sets proc.manycast_addr to multicast_v4_address."""
        proc = _make_proc()
        proc.net_cfg = self._net_cfg(mcast='224.0.0.1')
        mock_sock = self._sock(getsockname_addr='224.0.0.1')

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=True)

        assert proc.manycast_addr == '224.0.0.1'

    def test_multicast_sets_larger_manycast_packet_size(self):
        """Multicast path sets manycast_packet_size to 65527."""
        proc = _make_proc()
        proc.net_cfg = self._net_cfg()
        mock_sock = self._sock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=True)

        assert proc.manycast_packet_size == 65527

    def test_multicast_calls_add_membership_setsockopt(self):
        """Multicast path calls setsockopt(IP_ADD_MEMBERSHIP, ...) on the socket."""
        proc = _make_proc(my_address='192.168.1.10')
        proc.net_cfg = self._net_cfg(mcast='239.0.0.1')
        mock_sock = self._sock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=True)

        # Find the IP_ADD_MEMBERSHIP call among setsockopt calls
        calls = mock_sock.setsockopt.call_args_list
        membership_calls = [c for c in calls
                            if c[0][0] == socket.IPPROTO_IP
                            and c[0][1] == socket.IP_ADD_MEMBERSHIP]
        assert len(membership_calls) == 1

    def test_multicast_with_specific_address_uses_4s4s_pack(self):
        """With a specific (non-0.0.0.0) IP, membership req packs 4s+4s."""
        proc = _make_proc(my_address='192.168.1.10')
        proc.net_cfg = self._net_cfg(mcast='239.0.0.1')
        mock_sock = self._sock()

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=True)

        calls = mock_sock.setsockopt.call_args_list
        membership_calls = [c for c in calls
                            if c[0][0] == socket.IPPROTO_IP
                            and c[0][1] == socket.IP_ADD_MEMBERSHIP]
        req_arg = membership_calls[0][0][2]
        expected = struct.pack("=4s4s",
                               socket.inet_aton('239.0.0.1'),
                               socket.inet_aton('192.168.1.10'))
        assert req_arg == expected

    def test_multicast_with_any_address_uses_4sl_pack(self):
        """With my_address == '0.0.0.0', membership req packs 4s+l (INADDR_ANY)."""
        proc = _make_proc(my_address='0.0.0.0')
        proc.net_cfg = self._net_cfg(ip4='0.0.0.0', mcast='239.0.0.1')
        mock_sock = self._sock(getsockname_addr='239.0.0.1')

        with patch('socket.socket', return_value=mock_sock):
            UDPNetworkProcess._init_mcast(proc, use_mcast=True)

        calls = mock_sock.setsockopt.call_args_list
        membership_calls = [c for c in calls
                            if c[0][0] == socket.IPPROTO_IP
                            and c[0][1] == socket.IP_ADD_MEMBERSHIP]
        req_arg = membership_calls[0][0][2]
        expected = struct.pack("=4sl",
                               socket.inet_aton('239.0.0.1'),
                               socket.INADDR_ANY)
        assert req_arg == expected

    def test_multicast_bind_failure_propagates(self):
        """Multicast path re-raises OSError from bind."""
        proc = _make_proc()
        proc.net_cfg = self._net_cfg()
        mock_sock = self._sock(bind_side_effect=OSError('fail'))

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(OSError):
                UDPNetworkProcess._init_mcast(proc, use_mcast=True)

    def test_multicast_bind_failure_logs_error(self):
        """Multicast path logs error before re-raising on bind failure."""
        proc = _make_proc()
        proc.net_cfg = self._net_cfg()
        mock_sock = self._sock(bind_side_effect=OSError('fail'))

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(OSError):
                UDPNetworkProcess._init_mcast(proc, use_mcast=True)

        proc.logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# Original integration tests (preserved, require live config via setup_teardown)
# ---------------------------------------------------------------------------

from autonomous_trust.core.network.udp import UDPNetworkProcess as _UDP  # noqa: F811
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.automate import AutonomousTrust
from autonomous_trust.core.system import CfgIds


def test_reject(setup_teardown):
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    net_addr = cfgs[CfgIds.network].ip4
    udp = _UDP(cfgs, dict({}), None)
    udp.send_peer('test1', net_addr)
    msg_tpl = udp.recv_peer()
    # Sending to own address: _recv_udp returns (None, None, None)
    assert msg_tpl == (None, None, None)


def test_p2p(setup_teardown):
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    net_addr = cfgs[CfgIds.network].ip4
    udp = _UDP(cfgs, dict({}), None, acceptance_func=lambda x: True)
    udp.send_peer('test1', net_addr)
    msg_tpl = udp.recv_peer()
    assert b'test1' == msg_tpl[0]
    assert net_addr == msg_tpl[1]


@pytest.mark.skip(reason="blocked by firewall")
def test_mcast(setup_teardown):
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    udp = _UDP(cfgs, dict({}), None)
    udp.send_any('test2')
    assert 'test2' == udp.recv_any()
