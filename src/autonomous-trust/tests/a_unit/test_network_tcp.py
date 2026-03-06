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
Unit tests for TCPNetworkProcess._send_tcp, ._recv, .recv_peer, and .recv_group.

All mocked tests use a MagicMock instance in place of a real TCPNetworkProcess
object, then call the unbound methods directly (Class.method(mock, ...)) to
exercise method bodies without triggering __init__ or any network I/O.

The original integration tests (which require a live config) are preserved at
the bottom of this file.
"""

import socket
import pytest
from unittest.mock import patch, MagicMock

from autonomous_trust.core.network.tcp import TCPNetworkProcess
from autonomous_trust.core.network.netprocess import TransmissionError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proc(my_address='192.168.1.10', port=8000, group_port=8001,
               enc='utf-8', accept_peer=True, accept_group=True):
    """Return a minimal mock satisfying TCPNetworkProcess method contracts."""
    proc = MagicMock(spec=TCPNetworkProcess)
    proc.enc = enc
    proc.my_address = my_address
    proc.port = port
    proc.group_port = group_port
    proc.logger = MagicMock()
    proc.accept_peer_message.return_value = accept_peer
    proc.accept_group_message.return_value = accept_group
    # These sockets are assigned in __init__ so they are not covered by spec;
    # add them manually so tests that call recv_peer / recv_group can configure them.
    proc.recv_ptp_sock = MagicMock()
    proc.recv_grp_sock = MagicMock()
    return proc


def _make_context_sock(send_side_effect=None):
    """
    Return a MagicMock socket that works as a context manager.
    send_side_effect is forwarded to sock.send.side_effect.
    """
    sock = MagicMock()
    sock.__enter__ = lambda s: sock
    sock.__exit__ = MagicMock(return_value=False)
    if send_side_effect is not None:
        sock.send.side_effect = send_side_effect
    return sock


# ---------------------------------------------------------------------------
# _send_tcp — bytes message (happy path)
# ---------------------------------------------------------------------------

class TestSendTcpBytes:
    """_send_tcp sends bytes messages end-to-end without encoding."""

    def test_bytes_msg_connects_and_sends(self):
        """Bytes message: connect is called, prefix and data are sent."""
        proc = _make_proc()
        msg = b'hello'
        # send() for prefix "5|" returns 2; send() for data returns 5
        mock_sock = _make_context_sock(send_side_effect=[2, 5])

        with patch('socket.socket', return_value=mock_sock):
            TCPNetworkProcess._send_tcp(proc, msg, 'remotehost', 9000)

        mock_sock.connect.assert_called_once_with(('remotehost', 9000))
        assert mock_sock.send.call_count == 2

    def test_bytes_msg_prefix_format(self):
        """Length prefix sent is '<len>|' encoded as bytes."""
        proc = _make_proc()
        msg = b'hello'
        mock_sock = _make_context_sock(send_side_effect=[2, 5])

        with patch('socket.socket', return_value=mock_sock):
            TCPNetworkProcess._send_tcp(proc, msg, 'remotehost', 9000)

        prefix_arg = mock_sock.send.call_args_list[0][0][0]
        assert prefix_arg == b'5|'

    def test_bytes_msg_data_sent_as_bytes(self):
        """Data send argument is the original bytes message (not re-encoded)."""
        proc = _make_proc()
        msg = b'hello'
        mock_sock = _make_context_sock(send_side_effect=[2, 5])

        with patch('socket.socket', return_value=mock_sock):
            TCPNetworkProcess._send_tcp(proc, msg, 'remotehost', 9000)

        data_arg = mock_sock.send.call_args_list[1][0][0]
        assert data_arg == b'hello'

    def test_partial_data_sends_loop(self):
        """When send() returns fewer bytes than the message length, the loop continues."""
        proc = _make_proc()
        msg = b'abcde'
        # prefix "5|" → 2; first data chunk → 3; second data chunk → 2
        mock_sock = _make_context_sock(send_side_effect=[2, 3, 2])

        with patch('socket.socket', return_value=mock_sock):
            TCPNetworkProcess._send_tcp(proc, msg, 'remotehost', 9000)

        assert mock_sock.send.call_count == 3
        # Second call: full message from offset 0
        assert mock_sock.send.call_args_list[1][0][0] == b'abcde'
        # Third call: remaining 2 bytes
        assert mock_sock.send.call_args_list[2][0][0] == b'de'

    def test_uses_ipv4_stream_socket(self):
        """socket.socket is created with AF_INET and SOCK_STREAM."""
        proc = _make_proc()
        mock_sock = _make_context_sock(send_side_effect=[2, 5])

        with patch('socket.socket', return_value=mock_sock) as mock_socket_cls:
            TCPNetworkProcess._send_tcp(proc, b'hello', 'remotehost', 9000)

        mock_socket_cls.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)


# ---------------------------------------------------------------------------
# _send_tcp — string message (encoding path)
# ---------------------------------------------------------------------------

class TestSendTcpString:
    """_send_tcp encodes string messages using proc.enc before sending."""

    def test_string_gets_encoded_to_bytes(self):
        """A str message is encoded to bytes; the data send argument is bytes."""
        proc = _make_proc()
        mock_sock = _make_context_sock(send_side_effect=[2, 5])

        with patch('socket.socket', return_value=mock_sock):
            TCPNetworkProcess._send_tcp(proc, 'hello', 'remotehost', 9000)

        data_arg = mock_sock.send.call_args_list[1][0][0]
        assert isinstance(data_arg, bytes)
        assert data_arg == b'hello'

    def test_string_prefix_reflects_encoded_length(self):
        """The length prefix matches the byte length of the encoded string."""
        proc = _make_proc()
        # 'hello' encodes to 5 bytes in utf-8
        mock_sock = _make_context_sock(send_side_effect=[2, 5])

        with patch('socket.socket', return_value=mock_sock):
            TCPNetworkProcess._send_tcp(proc, 'hello', 'remotehost', 9000)

        prefix_arg = mock_sock.send.call_args_list[0][0][0]
        assert prefix_arg == b'5|'

    def test_non_ascii_string_uses_enc(self):
        """Non-ASCII strings are encoded using proc.enc (utf-8)."""
        proc = _make_proc(enc='utf-8')
        msg = 'café'   # 5 bytes in utf-8
        encoded = msg.encode('utf-8')
        mock_sock = _make_context_sock(send_side_effect=[2, len(encoded)])

        with patch('socket.socket', return_value=mock_sock):
            TCPNetworkProcess._send_tcp(proc, msg, 'remotehost', 9000)

        data_arg = mock_sock.send.call_args_list[1][0][0]
        assert data_arg == encoded


# ---------------------------------------------------------------------------
# _send_tcp — connect failure
# ---------------------------------------------------------------------------

class TestSendTcpConnectFailure:
    def test_connect_socket_error_raises_transmission_error(self):
        """socket.error during connect is wrapped and raised as TransmissionError."""
        proc = _make_proc()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.error('connection refused')
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(TransmissionError, match='Connect'):
                TCPNetworkProcess._send_tcp(proc, b'data', 'remotehost', 9000)

    def test_connect_error_message_included(self):
        """The underlying error text from socket.error is included in TransmissionError."""
        proc = _make_proc()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.error('ECONNREFUSED')
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(TransmissionError, match='ECONNREFUSED'):
                TCPNetworkProcess._send_tcp(proc, b'data', 'remotehost', 9000)


# ---------------------------------------------------------------------------
# _send_tcp — prefix send failures
# ---------------------------------------------------------------------------

class TestSendTcpPrefixFailure:
    def test_prefix_send_socket_error_raises_transmission_error(self):
        """socket.error during length-prefix send raises TransmissionError."""
        proc = _make_proc()
        mock_sock = _make_context_sock(send_side_effect=socket.error('send failed'))

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(TransmissionError, match='Send'):
                TCPNetworkProcess._send_tcp(proc, b'data', 'remotehost', 9000)

    def test_prefix_send_returns_zero_raises_transmission_error(self):
        """send() returning 0 for the length prefix raises TransmissionError."""
        proc = _make_proc()
        mock_sock = _make_context_sock(send_side_effect=[0])

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(TransmissionError, match='no bytes sent'):
                TCPNetworkProcess._send_tcp(proc, b'data', 'remotehost', 9000)


# ---------------------------------------------------------------------------
# _send_tcp — data loop failures
# ---------------------------------------------------------------------------

class TestSendTcpDataLoopFailure:
    def test_data_send_socket_error_in_loop_raises_transmission_error(self):
        """socket.error during the data-send loop raises TransmissionError."""
        proc = _make_proc()
        # Prefix send succeeds (returns 2), data send raises
        mock_sock = _make_context_sock(send_side_effect=[2, socket.error('broken pipe')])

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(TransmissionError):
                TCPNetworkProcess._send_tcp(proc, b'data', 'remotehost', 9000)

    def test_data_send_returns_zero_in_loop_raises_transmission_error(self):
        """send() returning 0 during the data-send loop raises TransmissionError."""
        proc = _make_proc()
        # Prefix succeeds, data send returns 0
        mock_sock = _make_context_sock(send_side_effect=[2, 0])

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(TransmissionError, match='no bytes sent'):
                TCPNetworkProcess._send_tcp(proc, b'data', 'remotehost', 9000)

    def test_data_send_error_on_second_chunk_raises(self):
        """Error on second iteration of the data-send loop also raises."""
        proc = _make_proc()
        msg = b'abcde'
        # Prefix ok, first chunk partial (3 bytes), second chunk errors
        mock_sock = _make_context_sock(send_side_effect=[2, 3, socket.error('pipe reset')])

        with patch('socket.socket', return_value=mock_sock):
            with pytest.raises(TransmissionError):
                TCPNetworkProcess._send_tcp(proc, msg, 'remotehost', 9000)


# ---------------------------------------------------------------------------
# send_peer / send_group — port delegation
# ---------------------------------------------------------------------------

class TestSendPeerGroupDelegation:
    def test_send_peer_uses_self_port(self):
        """send_peer calls _send_tcp with self.port (not group_port)."""
        proc = _make_proc(port=8000, group_port=8001)
        proc._send_tcp = MagicMock()
        TCPNetworkProcess.send_peer(proc, b'msg', '10.0.0.1')
        proc._send_tcp.assert_called_once_with(b'msg', '10.0.0.1', 8000)

    def test_send_group_uses_group_port(self):
        """send_group calls _send_tcp with self.group_port (not port)."""
        proc = _make_proc(port=8000, group_port=8001)
        proc._send_tcp = MagicMock()
        TCPNetworkProcess.send_group(proc, b'msg', '10.0.0.1')
        proc._send_tcp.assert_called_once_with(b'msg', '10.0.0.1', 8001)

    def test_send_peer_forwards_message_unchanged(self):
        """send_peer forwards the message argument unchanged to _send_tcp."""
        proc = _make_proc()
        proc._send_tcp = MagicMock()
        TCPNetworkProcess.send_peer(proc, b'exact_payload', '10.0.0.1')
        assert proc._send_tcp.call_args[0][0] == b'exact_payload'

    def test_send_group_forwards_message_unchanged(self):
        """send_group forwards the message argument unchanged to _send_tcp."""
        proc = _make_proc()
        proc._send_tcp = MagicMock()
        TCPNetworkProcess.send_group(proc, b'grp_payload', '10.0.0.1')
        assert proc._send_tcp.call_args[0][0] == b'grp_payload'


# ---------------------------------------------------------------------------
# _recv — helpers
# ---------------------------------------------------------------------------

def _build_recv_sock(msg_bytes, enc='utf-8', empty_chunk=False):
    """
    Build a mock socket whose recv(1) calls replay the length prefix byte-by-byte,
    followed by a recv(N) call that returns msg_bytes (or b'' to trigger the error
    path when empty_chunk=True).
    """
    sock = MagicMock()
    length_str = str(len(msg_bytes))
    prefix = (length_str + '|').encode(enc)
    single_byte_calls = [bytes([b]) for b in prefix]
    single_byte_calls.append(b'' if empty_chunk else msg_bytes)
    sock.recv.side_effect = single_byte_calls
    return sock


# ---------------------------------------------------------------------------
# _recv — normal message
# ---------------------------------------------------------------------------

class TestRecv:
    def test_normal_short_message(self):
        """_recv decodes and returns a short message correctly."""
        proc = _make_proc()
        sock = _build_recv_sock(b'hello world')
        result = TCPNetworkProcess._recv(proc, sock)
        assert result == 'hello world'

    def test_empty_body_message(self):
        """_recv handles a zero-length body (prefix '0|') without error."""
        proc = _make_proc()
        # '0|' then recv returns b'' — but b'' for chunk triggers the error;
        # A 0-length message means the while loop condition is immediately false,
        # so recv(N) is never called.
        sock = MagicMock()
        prefix = b'0|'
        single_byte_calls = [bytes([b]) for b in prefix]
        sock.recv.side_effect = single_byte_calls
        result = TCPNetworkProcess._recv(proc, sock)
        assert result == ''

    def test_multi_chunk_message(self):
        """_recv reassembles multi-chunk messages correctly."""
        proc = _make_proc()
        msg = b'x' * 4096
        sock = MagicMock()
        prefix = (str(len(msg)) + '|').encode('utf-8')
        calls = [bytes([b]) for b in prefix]
        # Simulate recv returning 2048 bytes at a time
        calls.append(msg[:2048])
        calls.append(msg[2048:])
        sock.recv.side_effect = calls
        result = TCPNetworkProcess._recv(proc, sock)
        assert result == 'x' * 4096

    def test_empty_chunk_raises_transmission_error(self):
        """_recv raises TransmissionError when a data chunk is b'' (connection broken)."""
        proc = _make_proc()
        sock = _build_recv_sock(b'hello', empty_chunk=True)
        with pytest.raises(TransmissionError, match='no bytes sent'):
            TCPNetworkProcess._recv(proc, sock)

    def test_result_is_decoded_string(self):
        """_recv returns a str, not bytes."""
        proc = _make_proc()
        sock = _build_recv_sock(b'test')
        result = TCPNetworkProcess._recv(proc, sock)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# recv_peer
# ---------------------------------------------------------------------------

class TestRecvPeer:
    def test_own_address_returns_none_triple(self):
        """recv_peer returns (None, None, None) when sender IP equals self.my_address."""
        proc = _make_proc(my_address='192.168.1.10')
        client_sock = MagicMock()
        proc.recv_ptp_sock.accept.return_value = (client_sock, ('192.168.1.10', 55001))
        result = TCPNetworkProcess.recv_peer(proc)
        assert result == (None, None, None)

    def test_own_address_does_not_call_recv(self):
        """recv_peer does not call _recv when the sender is self."""
        proc = _make_proc(my_address='192.168.1.10')
        proc.recv_ptp_sock.accept.return_value = (MagicMock(), ('192.168.1.10', 55001))
        TCPNetworkProcess.recv_peer(proc)
        proc._recv.assert_not_called()

    def test_rejected_peer_returns_none_addr_port(self):
        """recv_peer returns (None, addr, port) when accept_peer_message is False."""
        proc = _make_proc(my_address='192.168.1.10', accept_peer=False)
        proc.recv_ptp_sock.accept.return_value = (MagicMock(), ('10.0.0.5', 55001))
        result = TCPNetworkProcess.recv_peer(proc)
        assert result == (None, '10.0.0.5', 55001)

    def test_rejected_peer_does_not_call_recv(self):
        """recv_peer does not call _recv for rejected senders."""
        proc = _make_proc(my_address='192.168.1.10', accept_peer=False)
        proc.recv_ptp_sock.accept.return_value = (MagicMock(), ('10.0.0.5', 55001))
        TCPNetworkProcess.recv_peer(proc)
        proc._recv.assert_not_called()

    def test_accepted_peer_returns_message_addr_port(self):
        """recv_peer returns (msg, addr, port) for an accepted, non-self connection."""
        proc = _make_proc(my_address='192.168.1.10', accept_peer=True)
        client_sock = MagicMock()
        proc.recv_ptp_sock.accept.return_value = (client_sock, ('10.0.0.5', 55001))
        proc._recv.return_value = 'hello from peer'
        result = TCPNetworkProcess.recv_peer(proc)
        assert result == ('hello from peer', '10.0.0.5', 55001)

    def test_accepted_peer_calls_recv_with_client_sock(self):
        """recv_peer passes the accepted client socket to _recv."""
        proc = _make_proc(my_address='192.168.1.10', accept_peer=True)
        client_sock = MagicMock()
        proc.recv_ptp_sock.accept.return_value = (client_sock, ('10.0.0.5', 55001))
        proc._recv.return_value = 'data'
        TCPNetworkProcess.recv_peer(proc)
        proc._recv.assert_called_once_with(client_sock)

    def test_accept_peer_message_called_with_sender_addr(self):
        """recv_peer calls accept_peer_message with the sender's IP address."""
        proc = _make_proc(my_address='192.168.1.10', accept_peer=True)
        proc.recv_ptp_sock.accept.return_value = (MagicMock(), ('10.0.0.5', 55001))
        proc._recv.return_value = 'data'
        TCPNetworkProcess.recv_peer(proc)
        proc.accept_peer_message.assert_called_once_with('10.0.0.5')


# ---------------------------------------------------------------------------
# recv_group
# ---------------------------------------------------------------------------

class TestRecvGroup:
    def test_own_address_returns_none_triple(self):
        """recv_group returns (None, None, None) when sender IP equals self.my_address."""
        proc = _make_proc(my_address='192.168.1.10')
        proc.recv_grp_sock.accept.return_value = (MagicMock(), ('192.168.1.10', 55002))
        result = TCPNetworkProcess.recv_group(proc)
        assert result == (None, None, None)

    def test_own_address_does_not_call_recv(self):
        """recv_group does not call _recv when the sender is self."""
        proc = _make_proc(my_address='192.168.1.10')
        proc.recv_grp_sock.accept.return_value = (MagicMock(), ('192.168.1.10', 55002))
        TCPNetworkProcess.recv_group(proc)
        proc._recv.assert_not_called()

    def test_rejected_group_message_returns_none_addr_port(self):
        """recv_group returns (None, addr, port) when accept_group_message is False."""
        proc = _make_proc(my_address='192.168.1.10', accept_group=False)
        proc.recv_grp_sock.accept.return_value = (MagicMock(), ('10.0.0.5', 55002))
        result = TCPNetworkProcess.recv_group(proc)
        assert result == (None, '10.0.0.5', 55002)

    def test_rejected_group_does_not_call_recv(self):
        """recv_group does not call _recv for rejected group senders."""
        proc = _make_proc(my_address='192.168.1.10', accept_group=False)
        proc.recv_grp_sock.accept.return_value = (MagicMock(), ('10.0.0.5', 55002))
        TCPNetworkProcess.recv_group(proc)
        proc._recv.assert_not_called()

    def test_accepted_group_message_returns_message_addr_port(self):
        """recv_group returns (msg, addr, port) for an accepted, non-self group connection."""
        proc = _make_proc(my_address='192.168.1.10', accept_group=True)
        client_sock = MagicMock()
        proc.recv_grp_sock.accept.return_value = (client_sock, ('10.0.0.5', 55002))
        proc._recv.return_value = 'group broadcast'
        result = TCPNetworkProcess.recv_group(proc)
        assert result == ('group broadcast', '10.0.0.5', 55002)

    def test_accepted_group_calls_recv_with_client_sock(self):
        """recv_group passes the accepted client socket to _recv."""
        proc = _make_proc(my_address='192.168.1.10', accept_group=True)
        client_sock = MagicMock()
        proc.recv_grp_sock.accept.return_value = (client_sock, ('10.0.0.5', 55002))
        proc._recv.return_value = 'data'
        TCPNetworkProcess.recv_group(proc)
        proc._recv.assert_called_once_with(client_sock)

    def test_accept_group_message_called_with_sender_addr(self):
        """recv_group calls accept_group_message with the sender's IP address."""
        proc = _make_proc(my_address='192.168.1.10', accept_group=True)
        proc.recv_grp_sock.accept.return_value = (MagicMock(), ('10.0.0.5', 55002))
        proc._recv.return_value = 'data'
        TCPNetworkProcess.recv_group(proc)
        proc.accept_group_message.assert_called_once_with('10.0.0.5')

    def test_recv_group_uses_recv_grp_sock_not_ptp(self):
        """recv_group accepts on recv_grp_sock, not recv_ptp_sock."""
        proc = _make_proc(my_address='192.168.1.10', accept_group=True)
        proc.recv_grp_sock.accept.return_value = (MagicMock(), ('10.0.0.5', 55002))
        proc._recv.return_value = 'data'
        TCPNetworkProcess.recv_group(proc)
        proc.recv_grp_sock.accept.assert_called_once()
        proc.recv_ptp_sock.accept.assert_not_called()


# ---------------------------------------------------------------------------
# Original integration tests (preserved, require live config via setup_teardown)
# ---------------------------------------------------------------------------

from autonomous_trust.core.network.tcp import TCPNetworkProcess as _TCP  # noqa: F811
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.automate import AutonomousTrust
from autonomous_trust.core.system import CfgIds


def test_reject(setup_teardown):
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    net_addr = cfgs[CfgIds.network].ip4
    tcp = _TCP(cfgs, dict({}), None)
    tcp.send_peer('test1', net_addr)
    msg_tpl = tcp.recv_peer()
    print(msg_tpl)
    assert msg_tpl[0] is None
    #assert net_addr == msg_tpl[1][0]


def test_p2p(setup_teardown):
    """Self-addressed messages are dropped even when acceptance_func accepts all."""
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    net_addr = cfgs[CfgIds.network].ip4
    tcp = _TCP(cfgs, dict({}), None, acceptance_func=lambda x: True)
    tcp.send_peer('test1', net_addr)
    msg_tpl = tcp.recv_peer()
    assert msg_tpl == (None, None, None)


@pytest.mark.skip(reason="blocked by firewall")
def test_mcast(setup_teardown):
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    tcp = _TCP(cfgs, dict({}), None)
    tcp.send_any('test2')
    assert 'test2' == tcp.recv_any()
