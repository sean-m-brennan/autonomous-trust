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

import socket
import struct

from .netprocess import NetworkProtocol, TransmissionError
from .udp import UDPNetworkProcess


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

    # Generous explicit timeout for outbound TCP. Was inheriting the
    # 100ms global default, which under bursty cross-container load
    # connect()-failed thousands of times per peer per minute. We swap
    # the process-wide default rather than per-socket settimeout(),
    # because Python 3.13's settimeout(positive) appears to leave the
    # socket in non-blocking mode (BlockingIOError on first I/O).
    send_timeout = 5.0

    def _send_tcp(self, msg, host, port):
        old_default = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.send_timeout)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old_default)
        with sock:
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            self.logger.debug('Solo connect to %s:%s' % (host, port))
            try:
                sock.connect((host, port))
            except socket.error as err:
                raise TransmissionError('Connect - ' + str(err))
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
                self.logger.debug('sending ...')
                total_sent = total_sent + sent
            self.logger.debug('Sent %s bytes' % total_sent)

    def send_peer(self, msg, host):
        self._send_tcp(msg, host, self.port)

    def send_group(self, msg, host):
        self._send_tcp(msg, host, self.group_port)

    def _recv(self, sock):
        size_data = b''
        while len(size_data) < 4:
            chunk = sock.recv(4 - len(size_data))
            if chunk == b'':
                raise TransmissionError("Socket connection broken reading length prefix")
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
            return None, None, None  # my own message
        if self.reject_message(addr):
            clientsock.close()
            return None, addr, port  # blacklisted
        return self._recv(clientsock), addr, port

    def recv_group(self):
        # Same relaxation as recv_peer: blacklist-only at the socket
        # gate. Group decryption downstream still requires the sender
        # to be a known group member (group.decrypt + group.addresses
        # check), so this can't leak unencrypted group payloads to a
        # stranger.
        (clientsock, (addr, port)) = self.recv_grp_sock.accept()
        if addr == self.my_address:
            return None, None, None  # my own message
        if self.reject_message(addr):
            clientsock.close()
            return None, addr, port  # blacklisted
        return self._recv(clientsock), addr, port
