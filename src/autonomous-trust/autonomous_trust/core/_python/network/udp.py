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

from .netprocess import NetworkProcess, NetworkProtocol, TransmissionError
from .. import _probes

# Warn at most once per process that a source bind failed, so a
# misconfigured address does not log on every single send.
_bind_warned = False


def bind_source_address(sock, address, logger=None, stream=False):
    """Pin `sock`'s SOURCE address to `address` before it sends or connects.

    AT's receive sockets bind the node's configured address, but the send
    sockets historically did not, so the kernel chose the source from the route
    to the destination. Any node with more than one candidate source address
    (loopback aliases, multi-homed hosts, containers on several networks) then
    transmitted from an address its peers do not have in their listing:
    `_recv_udp` hands `recvfrom()`'s source addr to
    `netprocess.peers.find_by_address()`, so every encrypted frame missed
    attribution and aged out through mystery_handler, and `_recv_udp`'s
    `addr == self.my_address` self-filter stopped recognising the node's own
    broadcasts. Binding the source makes the address a node transmits FROM equal
    the address it is known BY.

    Port collisions: always bind port 0 and NEVER set SO_REUSEADDR here. The
    recv sockets hold (my_address, comm_port) WITH SO_REUSEADDR, and UDP lets two
    sockets share addr:port only when BOTH set it -- so omitting it is what makes
    the kernel's autobind unable to hand out the port this node is listening on,
    even when AT_COMM_PORT is configured inside the ephemeral range. Verified:
    an explicit same-port bind is refused without the option and succeeds with
    it, and 4000 concurrent autobinds never landed on the held port.

    For TCP, `stream=True` sets IP_BIND_ADDRESS_NO_PORT so the kernel defers port
    selection to connect() and keeps 4-tuple uniqueness. Without it, binding
    before connect reserves a port against the local address alone, which
    exhausts the ephemeral range much sooner under the per-message
    connect/send/close path that is still the default.

    Returns True if the source was pinned. A bind failure is NOT fatal -- the
    send proceeds unbound (losing attribution, as before) and warns once, rather
    than taking the node off the air over a bad address.
    """
    global _bind_warned
    # Guard on `str` rather than truthiness: this is called with
    # getattr(self, 'my_address', None), and the unit tests drive the send
    # bodies on spec-mocks whose attributes are Mock objects, not addresses.
    if not isinstance(address, str) or address in ('', '0.0.0.0', '::'):
        _probes.counter('net.bind_source', 'skipped', 'wildcard_or_unset')
        return False
    if stream:
        opt = getattr(socket, 'IP_BIND_ADDRESS_NO_PORT', None)
        if opt is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IP, opt, 1)
            except OSError:
                pass  # best-effort; correctness does not depend on it
    try:
        sock.bind((address, 0))
        _probes.counter('net.bind_source', 'bound')
        return True
    except OSError as err:
        _probes.counter('net.bind_source', 'failed', err.__class__.__name__)
        if not _bind_warned:
            _bind_warned = True
            if logger is not None:
                logger.warning(
                    'Could not bind source address %s (%s); sending unbound, so '
                    'peers may fail to attribute these messages' % (address, err))
        return False


class UDPNetworkProcess(NetworkProcess):
    """
    Implementation of NetworkProcess that uses UDP for point-to-point and one-to-many
    Can use either multicast or broadcast for UDP
    """
    mcast_ttl = 2
    net_proto = NetworkProtocol.IPV4

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, udp=True, use_mcast=False, **kwargs):
        super().__init__(configurations, subsystems, log_q, acceptance_func, **kwargs)
        # Set the per-process default timeout BEFORE socket creation so
        # the listener / recv sockets land in proper "timeout" mode.
        # Per-socket settimeout(positive_value) AFTER the fact is meant
        # to do the same thing, but on Python 3.13 it appears to leave
        # the socket in non-blocking mode — accept()/recvfrom() then
        # raise BlockingIOError immediately and the receiver threads
        # die at startup. The TCPNetworkProcess subclass overrides this
        # for its outbound _send_tcp client sockets via per-socket
        # settimeout(send_timeout) — that codepath is short-lived and
        # explicit, so the global default doesn't poison it.
        socket.setdefaulttimeout(self.socket_timeout)
        self.packet_size = 65507
        self.my_address = self.net_cfg.ip4
        self.group_port = self.port + 1
        if udp:
            self._init_udp_ptp()
            self._init_udp_grp()
        self._init_mcast(use_mcast)

    def _init_udp_ptp(self):
        self.recv_ptp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.recv_ptp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.recv_ptp_sock.bind((self.my_address, self.port))
        except (Exception, OSError) as err:
            self.logger.error('Failed to bind to %s:%s, detected IP is %s' % (self.my_address, self.port, self.my_ip))
            raise err
        self.logger.info('Bound peer recv to %s:%s' % (self.my_address, self.port))

    def _init_udp_grp(self):
        self.recv_grp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.recv_grp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.recv_grp_sock.bind((self.my_address, self.group_port))
        except (Exception, OSError) as err:
            self.logger.error('Failed to bind to %s:%s, detected IP is %s' % (self.my_address, self.port, self.my_ip))
            raise err
        self.logger.info('Bound group recv to %s:%s' % (self.my_address, self.group_port))

    def _init_mcast(self, use_mcast=False):
        if use_mcast:
            self.manycast_packet_size = 65527
            self.sock_options = (socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.mcast_ttl)
            self.manycast_addr = self.net_cfg.multicast_v4_address
            self.recv_cast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.recv_cast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self.recv_cast_sock.bind((self.manycast_addr, self.port))
            except (Exception, OSError) as err:
                self.logger.error('Failed to bind to %s:%s' % (self.manycast_addr, self.port))
                raise err
            if self.my_address == '0.0.0.0':
                req = struct.pack("=4sl", socket.inet_aton(self.manycast_addr), socket.INADDR_ANY)
            else:
                req = struct.pack("=4s4s", socket.inet_aton(self.manycast_addr), socket.inet_aton(self.my_address))
            self.recv_cast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, req)
            self.logger.info('Bound any recv to %s:%s' % self.recv_cast_sock.getsockname())
        else:
            self.manycast_packet_size = 65507
            self.sock_options = (socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.manycast_addr = self.net_cfg.ip4_broadcast
            self.recv_cast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.recv_cast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self.recv_cast_sock.bind((self.manycast_addr, self.port))
            except (Exception, OSError) as err:
                self.logger.error('Failed to bind to %s:%s' % (self.manycast_addr, self.port))
                raise err
            self.logger.info('Bound any recv to %s:%s' % self.recv_cast_sock.getsockname())

    def _send_udp(self, msg, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            # Transmit FROM the address peers know us by, or they cannot
            # attribute the frame (see bind_source_address).
            bind_source_address(sock, getattr(self, 'my_address', None),
                                getattr(self, 'logger', None))
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            sent = sock.sendto(msg, (host, port))
            if sent == 0:
                raise TransmissionError("Socket connection broken (no bytes sent)")

    def send_peer(self, msg, host):
        if len(msg) > self.packet_size:
            raise TransmissionError(
                f"Message too large for UDP ({len(msg)} > {self.packet_size} bytes)")
        self._send_udp(msg, host, self.port)

    def send_group(self, msg, host):
        self._send_udp(msg, host, self.group_port)

    def send_any(self, msg):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            # Also the fix for the self-filter: _recv_udp drops our own
            # broadcast only when its source matches my_address, and this node
            # receives its own send_any on the cast socket.
            bind_source_address(sock, getattr(self, 'my_address', None),
                                getattr(self, 'logger', None))
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            sock.setsockopt(*self.sock_options)
            sent = sock.sendto(msg, (self.manycast_addr, self.port))
            if sent == 0:
                raise TransmissionError("Socket connection broken (no bytes sent)")

    def _recv_udp(self, sock, packet_size):
        msg, (addr, port) = sock.recvfrom(packet_size)
        if addr == self.my_address:
            if self.acceptance is None or not self.acceptance(addr):
                return None, None, None  # my own message
        if self.reject_message(addr):
            return None, addr, port  # reject
        return msg, addr, port

    def recv_peer(self):
        return self._recv_udp(self.recv_ptp_sock, self.packet_size)

    def recv_group(self):
        return self._recv_udp(self.recv_grp_sock, self.packet_size)

    def recv_any(self):
        return self._recv_udp(self.recv_cast_sock, self.manycast_packet_size)
