import socket
import struct

from .netprocess import NetworkProcess, NetworkProtocol, TransmissionError


class UDPNetworkProcess(NetworkProcess):
    """
    Implementation of NetworkProcess that uses UDP for point-to-point and one-to-many
    Can use either multicast or broadcast for UDP
    """
    mcast_ttl = 2
    net_proto = NetworkProtocol.IPV4

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, udp=True, use_mcast=False):
        super().__init__(configurations, subsystems, log_q, acceptance_func)
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
        self.recv_ptp_sock.bind((self.my_address, self.port))
        self.logger.info('Bound peer recv to %s:%s' % (self.my_address, self.port))

    def _init_udp_grp(self):
        self.recv_grp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.recv_grp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_grp_sock.bind((self.my_address, self.group_port))
        self.logger.info('Bound group recv to %s:%s' % (self.my_address, self.group_port))

    def _init_mcast(self, use_mcast=False):
        if use_mcast:
            self.manycast_packet_size = 65527
            self.sock_options = (socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.mcast_ttl)
            self.manycast_addr = self.net_cfg.multicast_v4_address
            self.recv_cast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.recv_cast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.recv_cast_sock.bind((self.manycast_addr, self.port))
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
            self.recv_cast_sock.bind((self.manycast_addr, self.port))
            self.logger.info('Bound any recv to %s:%s' % self.recv_cast_sock.getsockname())

    def _send_udp(self, msg, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            sent = sock.sendto(msg, (host, port))
            if sent == 0:
                raise TransmissionError("Socket connection broken (no bytes sent)")

    def send_peer(self, msg, host):
        self._send_udp(msg, host, self.port)

    def send_group(self, msg, host):
        self._send_udp(msg, host, self.group_port)

    def send_any(self, msg):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            sock.setsockopt(*self.sock_options)
            sent = sock.sendto(msg, (self.manycast_addr, self.port))
            if sent == 0:
                raise TransmissionError("Socket connection broken (no bytes sent)")

    def _recv_udp(self, sock, packet_size):
        msg, (addr, port) = sock.recvfrom(packet_size)
        if addr == self.my_address:
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
