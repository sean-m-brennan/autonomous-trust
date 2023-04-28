import socket
import struct

from .network import Network
from .netprocess import NetworkProcess, NetworkProtocol, TransmissionError


class SimpleTCPNetworkProcess(NetworkProcess):
    """
    Implementation of NetworkProcess that uses TCP for point-to-point, and UDP for one-to-many
    Can use either multicast or broadcast for UDP
    """
    mcast_ttl = 2
    enc = Network.encoding
    net_proto = NetworkProtocol.IPV4

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, use_mcast=False):
        super().__init__(configurations, subsystems, log_q, acceptance_func)
        bind_address = self.net_cfg.ip4
        self.recv_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recv_tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.recv_tcp_sock.bind((bind_address, self.port))
        except OSError as err1:
            self.logger.warning('Address %s:%s error: %s' % (bind_address, self.port, str(err1)))
            bind_address = '0.0.0.0'
            self.recv_tcp_sock.bind((bind_address, self.port))
        self.my_address, self.port = self.recv_tcp_sock.getsockname()
        self.logger.info('Bound peer recv to %s:%s' % (self.my_address, self.port))
        self.recv_tcp_sock.listen(self.rcv_backlog)

        if use_mcast:
            self.packet_size = 65527
            self.sock_options = (socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.mcast_ttl)
            self.manycast_addr = self.net_cfg.multicast_v4_address
            self.recv_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.recv_udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.recv_udp_sock.bind((self.manycast_addr, self.port))
            if bind_address == '0.0.0.0':
                req = struct.pack("=4sl", socket.inet_aton(self.manycast_addr), socket.INADDR_ANY)
            else:
                req = struct.pack("=4s4s", socket.inet_aton(self.manycast_addr), socket.inet_aton(bind_address))
            self.recv_udp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, req)
            self.logger.info('Bound any recv to %s:%s' % self.recv_udp_sock.getsockname())
        else:
            self.packet_size = 65507
            self.sock_options = (socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.manycast_addr = self.net_cfg.ip4_broadcast
            self.recv_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.recv_udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.recv_udp_sock.bind((self.manycast_addr, self.port))
            self.logger.info('Bound any recv to %s:%s' % self.recv_udp_sock.getsockname())

    def send_peer(self, msg, host):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            sock.connect((host, self.port))
            sent = sock.send(('%d|' % len(msg)).encode(self.enc))  # FIXME encoding
            if sent == 0:
                raise TransmissionError("socket connection broken")
            total_sent = 0
            while total_sent < len(msg):
                sent = sock.send(msg[total_sent:])
                if sent == 0:
                    raise TransmissionError("socket connection broken")
                total_sent = total_sent + sent

    def send_all(self, msg):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            sock.setsockopt(*self.sock_options)
            sent = sock.sendto(msg, (self.manycast_addr, self.port))
            if sent == 0:
                raise TransmissionError("socket connection broken")

    def _recv(self, sock):
        byte = b''
        size_bytes = byte
        while byte != '|'.encode(self.enc):
            size_bytes += byte
            byte = sock.recv(1)
        msg_len = int(size_bytes.decode(self.enc))
        chunks = []
        bytes_recvd = 0
        while bytes_recvd < msg_len:
            chunk = sock.recv(min(msg_len - bytes_recvd, 2048))
            if chunk == b'':
                raise TransmissionError("socket connection broken")
            chunks.append(chunk)
            bytes_recvd += len(chunk)
        return b''.join(chunks).decode(self.enc)

    def recv_peer(self):
        (clientsock, address) = self.recv_tcp_sock.accept()
        if address == self.my_address:
            return None, None  # my own message
        if not self.accept_peer_message(address):
            return None, address  # reject
        return self._recv(clientsock), address

    def recv_any(self):
        msg, addr = self.recv_udp_sock.recvfrom(self.packet_size)
        if addr == self.my_address:
            return None, None  # my own message
        if self.reject_message(addr):
            return None, addr  # reject
        return msg, addr
