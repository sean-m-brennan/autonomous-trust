import socket

from .netprocess import NetworkProtocol, TransmissionError
from .udp import UDPNetworkProcess


class TCPNetworkProcess(UDPNetworkProcess):
    """
    Implementation of NetworkProcess that uses TCP for point-to-point, and UDP for one-to-many
    Can use either multicast or broadcast for UDP
    """
    mcast_ttl = 2
    rcv_backlog = 5
    net_proto = NetworkProtocol.IPV4

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, use_mcast=False, **kwargs):
        super().__init__(configurations, subsystems, log_q, acceptance_func, **kwargs)
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

    def _send_tcp(self, msg, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            self.logger.debug('Solo connect to %s:%s' % (host, port))
            try:
                sock.connect((host, port))
            except socket.error as err:
                raise TransmissionError('Connect - ' + str(err))
            try:
                sent = sock.send(('%d|' % len(msg)).encode(self.enc))  # FIXME encoding
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
                raise TransmissionError("Socket connection broken (no bytes sent)")
            chunks.append(chunk)
            bytes_recvd += len(chunk)
        return b''.join(chunks).decode(self.enc)

    def recv_peer(self):
        (clientsock, (addr, port)) = self.recv_ptp_sock.accept()
        if addr == self.my_address:
            return None, None, None  # my own message
        if not self.accept_peer_message(addr):
            return None, addr, port  # reject
        return self._recv(clientsock), addr, port

    def recv_group(self):
        (clientsock, (addr, port)) = self.recv_grp_sock.accept()
        if addr == self.my_address:
            return None, None, None  # my own message
        if not self.accept_group_message(addr):
            return None, addr, port  # reject
        return self._recv(clientsock), addr, port
