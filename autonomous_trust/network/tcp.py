import socket

from .netprocess import NetworkProcess
from ..config.configuration import CfgIds


class SimpleTCPNetworkProcess(NetworkProcess):
    def __init__(self, configurations):
        super().__init__(configurations)
        bind_address = configurations[CfgIds.network.value].ip4
        self.sendsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recvsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.recvsock.bind((bind_address, self.port))
        except OSError:
            self.recvsock.bind(('0.0.0.0', self.port))
        self.recvsock.listen(self.rcv_backlog)

    def send(self, msg, whom_list):
        for host in whom_list:  # peer identity
            self.sendsock.connect((host, self.port))
            sent = self.sendsock.send(('%d|' % len(msg)).encode())
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = 0
            while totalsent < len(msg):
                sent = self.sendsock.send(msg[totalsent:])
                if sent == 0:
                    raise RuntimeError("socket connection broken")
                totalsent = totalsent + sent

    def bcast(self, msg):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sent = sock.sendto(msg, ('<broadcast>', self.port))
        if sent == 0:
            raise RuntimeError("socket connection broken")

    def recv(self):
        (clientsock, address) = self.recvsock.accept()
        byte = b''
        size_bytes = byte
        while byte != '|'.encode():
            size_bytes += byte
            byte = clientsock.recv(1)
        msg_len = int(size_bytes.decode())
        chunks = []
        bytes_recvd = 0
        while bytes_recvd < msg_len:
            chunk = clientsock.recv(min(msg_len - bytes_recvd, 2048))
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            bytes_recvd += len(chunk)
        return b''.join(chunks), address
