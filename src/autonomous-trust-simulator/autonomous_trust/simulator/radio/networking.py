import socket
from typing import Optional

from .. import net_util as net


class ATNet(net.Net):
    """Drop-in AutonomousTrust replacement for normal socket client/server protocol"""
    # FIXME AT packet nesting

    def _read(self, sock: socket.socket, size: int) -> Optional[bytes]:
        data = b""
        while len(data) < size:
            try:
                new_data = sock.recv(size - len(data))
            except OSError:
                sock.close()
                raise net.ReceiveError
            if len(new_data) == 0:
                raise net.ReceiveError
            data += new_data
        if self.logger is not None:
            self.logger.debug('Recv %s' % data)
        return data

    def _write(self, sock: socket.socket, data: bytes):
        data_len = len(data)
        offset = 0
        while offset != data_len:
            offset += sock.send(data[offset:])
        if self.logger is not None:
            self.logger.debug('Send %s' % data)


class Client(net.Client, ATNet):
    pass


class Server(net.Server, ATNet):
    pass
