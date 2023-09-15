import base64
import logging
import select
import socket
import struct
import threading
import time
from queue import Queue, Empty
from typing import Optional


class ReceiveError(RuntimeError):
    pass


class ReceiveFormatError(ReceiveError):
    pass


class Net(object):
    """Base networking class"""
    header_fmt = '!L'  # max 4GB message size

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger
        self.halt = False
        self.sock: Optional[socket.socket] = None

    def _read(self, sock: socket.socket, size: int) -> Optional[bytes]:
        data = b""
        while len(data) < size:
            try:
                new_data = sock.recv(size - len(data))
            except OSError:
                sock.close()
                raise ReceiveError
            if len(new_data) == 0:
                raise ReceiveError
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


class Client(Net):
    @property
    def connected(self) -> bool:
        if self.sock is None:
            return False
        try:
            if self.sock.fileno() < 0:
                return False
        except AttributeError:
            return False
        flags = socket.MSG_PEEK  # required
        tmo = False
        if getattr(socket, 'MSG_DONTWAIT'):
            flags |= socket.MSG_DONTWAIT
        else:
            self.sock.settimeout(0.0001)
            tmo = True
        try:
            data = self.sock.recv(1, flags)
            if len(data) == 0:
                return False
        except BlockingIOError:
            return True  # socket is open, and reading from it would block
        except TimeoutError:
            pass
        except OSError:
            return False  # socket was never connected to begin with
        finally:
            if tmo:
                self.sock.settimeout(None)
        return True

    def reconnect(self, serv_addr: str, serv_port: int):
        while not self.halt:
            if self.sock is None:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if not self.connected:
                try:
                    self.sock.connect((serv_addr, serv_port))
                    if self.logger is not None:
                        self.logger.info('Reconnect to %s:%d' % (serv_addr, serv_port))
                except ConnectionRefusedError:
                    pass
                except OSError:
                    self.sock.close()
                    self.sock = None
            time.sleep(0.01)

    def decode(self, data: bytes) -> str:
        return base64.b64decode(data).decode()

    def recv_all(self) -> tuple:
        header_size = struct.calcsize(self.header_fmt)
        hdr_data = self._read(self.sock, header_size)
        try:
            header = struct.unpack(self.header_fmt, hdr_data)  # always a tuple
            msg_size = header[0]
        except struct.error:
            raise ReceiveFormatError

        data = self._read(self.sock, msg_size)
        return header, data

    def recv_data(self, **kwargs):
        # eg. data = self.recv_all(self.header_fmt)
        raise NotImplementedError

    def finish(self):
        pass

    def run(self, server: str, port: int, **kwargs):
        thread = threading.Thread(target=self.reconnect, args=(server, port))
        thread.start()
        try:
            while not self.halt:
                self.recv_data(**kwargs)
        except KeyboardInterrupt:
            pass
        finally:
            self.halt = True
            thread.join()
        if self.sock is not None:
            self.sock.close()
        self.finish()
        self.sock = None
        self.halt = False  # makes object reusable


class Server(Net):
    def __init__(self, logger: logging.Logger = None):
        super().__init__(logger)
        self.clients: list[socket.socket] = []
        self.listener: Optional[threading.Thread] = None

    def listen(self):
        while not self.halt:
            try:
                client_socket, (host, port) = self.sock.accept()
                self.clients.append(client_socket)
                if self.logger is not None:
                    self.logger.debug('New client at %s:%d' % (host, port))
            except socket.timeout:
                pass

    def process(self, **kwargs):
        raise NotImplementedError

    def set_socket_options(self):
        if self.sock is not None:
            self.sock.settimeout(0.2)

    def encode(self, message: str) -> bytes:
        return base64.b64encode(message.encode())

    def send_all(self, sock: socket.socket, data: bytes, *args):
        header = struct.pack(self.header_fmt, len(data), *args)
        self._write(sock, header)
        self._write(sock, data)

    def finish(self):
        pass

    def run(self, port: int, **kwargs):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.set_socket_options()
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen(5)

        self.listener = threading.Thread(target=self.listen)
        self.listener.start()

        try:
            self.process(**kwargs)
        except KeyboardInterrupt:
            pass
        finally:
            self.halt = True
            self.listener.join()
        for client in self.clients:
            client.close()
        self.finish()
        self.clients = []
        self.halt = False


class SelectServer(Server):
    def __init__(self, logger: logging.Logger = None):
        super().__init__(logger)
        self.queues = {}

    def listen(self):  # override
        outputs = []
        while not self.halt:
            inputs = list(self.clients) + [self.sock]
            rd, wr, err = select.select(inputs, outputs, inputs)
            for sock in rd:
                if sock is self.sock:
                    client_socket, (host, port) = sock.accept()
                    client_socket.setblocking(False)
                    self.clients.append(client_socket)
                    self.queues[client_socket] = Queue()
                    if self.logger is not None:
                        self.logger.debug('New client at %s:%d' % (host, port))
                else:
                    data = self.recv_data(sock)
                    if data:
                        self.queues[sock].put(data)
                        if sock not in outputs:
                            outputs.append(sock)
                    else:
                        if sock in outputs:
                            outputs.remove(sock)
                        self.clients.remove(sock)
                        sock.close()
                        del self.queues[sock]
            for sock in wr:
                try:
                    self.queues[sock].get_nowait()
                    self.send_data(sock)
                except (Empty, KeyError):
                    if sock in outputs:
                        outputs.remove(sock)
            for sock in err:
                if sock is self.sock:
                    self.sock.close()
                    self.halt = True  # FIXME recovery?
                else:
                    if sock in outputs:
                        outputs.remove(sock)
                    self.clients.remove(sock)
                    sock.close()
                    del self.queues[sock]

    def recv_data(self, sock: socket.socket):
        raise NotImplementedError

    def send_data(self, sock: socket.socket):
        raise NotImplementedError

    def set_socket_options(self):  # override
        if self.sock is not None:
            self.sock.setblocking(False)
