# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

    def __init__(self, logger: logging.Logger = None, verbose: bool = False):
        self.logger = logger
        self.verbose = verbose
        self.halt = False
        self.sock: Optional[socket.socket] = None

    def _read(self, sock: socket.socket, size: int) -> Optional[bytes]:
        data = b""
        while len(data) < size:
            try:
                new_data = sock.recv(size - len(data))
            except OSError as err:
                sock.close()
                raise ReceiveError(str(err))
            if len(new_data) == 0:
                raise ReceiveError('No data')  # FIXME need to reconnect
            data += new_data
        if self.logger is not None and self.verbose:
            self.logger.debug('Recv %s' % data)
        return data

    def _write(self, sock: socket.socket, data: bytes):
        data_len = len(data)
        offset = 0
        while offset != data_len:
            offset += sock.send(data[offset:])
        if self.logger is not None and self.verbose:
            self.logger.debug('Send %s' % data)


class Client(Net):
    @property
    def is_connected(self) -> bool:
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
            #if len(data) == 0:  # FIXME what if there's no data en-route?
            #    return False
        except BlockingIOError:
            return True  # socket is open, and reading from it would block
        except TimeoutError:
            pass
        except OSError as e:
            return False  # socket was never connected to begin with
        finally:
            if tmo:
                self.sock.settimeout(None)
        return True

    def _do_connect(self, serv_addr: str, serv_port: int, await_server: bool = True):
        was_connected = not await_server
        try:
            if self.sock is None:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((serv_addr, serv_port))
            if self.logger is not None:
                self.logger.debug('Reconnect to %s:%d' % (serv_addr, serv_port))
        except ConnectionRefusedError:
            self.sock.close()
            self.sock = None
            if was_connected:
                self.halt = True
                if self.logger is not None:
                    self.logger.warning('Connection refused to %s:%d. Halting.' % (serv_addr, serv_port))
                elif self.logger is not None:
                    self.logger.debug('Connection refused to %s:%d' % (serv_addr, serv_port))
        except OSError as e:
            self.sock.close()
            self.sock = None
            if self.logger is not None:
                self.logger.debug('Reconnect failed to %s:%d (%s)' % (serv_addr, serv_port, e))

    def reconnect(self, serv_addr: str, serv_port: int, await_server: bool = True):
        while not self.halt:
            if self.sock is None:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if not self.is_connected:
                self._do_connect(serv_addr, serv_port, await_server)
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
        wait = kwargs.get('await_server', True)
        cadence = kwargs.get('cadence', None)
        self._do_connect(server, port, wait)
        thread = threading.Thread(target=self.reconnect, args=(server, port, wait))
        thread.start()
        try:
            while not self.halt:
                self.recv_data(**kwargs)
                if cadence is not None:
                    time.sleep(cadence)
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
    def __init__(self, logger: logging.Logger = None, resolve: bool = False, short: bool = False):
        super().__init__(logger)
        self.clients: list[socket.socket] = []
        self.listener: Optional[threading.Thread] = None
        self.resolve = resolve
        self.short = short

    def listen(self):
        while not self.halt:
            try:
                client_socket, (host, port) = self.sock.accept()
                self.clients.append(client_socket)
                if self.logger is not None:
                    if self.resolve:
                        host = socket.gethostbyaddr(host)[0]
                        if self.short:
                            host = host[:host.find('.')]
                    self.logger.info('New client at %s:%d' % (host, port))
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
        self.sock.bind(('', port))
        self.sock.listen(10)

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
    def __init__(self, logger: logging.Logger = None, **kwargs):
        super().__init__(logger, **kwargs)
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
                    self.queues[client_socket] = (host, port), Queue()
                    if self.logger is not None:
                        if self.resolve:
                            host = socket.gethostbyaddr(host)[0]
                            if self.short:
                                host = host[:host.find('.')]
                        self.logger.info('New client at %s:%d' % (host, port))
                else:
                    try:
                        data = self.recv_data(sock)
                        self.queues[sock][1].put(data)
                        if sock not in outputs:
                            outputs.append(sock)
                    except ReceiveError as error:
                        host, port = self.queues[sock][0]
                        if sock in outputs:
                            outputs.remove(sock)
                        self.clients.remove(sock)
                        sock.close()
                        del self.queues[sock]
                        if self.logger is not None:
                            self.logger.info('Client at %s:%d disconnected: %s' % (host, port, error))
            for sock in wr:
                try:
                    self.queues[sock][1].get_nowait()  # just acts as a semaphore
                    self.send_data(sock)
                except (Empty, KeyError):
                    if sock in outputs:
                        outputs.remove(sock)
            for sock in err:
                if sock is self.sock:
                    self.sock.close()
                    self.halt = True
                else:
                    host, port = self.queues[sock][0]
                    if sock in outputs:
                        outputs.remove(sock)
                    self.clients.remove(sock)
                    sock.close()
                    del self.queues[sock]
                    if self.logger is not None:
                        self.logger.info('Client at %s:%d errored out' % (host, port))

    def recv_data(self, sock: socket.socket):
        raise NotImplementedError

    def send_data(self, sock: socket.socket):
        raise NotImplementedError

    def set_socket_options(self):  # override
        if self.sock is not None:
            self.sock.setblocking(False)
