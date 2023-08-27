import select
import socket
import struct
import threading
import time
from typing import Optional


class ReceiveFormatError(RuntimeError):
    pass


class Client(object):
    def __init__(self):
        self.halt = False
        self.sock: Optional[socket.socket] = None

    def is_socket_closed(self) -> bool:
        if self.sock is None:
            return True
        try:
            data = self.sock.recv(16, socket.MSG_DONTWAIT | socket.MSG_PEEK)
            if len(data) == 0:
                return True
        except BlockingIOError:
            return False  # socket is open and reading from it would block
        except ConnectionResetError:
            return True  # socket was closed for some other reason
        except OSError:
            return True  # socket was never connected to begin with
        except Exception:  # noqa
            return False
        return False

    def reconnect(self, serv_addr: str, serv_port: int):
        while not self.halt:
            if self.sock is None:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.is_socket_closed():
                try:
                    self.sock.connect((serv_addr, serv_port))
                except ConnectionRefusedError:
                    pass
                except OSError:
                    self.sock.close()
                    self.sock = None
            time.sleep(0.001)

    def recv_all(self, header_fmt: str):
        header_size = struct.calcsize(header_fmt)
        data = b""
        while len(data) < header_size:
            packet = self.sock.recv(1024)
            if not packet:
                break
            data += packet
        packed_msg_size = data[:header_size]
        data = data[header_size:]
        try:
            header = struct.unpack(header_fmt, packed_msg_size)
            msg_size = header[0]
        except struct.error:
            raise ReceiveFormatError

        while len(data) < msg_size:
            data += self.sock.recv(msg_size - len(data))
        return header, data

    def recv_data(self, **kwargs):
        # eg. data = self.sock.recv(1024)
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


class Server(object):
    def __init__(self):
        self.clients: list[socket.socket] = []
        self.halt: bool = False
        self.sock: Optional[socket.socket] = None
        self.listener: Optional[threading.Thread] = None

    def listen(self):
        while not self.halt:
            try:
                client_socket, _ = self.sock.accept()
                self.clients.append(client_socket)
            except socket.timeout:
                pass

    def process(self, **kwargs):
        raise NotImplementedError

    def set_socket_options(self):
        if self.sock is not None:
            self.sock.settimeout(0.2)

    @staticmethod
    def prepend_header(fmt, data, *args):
        return struct.pack(fmt, len(data), *args) + data

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
    def listen(self):  # override
        while not self.halt:
            inputs = list(self.clients) + [self.sock]
            rd, wr, err = select.select(inputs, self.clients, inputs)
            for sock in rd:
                if sock is self.sock:
                    client_socket, _ = sock.accept()
                    client_socket.setblocking(False)
                    self.clients.append(client_socket)
                else:
                    self.recv_data(sock)
            for sock in wr:
                self.send_data(sock)
            for sock in err:
                if sock is self.sock:
                    self.sock.close()
                    self.halt = True  # FIXME recovery?
                else:
                    self.clients.remove(sock)
                    sock.close()

    def recv_data(self, sock: socket.socket):
        raise NotImplementedError

    def send_data(self, sock: socket.socket):
        raise NotImplementedError

    def set_socket_options(self):  # override
        if self.sock is not None:
            self.sock.setblocking(False)

    def run(self, port: int, **kwargs):  # override
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(False)
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen(5)

        self.listener = threading.Thread(target=self.listen)
        self.listener.start()

        try:
            while not self.halt:
                self.process(**kwargs)
        except KeyboardInterrupt:
            pass
        finally:
            self.halt = True
            self.listener.join()
        for client in self.clients:
            client.close()
        self.clients = []
        self.halt = False
