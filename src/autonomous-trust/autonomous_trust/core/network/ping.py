import logging
import threading
import time
from datetime import timedelta
import socket

from ..system import now, ping_rcv_port, ping_snd_port


class PingStats(object):
    def __init__(self, host, times, total):
        self.host = host
        self.times = times
        self.total_time = total

    @property
    def count(self):
        return len(self.times)

    @property
    def min(self):
        times = [t for t in self.times.values() if t is not None] or [0]
        return timedelta(seconds=min(times))

    @property
    def max(self):
        times = [t for t in self.times.values() if t is not None] or [0]
        return timedelta(seconds=max(times))

    @property
    def avg(self):
        times = [t for t in self.times.values() if t is not None] or [0]
        if len(times) > 0:
            return timedelta(seconds=sum(times) / len(times))
        return timedelta(seconds=0)

    @property
    def loss(self):
        return len([t for t in self.times.values() if t is None]) / len(self.times) * 100

    @property
    def succeeded(self):
        return len([t for t in self.times.values() if t is not None])

    def __str__(self):
        return 'Ping %s\n' % self.host + \
            '  %d packets transmitted, %d received, %0.0f%% packet loss, time %0.0fms\n' % \
            (self.count, self.succeeded, self.loss, self.total_time.total_seconds() * 1000) + \
            '  rtt min/avg/max = %0.3f/%0.3f/%0.3f ms' % \
            (self.min.total_seconds() * 1000, self.avg.total_seconds() * 1000, self.max.total_seconds() * 1000)


class PingServer(threading.Thread):
    def __init__(self, host, logger=None):
        super().__init__()
        self.logger = logger
        if logger is None:
            self.logger = logging.getLogger()
        timeout = 0.1
        socket.setdefaulttimeout(timeout)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_sock.bind((host, ping_rcv_port))
        self.done = False

    def run(self):
        addr = self.recv_sock.getsockname()
        self.logger.info('Ping server started at %s:%s' % addr)
        while not self.done:
            try:
                packet = self.recv_sock.recvfrom(64)
            except TimeoutError:
                packet = None
            if packet is not None:
                data, (host, _) = packet
                try:
                    seq_num = int.from_bytes(data, 'big')
                    data = (seq_num + 1).to_bytes(4, 'big')
                except OverflowError:
                    data = (1).to_bytes(4, 'big')
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                    self.logger.debug('Echo ping to %s:%s' % (host, ping_snd_port))
                    sent = sock.sendto(data, (host, ping_snd_port))
                    if sent == 0:
                        raise RuntimeError("Socket connection broken (no bytes sent)")
        self.logger.info('Ping server halted')

    def stop(self):
        self.done = True


def ping(host: str, seq_num: int = None, count: int = 1, timeout: float = 1.0) -> PingStats:
    if seq_num is None:
        seq_num = 1
    try:
        data = seq_num.to_bytes(4, 'big')
    except OverflowError:
        data = (1).to_bytes(4, 'big')

    socket.setdefaulttimeout(timeout)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    recv_sock.bind(('', ping_snd_port))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        times = {}
        start = now()
        end = now()
        for seq_num in range(1, count+1):
            init = now()
            sent = sock.sendto(data, (host, ping_rcv_port))
            print('Ping %s:%s from %s' % (host, ping_rcv_port, recv_sock.getsockname()))  # FIXME
            if sent == 0:
                raise RuntimeError("Socket connection broken (no bytes sent)")
            try:
                packet = recv_sock.recvfrom(64)
            except TimeoutError:
                packet = None
                print('timeout')
            end = now()
            if packet is None:
                times[seq_num] = None
                continue
            data = packet[0]
            elapsed = (end-init).total_seconds()
            times[seq_num] = elapsed
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)
    recv_sock.close()
    return PingStats(host, times, (end-start))
