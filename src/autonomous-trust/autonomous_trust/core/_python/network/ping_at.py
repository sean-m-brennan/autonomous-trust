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

import logging
import threading
import time
from datetime import timedelta
import socket

from ..system import now, ping_at_rcv_port, ping_at_snd_port


def local_address_toward(host, logger=None):
    """The source address this host would use to reach `host`.

    The PingAT client must bind its reply socket to a specific address, not
    the wildcard. `PingATServer` echoes to the SOURCE address of the datagram
    it received, so the address the client listens on has to be the address it
    egresses from -- and with two co-located nodes separated only by address,
    a wildcard bind on `ping_at_snd_port` means whichever node bound last
    silently receives the other's replies (SO_REUSEADDR makes that theft rather
    than an error; same failure class as the transport's duplicate unicast
    bind).

    Connecting an unbound UDP socket sends nothing -- it only asks the kernel
    to run the route lookup and assign a local endpoint, which is exactly the
    address a subsequent unbound send would have used.

    Returns None if the route cannot be resolved; the caller then falls back to
    the wildcard and warns, rather than taking ping off the air.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as probe:
            probe.connect((host, ping_at_rcv_port))
            return probe.getsockname()[0]
    except OSError as err:
        (logger or logging.getLogger(__name__)).warning(
            'PingAT could not resolve a source address toward %s (%s); binding the '
            'wildcard, so a co-located node on another address may receive these '
            'replies instead' % (host, err))
        return None


class PingATStats(object):
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


class PingATServer(threading.Thread):
    def __init__(self, host, logger=None):
        super().__init__()
        self.logger = logger
        if logger is None:
            self.logger = logging.getLogger()
        # Use global setdefaulttimeout, not per-socket settimeout —
        # Python 3.13's settimeout(positive) leaves the socket in
        # non-blocking mode (recvfrom raises BlockingIOError immediately).
        # The 0.1s default was already set by NetworkProcess.__init__,
        # so this is mostly a no-op safety net for direct PingATServer
        # instantiation outside the AT runtime.
        timeout = 0.1
        socket.setdefaulttimeout(timeout)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # No SO_REUSEADDR: one node answers on this addr:port. With the option
        # a second node binds the same pair silently and takes every request,
        # so the first stops answering pings with nothing logged.
        try:
            self.recv_sock.bind((host, ping_at_rcv_port))
        except OSError as err:
            self.recv_sock.close()
            raise OSError(
                err.errno,
                'PingAT server cannot bind %s:%s -- already held, most likely by another '
                'AT node on this address. Give each co-located node a distinct base port '
                '(config net_cfg.port, or AT_COMM_PORT), from which the PingAT ports are '
                'derived.' % (host, ping_at_rcv_port)) from err
        self.done = False

    def run(self):
        addr = self.recv_sock.getsockname()
        self.logger.info('Ping server started at %s:%s' % addr)
        try:
            while not self.done:
                try:
                    packet = self.recv_sock.recvfrom(64)
                except TimeoutError:
                    packet = None
                except OSError:
                    break  # socket closed under us; nothing left to answer on
                if packet is not None:
                    data, (host, _) = packet
                    try:
                        seq_num = int.from_bytes(data, 'big')
                        data = (seq_num + 1).to_bytes(4, 'big')
                    except OverflowError:
                        data = (1).to_bytes(4, 'big')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                        self.logger.debug('Echo ping to %s:%s' % (host, ping_at_snd_port))
                        sent = sock.sendto(data, (host, ping_at_snd_port))
                        if sent == 0:
                            raise RuntimeError("Socket connection broken (no bytes sent)")
        finally:
            # Release the port here, in the thread that owns the socket. Left
            # bound, it denies the port to the next node on this address --
            # there is deliberately no SO_REUSEADDR on it (see __init__), so
            # the next bind fails outright rather than silently sharing.
            self.recv_sock.close()
        self.logger.info('Ping server halted')

    def stop(self, timeout=1.0):
        """Stop answering pings and release the bound port.

        Idempotent, and safe whether or not the thread was ever started.
        """
        self.done = True
        if self.is_alive():
            self.join(timeout)  # run()'s finally closes the socket
        try:
            self.recv_sock.close()  # never started, or join timed out
        except OSError:
            pass


def ping_at(host: str, seq_num: int = None, count: int = 1, timeout: float = 1.0,
            local_address: str = None) -> PingATStats:
    """Ping an AT peer.

    @param local_address  This node's own address, to bind the reply socket
                          (and pin the outbound source) to. Defaults to the
                          source address the route toward `host` selects, which
                          is what an unbound send would have used anyway --
                          never the wildcard, so co-located nodes separated by
                          address do not steal each other's replies.
    """
    if seq_num is None:
        seq_num = 1
    try:
        data = seq_num.to_bytes(4, 'big')
    except OverflowError:
        data = (1).to_bytes(4, 'big')

    if local_address is None:
        local_address = local_address_toward(host)

    socket.setdefaulttimeout(timeout)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # No SO_REUSEADDR: this port belongs to one node on this address, and with
    # the option set a second binder takes delivery of every reply instead of
    # being told the port is taken.
    try:
        recv_sock.bind((local_address or '', ping_at_snd_port))
    except OSError as err:
        recv_sock.close()
        raise OSError(
            err.errno,
            'PingAT cannot bind %s:%s -- already held, most likely by another AT node '
            'on this address. Give each co-located node a distinct base port (config '
            'net_cfg.port, or AT_COMM_PORT), from which the PingAT ports are derived.'
            % (local_address or '*', ping_at_snd_port)) from err

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        # Send FROM the address we are listening on: the server echoes to the
        # datagram's source, so an unbound send on a multi-homed host could
        # direct the reply at an address this socket does not hold.
        if local_address:
            try:
                sock.bind((local_address, 0))
            except OSError as err:
                logging.getLogger(__name__).warning(
                    'PingAT could not pin source address %s (%s); replies from %s may '
                    'not arrive' % (local_address, err, host))
        times = {}
        start = now()
        end = now()
        for seq_num in range(1, count+1):
            init = now()
            sent = sock.sendto(data, (host, ping_at_rcv_port))
            logging.getLogger(__name__).debug('Ping %s:%s from %s' % (host, ping_at_rcv_port, recv_sock.getsockname()))
            if sent == 0:
                raise RuntimeError("Socket connection broken (no bytes sent)")
            try:
                packet = recv_sock.recvfrom(64)
            except TimeoutError:
                packet = None
                logging.getLogger(__name__).debug('Ping timeout for %s' % host)
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
    return PingATStats(host, times, (end-start))
