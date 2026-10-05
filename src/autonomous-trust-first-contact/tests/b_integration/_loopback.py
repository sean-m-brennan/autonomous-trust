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
"""Loopback helpers for this distribution's multi-node tests.

Copied from the core's tests/b_integration/test_two_node.py, which cannot be
imported from here: both distributions name their test package ``tests``. Keep
the two in step if the loopback patch changes."""
import multiprocessing
import os
import socket

from autonomous_trust.core.network.udp import UDPNetworkProcess, TransmissionError

SUBNET = '255.0.0.0'
CAST_PORT_OFFSET = 5  # avoids conflict with peer(+0), group(+1), ping(+2,+3), ntp(+4)

# Match the framework's start method (AutonomousTrust defaults to forkserver):
# the default 'fork' on Linux forks a multi-threaded process and risks deadlocks.
MP_CTX = multiprocessing.get_context('forkserver')


def _mock_addresses(ip4):
    return {
        'ip4': ip4,
        'ip6': None,
        'mac': '00:11:22:33:44:%02x' % int(ip4.split('.')[-1]),
        'ip4_subnet': SUBNET,
        'ip6_subnet': None,
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }


def _make_node_dir(base, name):
    cfg_dir = os.path.join(base, name, 'etc', 'at')
    os.makedirs(cfg_dir, exist_ok=True)
    return cfg_dir


def _patch_loopback(peer_addrs, my_addr, port):
    """Monkey-patch UDPNetworkProcess for loopback testing.

    Fixes two loopback issues:
    1. UDP broadcast doesn't work on lo — replace with direct unicast on port+5
    2. Loopback source address defaults to 127.0.0.1 regardless of dest —
       explicitly bind sending sockets to my_addr so _recv_udp self-filtering works
    """
    cast_port = port + CAST_PORT_OFFSET

    def patched_init_mcast(self, use_mcast=False):
        self.manycast_packet_size = 65507
        self.sock_options = (socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.manycast_addr = my_addr
        self.recv_cast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.recv_cast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_cast_sock.bind((my_addr, cast_port))
        self.logger.info('Bound any recv to %s:%s (patched for loopback)' % (my_addr, cast_port))

    def patched_send_any(self, msg):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.bind((my_addr, 0))
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            for addr in peer_addrs:
                if addr != my_addr:
                    sock.sendto(msg, (addr, cast_port))

    def patched_send_udp(self, msg, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.bind((my_addr, 0))
            if not isinstance(msg, bytes):
                msg = msg.encode(self.enc)
            sent = sock.sendto(msg, (host, port))
            if sent == 0:
                raise TransmissionError("Socket connection broken (no bytes sent)")

    UDPNetworkProcess._init_mcast = patched_init_mcast
    UDPNetworkProcess.send_any = patched_send_any
    UDPNetworkProcess._send_udp = patched_send_udp
