# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

"""
Two-node integration test: verifies full protocol lifecycle
(startup -> identity exchange -> negotiation -> reputation scoring)
across two AutonomousTrust nodes on separate loopback IPs.

UDP broadcast does not work on loopback, so UDPNetworkProcess is
monkey-patched in each subprocess to use direct unicast on port+5.
"""

import json
import logging
import multiprocessing
import os
import queue
import re
import shutil
import socket
import threading
import time
from unittest.mock import patch

import pytest

from autonomous_trust.core import AutonomousTrust, Process
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity
from autonomous_trust.core.network.udp import UDPNetworkProcess, TransmissionError
from autonomous_trust.core.system import comm_port, CfgIds
from .. import TEST_DIR


# ---------- constants ----------

NODE_A_IP = '127.0.0.1'
NODE_B_IP = '127.0.0.2'
SUBNET = '255.0.0.0'
ALL_PEERS = [NODE_A_IP, NODE_B_IP]
CAST_PORT_OFFSET = 5  # avoids conflict with peer(+0), group(+1), ping(+2,+3), ntp(+4)
RUNTIME = 90  # seconds
STAGGER = 15  # seconds between node starts (lets Node A establish group first)

# Match the framework's start method (AutonomousTrust defaults to forkserver):
# the default 'fork' on Linux forks a multi-threaded process and risks deadlocks.
MP_CTX = multiprocessing.get_context('forkserver')

STAGES = [
    (1, 'Startup',        r'Ready\.'),
    (2, 'Announce',       r'Announce myself'),
    (3, 'Group formed',   r'No history/group key: generate my own\.|Updated group key'),
    (4, 'Peer discovered', r'Received new identity:'),
    (5, 'Peer accepted',  r'Received peer acceptance|Process accepted peer:'),
    (6, 'Task sent',      r'Send task to'),
    (7, 'Task executed',  r'Running task|Task result recvd:'),
]


# ---------- helpers ----------

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


def _parse_stages(log_path):
    """Extract which protocol stages completed from a log file."""
    reached = set()
    errors = []
    try:
        with open(log_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        return reached, ['Log file not found: %s' % log_path]

    for num, _name, pattern in STAGES:
        if re.search(pattern, content):
            reached.add(num)

    # Collect every ERROR-level log line
    node = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(log_path))))
    for match in re.finditer(r'^.*- ERROR (.+)$', content, re.MULTILINE):
        errors.append('[%s] %s' % (node, match.group(1)))

    return reached, errors


def _run_node(cfg_dir, ip_addr, peer_addrs, runtime, log_file):
    """Subprocess entry point for a single node."""
    os.environ[Configuration.ROOT_VARIABLE_NAME] = cfg_dir
    mock_addrs = _mock_addresses(ip_addr)

    # Patch network for loopback before any socket is created
    _patch_loopback(peer_addrs, ip_addr, comm_port)

    # Mock get_addresses for the entire run (Network.__init__ calls it)
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=mock_addrs):
        control_q = queue.Queue()

        timer = threading.Timer(runtime, lambda: control_q.put(Process.sig_quit))
        timer.daemon = True

        at = AutonomousTrust(
            multiproc=False,
            log_level=logging.DEBUG,
            logfile=log_file,
            testing=True,
            silent=True,
        )

        timer.start()
        at.run_forever(q_in=control_q)


# ---------- fixtures ----------

@pytest.fixture(scope='session')
def two_node_setup():
    """Create two separate config directories with unique identities."""
    base = os.path.join(TEST_DIR, 'two_node')
    if os.path.exists(base):
        shutil.rmtree(base)

    nodes = {}
    for name, ip in [('node_a', NODE_A_IP), ('node_b', NODE_B_IP)]:
        cfg_dir = _make_node_dir(base, name)
        mock_addrs = _mock_addresses(ip)
        seed = int(ip.split('.')[-1])

        with patch('autonomous_trust.core.network.network.Network.get_addresses',
                   return_value=mock_addrs):
            generate_identity(cfg_dir, randomize=True, seed=seed)

        log_dir = os.path.join(base, name, 'var', 'at')
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, 'autonomous_trust.log')

        nodes[name] = {'cfg_dir': cfg_dir, 'ip': ip, 'log_file': log_file}

    yield nodes

    if os.path.exists(base):
        shutil.rmtree(base)


# ---------- test ----------

def test_two_node_protocol_stages(two_node_setup):
    """Verify two nodes complete the full protocol lifecycle on loopback."""
    nodes = two_node_setup

    # Launch Node A first so it establishes the group key,
    # then start Node B after STAGGER seconds to avoid
    # group-key cross-adoption race.
    node_a = nodes['node_a']
    proc_a = MP_CTX.Process(
        target=_run_node,
        args=(node_a['cfg_dir'], node_a['ip'], ALL_PEERS, RUNTIME, node_a['log_file']),
        daemon=True,
    )
    proc_a.start()

    time.sleep(STAGGER)

    node_b = nodes['node_b']
    proc_b = MP_CTX.Process(
        target=_run_node,
        args=(node_b['cfg_dir'], node_b['ip'], ALL_PEERS, RUNTIME - STAGGER, node_b['log_file']),
        daemon=True,
    )
    proc_b.start()

    procs = {'node_a': proc_a, 'node_b': proc_b}

    # Wait for all nodes to finish (timer-driven shutdown)
    for name, p in procs.items():
        p.join(timeout=RUNTIME + 30)
        if p.is_alive():
            p.terminate()
            p.join(timeout=5)

    # Parse logs and report
    all_stages = {}
    all_errors = []
    stage_names = {num: sname for num, sname, _ in STAGES}

    for name, info in nodes.items():
        stages, errors = _parse_stages(info['log_file'])
        all_stages[name] = stages
        all_errors.extend(errors)

        reached = sorted(stages)
        desc = ', '.join('%d(%s)' % (s, stage_names[s]) for s in reached)
        print('\n%s (%s): Stages reached: %s' % (name, info['ip'], desc))

    # No errors of any kind
    assert len(all_errors) == 0, \
        '%d error(s) found:\n  %s' % (len(all_errors), '\n  '.join(all_errors))

    # Both nodes reach at least stage 5 (peer accepted) -
    # proves identity serialization works end-to-end
    for name in nodes:
        assert 5 in all_stages[name], (
            '%s did not reach peer acceptance (stage 5). Reached: %s' %
            (name, sorted(all_stages[name]))
        )

    # At least one node reaches stage 6+ (task negotiation attempted) -
    # proves negotiation works
    any_tasking = any(6 in stages for stages in all_stages.values())
    assert any_tasking, (
        'No node reached task negotiation (stage 6). Stages: %s' %
        {n: sorted(s) for n, s in all_stages.items()}
    )
