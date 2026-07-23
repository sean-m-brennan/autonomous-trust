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
import multiprocessing
import os
import pkgutil
import queue
import sys
import traceback
from datetime import UTC, datetime
from typing import Union

from nacl.hash import blake2b

from .algorithms.impl import AgreementImpl
from .util import ClassEnumMeta

pkg = __name__.rsplit('.', 1)[0]


class CfgIds(object, metaclass=ClassEnumMeta):
    main = 'main'
    network = 'network'
    identity = 'identity'
    peers = 'peers'
    capabilities = 'peer-capabilities'
    group = 'group'
    negotiation = 'negotiation'
    reputation = 'reputation'


# Constants for system tweaking
tcp_communications = pkg + '.network.TCPNetworkProcess'
udp_communications = pkg + '.network.UDPNetworkProcess'
communications = os.environ.get('AT_TRANSPORT', udp_communications)
comm_port = 27787
ping_rcv_port = comm_port + 2
ping_snd_port = ping_rcv_port + 1
ntp_port = comm_port + 4
preferred_proto_ver = 4
# Network subsystem poll cadence. Was 0.0001 (100us), which made the net
# process + its receiver threads effectively busy-wait (sleep_until no-ops
# whenever a loop iteration exceeds the cadence), pegging a core per node —
# pathological when the whole cohort is co-located on one host. 5ms trades
# sub-millisecond network latency (irrelevant for this demo) for far lower
# idle CPU. See ISSUES.md (net CPU / connection churn).
net_cadence = 0.005
encoding = 'utf-8'
cadence = 0.5
queue_cadence = 0.01


def _env_bool(name: str) -> bool:
    return os.environ.get(name, '').strip().lower() in ('1', 'true', 'yes', 'on')


def _env_num(name: str, default, cast):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return cast(raw)
    except (TypeError, ValueError):
        return default


# Persistent / pooled TCP connections. The TCP transport normally opens one
# connection per message (connect/send/close); with pooling on it reuses one
# connection per (peer, channel) for many messages, so steady-state handshakes
# drop from ~1/message to ~1/peer/idle-period. Framing is unchanged, so a
# pooling node still interoperates with a per-message peer (Python or C).
# Default OFF; opt in with AT_NET_POOL=1. See
# doc/architecture/network-connection-pooling.md.
net_persistent_conn = _env_bool('AT_NET_POOL')
# Close a pooled/accepted connection after this many idle seconds, to bound fds.
net_conn_idle_ttl = _env_num('AT_NET_CONN_IDLE_TTL', 30.0, float)
# Cap on simultaneous live connections per direction (outbound pool / inbound
# reader threads), so a hostile peer can't exhaust fds by holding many open.
net_max_live_conns = _env_num('AT_NET_MAX_CONNS', 64, int)


def _proc_idle_floor() -> float:
    """Minimum wall-clock period (sec) for the reputation/negotiation main
    loops. Those loops pace only via queue.get's blocking q_cadence timeout,
    which sleeps ONLY when the queue is empty for a full window; under
    continuous traffic (e.g. the multi-agency demo) there is never an idle
    window, so the loop spins at 100% CPU. A small trailing sleep_until(floor)
    guarantees the loop yields the CPU whenever it is not genuinely saturated,
    without the old sleep_until(cadence)=0.5s throughput cap (~2 msg/s).

    Tunable via AT_PROC_IDLE_FLOOR_SEC; set 0 to restore the un-throttled loop.
    """
    raw = os.environ.get('AT_PROC_IDLE_FLOOR_SEC')
    if raw is None:
        return 0.01
    try:
        val = float(raw)
    except ValueError:
        return 0.01
    return val if val >= 0 else 0.01


proc_idle_floor = _proc_idle_floor()
agreement_impl = AgreementImpl.POA.value
dev_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
core_system = {CfgIds.network: communications,
               CfgIds.identity: pkg + '.identity.IdentityProcess',
               CfgIds.negotiation: pkg + '.negotiation.NegotiationProcess',
               CfgIds.reputation: pkg + '.reputation.ReputationProcess',
               }
max_concurrency = os.cpu_count() * 2
base_system_deps = core_system.keys()


QueueType = Union[queue.Queue, multiprocessing.Queue]


def now():
    """Return current time adjusted by NTP offset (if available)."""
    from .network.ntp import get_offset
    return datetime.now(UTC) + get_offset()


class PackageHash(object):
    key = 'package_hash'
    excludes = ['viz']

    def __init__(self, pkg_path=None, pkg_name=None, debug=False):
        self.logger = logging.getLogger()
        self.debug = debug
        self.modules = {}
        if pkg_path is None or pkg_name is None:
            # Scope the default to autonomous_trust.core so the digest is
            # stable regardless of which sibling autonomous_trust.* packages
            # happen to be merged into the namespace via PYTHONPATH (e.g.
            # the inspector container layers in inspector/evaluation/
            # services/simulator). Identity verification only cares that
            # peers are running the same protocol/core.
            # __name__ here is autonomous_trust.core._python.system; trim
            # to autonomous_trust.core.
            package = sys.modules[__name__.rsplit('.', 2)[0]]
            if pkg_path is None:
                pkg_path = package.__path__
            if pkg_name is None:
                pkg_name = package.__name__
        for loader, name, is_pkg in pkgutil.walk_packages(pkg_path, pkg_name + '.'):
            if any(name.endswith('.' + ex) or ('.%s.' % ex) in name
                   for ex in self.excludes):
                continue
            try:
                module_path = loader.find_spec(name).origin
                with open(module_path, 'r') as src:
                    source = src.read()
                module_hash = blake2b(source.encode(encoding))
                self.modules[name] = module_hash
            except (OSError, TypeError):
                if self.debug:
                    self.logger.error('Skipping ', name)
        self.digest = blake2b(b''.join([dig for dig in self.modules.values()]))

    def onerror(self, name):
        if self.debug:
            self.logger.error("Error importing module %s: %s" % (name, traceback.format_exc()))
