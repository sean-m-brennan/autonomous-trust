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

# Compile-time DEFAULT base port, not a fixed one. Mirrors C's COMM_PORT
# (network/network.h). The bounds leave room for the derived group port
# (base + 1) inside the 16-bit space and keep a node off the privileged range.
default_comm_port = 27787
comm_port_min = 1024
comm_port_max = 65534


class PortSource(object, metaclass=ClassEnumMeta):
    """Which layer supplied the base port. Mirrors C's net_port_source_t."""
    config = 'config'
    env = 'AT_COMM_PORT'
    default = 'default'


def resolve_comm_port(cfg_port: int = 0, logger: logging.Logger = None) -> tuple[int, str]:
    """Resolve the base port a node communicates on, with its source.

    Resolution order, identical to C's ``net_port_resolve``: a usable
    ``cfg_port`` (the provisioned config always wins) -> ``AT_COMM_PORT``
    (operator override, applied only where the config is silent) ->
    ``default_comm_port``.

    An ``AT_COMM_PORT`` that is unparseable or out of range is refused with a
    warning and the default kept -- never a silent 0, which would ask the
    kernel for an ephemeral port and put the node where no peer is looking.
    """
    def _warn(msg):
        if logger is not None:
            logger.warning(msg)

    if cfg_port and comm_port_min <= cfg_port <= comm_port_max:
        raw = os.environ.get('AT_COMM_PORT')
        if raw and logger is not None:
            # Say so rather than letting an operator believe the override took.
            logger.info('config port %d overrides AT_COMM_PORT=%s', cfg_port, raw)
        return cfg_port, PortSource.config
    if cfg_port:
        _warn('refusing configured port %r (want an integer in [%d, %d]); falling back'
              % (cfg_port, comm_port_min, comm_port_max))

    raw = os.environ.get('AT_COMM_PORT')
    if raw:
        try:
            val = int(raw)
        except (TypeError, ValueError):
            val = None
        if val is None or not (comm_port_min <= val <= comm_port_max):
            _warn("refusing AT_COMM_PORT=%r (want an integer in [%d, %d]); using default %d"
                  % (raw, comm_port_min, comm_port_max, default_comm_port))
        else:
            return val, PortSource.env
    return default_comm_port, PortSource.default


# Compile-time DEFAULTS for the three network tunables, mirroring C's
# NET_ANNOY_LIMIT / NET_RECV_POLL_MS / NET_MYSTERY_MAX_AGE_SEC and their bounds
# (network/network.h). These used to be plain class attributes on
# NetworkProcess with no C counterpart at all, so a deployment could tune one
# runtime and not the other (doc/architecture/networking.md).
default_annoy_limit = 5
annoy_limit_min = 1
annoy_limit_max = 10000

default_recv_poll_ms = 100
recv_poll_ms_min = 1
recv_poll_ms_max = 60000

default_mystery_max_age_s = 30
mystery_max_age_s_min = 1
mystery_max_age_s_max = 86400


class KnobSource(object, metaclass=ClassEnumMeta):
    """Which layer supplied a network tunable. Mirrors C's net_knob_source_t."""
    env = 'env'
    default = 'default'


def resolve_env_int(name: str, default: int, lo: int, hi: int,
                    logger: logging.Logger = None) -> tuple[int, str]:
    """Resolve one network tunable from the environment, with its source.

    Two layers -- env then compile-time default -- with the same refusal rules
    as ``resolve_comm_port``'s env layer, and identical to C's
    ``net_knob_resolve``: strictly parsed, range-checked, and a bad value
    refused with a warning while the default is kept. There is deliberately no
    config layer; see the C header for why.
    """
    raw = os.environ.get(name)
    if raw:
        try:
            val = int(raw)
        except (TypeError, ValueError):
            val = None
        if val is None or not (lo <= val <= hi):
            if logger is not None:
                logger.warning('refusing %s=%r (want an integer in [%d, %d]); using default %d', name, raw, lo, hi, default)
        else:
            return val, KnobSource.env
    return default, KnobSource.default


def resolve_annoy_limit(logger: logging.Logger = None) -> tuple[int, str]:
    """Duplicate-broadcast threshold before a peer is blacklisted."""
    return resolve_env_int('AT_NET_ANNOY_LIMIT', default_annoy_limit,
                           annoy_limit_min, annoy_limit_max, logger)


def resolve_recv_poll_ms(logger: logging.Logger = None) -> tuple[int, str]:
    """Receive-poll timeout in MILLISECONDS.

    Python's socket layer wants seconds and C's poll wants milliseconds, so the
    knob is stated in the unit the two can share exactly (an integer count of
    ms); Python divides at the point of use. The unit differs because the APIs
    do -- the value does not.
    """
    return resolve_env_int('AT_NET_RECV_POLL_MS', default_recv_poll_ms,
                           recv_poll_ms_min, recv_poll_ms_max, logger)


def resolve_mystery_max_age_s(logger: logging.Logger = None) -> tuple[int, str]:
    """How long a deferred encrypted message is held before being reclaimed."""
    return resolve_env_int('AT_MYSTERY_MAX_AGE_SEC', default_mystery_max_age_s,
                           mystery_max_age_s_min, mystery_max_age_s_max, logger)


def resolve_env_choice(name: str, default: str, choices: tuple,
                       logger: logging.Logger = None) -> tuple[str, str]:
    """Resolve a network tunable whose values are NAMES rather than numbers.

    Same two layers and same refusal discipline as :func:`resolve_env_int` (and
    C's ``net_knob_str_resolve``): a value outside ``choices`` is refused with a
    warning and the default kept. Comparison is case-insensitive and
    whitespace-trimmed, because an operator writing ``AT_NET_WIRE_MODE=Proto``
    means proto and a silent fall back to JSON there would look like the
    envelope work simply not happening.
    """
    raw = os.environ.get(name)
    if raw:
        val = raw.strip().lower()
        if val in choices:
            return val, KnobSource.env
        if logger is not None:
            logger.warning('refusing %s=%r (want one of %s); using default %r',
                           name, raw, '|'.join(choices), default)
    return default, KnobSource.default


#: Default envelope encoding for a group this node MINTS (doc/architecture/network-wire-format.md).
#: JSON, because a group's format is what its members must all speak and JSON
#: is the format every AT node can read; a deployment opts a new cohort into
#: proto with AT_NET_WIRE_MODE=proto. Mirrors C's NET_WIRE_MODE_DEFAULT.
default_net_wire_mode = 'json'
net_wire_modes = ('json', 'proto')


def resolve_net_wire_mode(logger: logging.Logger = None) -> tuple[str, str]:
    """Envelope encoding for a group this node mints, with its source.

    This knob does NOT decide what goes on the wire for an existing group --
    that comes from the group itself (``Group.wire_format``), which is what
    keeps a cohort consistent and is why there is no per-message override. It
    decides only what a *new* group is stamped with, so an operator standing up
    a proto cohort sets it on the node that forms the group and every joiner
    adopts it at admission. Mirrors C's ``net_wire_mode_resolve``.
    """
    return resolve_env_choice('AT_NET_WIRE_MODE', default_net_wire_mode,
                              net_wire_modes, logger)


# Module-level defaults layer. A lot imports these names, so they stay -- but
# they are the resolved-at-import view (config is not visible here), not the
# truth for a node that carries a configured port. Use resolve_comm_port() when
# a config is in hand. The derived ports follow the base, so an AT_COMM_PORT
# override separates two co-located nodes on every socket, not just the peer one.
comm_port = resolve_comm_port()[0]
ping_at_rcv_port = comm_port + 2
ping_at_snd_port = ping_at_rcv_port + 1
ntp_port = comm_port + 4
preferred_proto_ver = 4
# Network subsystem poll cadence. Was 0.0001 (100us), which made the net
# process + its receiver threads effectively busy-wait (sleep_until no-ops
# whenever a loop iteration exceeds the cadence), pegging a core per node —
# pathological when the whole cohort is co-located on one host. 5ms trades
# sub-millisecond network latency (irrelevant for this demo) for far lower
# idle CPU. See doc/architecture/network-connection-pooling.md.
net_cadence = 0.005
encoding = 'utf-8'
cadence = 0.5
queue_cadence = 0.01


def _env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean knob. Unset, or set to something unrecognized, gives
    `default` -- a knob that is on by default must be turned off explicitly,
    not by a typo."""
    raw = os.environ.get(name, '').strip().lower()
    if raw in ('1', 'true', 'yes', 'on'):
        return True
    if raw in ('0', 'false', 'no', 'off'):
        return False
    return default


def _env_num(name: str, default, cast):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return cast(raw)
    except (TypeError, ValueError):
        return default


# Persistent / pooled TCP connections. Without pooling the TCP transport opens
# one connection per message (connect/send/close), so `net.tcp.send/connect`
# tracks the message rate; with it, one connection per (peer, channel) carries
# many messages and steady-state handshakes drop to ~1/peer/idle-period. That
# per-message handshake was the remaining half of the connection-churn cost in
# See doc/architecture/network-connection-pooling.md.
#
# ON by default since 2026-08-10; set AT_NET_POOL=0 to go back to per-message
# connections. Framing is unchanged either way, and reuse is guarded on both
# ends: the sender checks a pooled socket is still open before writing to it
# (a write into a closed peer succeeds and loses the frame -- see
# TCPNetworkProcess._peer_gone), and both runtimes' receivers now read many
# frames from one connection. A peer that still closes after one frame costs a
# reconnect per message, which is what the un-pooled path did anyway.
#
# FLAG DAY: C nodes older than 2026-08-10 close after the first frame AND
# predate that receive-side fix, so a mixed fleet with such nodes should set
# AT_NET_POOL=0 until they are updated. See
# doc/architecture/network-connection-pooling.md.
net_persistent_conn = _env_bool('AT_NET_POOL', default=True)
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
    """Return the current time from the host clock.

    The host clock is disciplined by a stock NTP daemon (chrony / ntpd /
    systemd-timesyncd); AT does not maintain a time correction of its own. It
    used to: a userspace offset was applied HERE and nowhere else, so AT's notion
    of time diverged from its own host's, with no clock discipline (one raw
    sample per poll, no filter, dispersion check, step/slew policy or sanity
    bound) and no authentication. Time discipline is a solved problem that belongs
    to the daemon that owns the kernel clock.

    ``network.clock`` reads how well that discipline is going, and a node can
    refuse to start on a clock nothing is steering -- see
    ``clock.require_synced_clock``.
    """
    return datetime.now(UTC)


class PackageHash(object):
    key = 'package_hash'
    # '__pycache__' is not a package, but it becomes importable if anything ever
    # seeds an __init__.py into it (scripts/build-py.sh used to). Such a file
    # would otherwise join the walk below and perturb the digest, which peers
    # compare -- a mismatch is treated as a counterfeit and the peer is refused.
    # The digest must depend on the source only, so exclude it unconditionally.
    excludes = ['viz', '__pycache__']

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
                # `find_spec` can answer None for a name the walk just yielded:
                # a directory importlib lists but declines to import. A
                # `__pycache__` that something seeded an `__init__.py` into is
                # exactly that, and whether it resolves is INTERPRETER-DEPENDENT
                # -- 3.14 hands back a spec, 3.13 hands back None. Unguarded,
                # `.origin` on that None raised AttributeError, which the except
                # below does not catch, so ONE such directory anywhere under the
                # package abandoned the entire digest. That digest gates peer
                # admission (a mismatch is treated as a counterfeit), so failing
                # to compute it is worse than any single module's absence from
                # it. Skipped here, the same outcome `excludes` already produces.
                spec = loader.find_spec(name)
                if spec is None or spec.origin is None:
                    if self.debug:
                        self.logger.error('Skipping unresolvable %s', name)
                    continue
                module_path = spec.origin
                with open(module_path, 'r') as src:
                    source = src.read()
                module_hash = blake2b(source.encode(encoding))
                self.modules[name] = module_hash
            except (OSError, TypeError, AttributeError):
                if self.debug:
                    self.logger.error('Skipping %s', name)
        self.digest = blake2b(b''.join([dig for dig in self.modules.values()]))

    def onerror(self, name):
        if self.debug:
            self.logger.error("Error importing module %s: %s", name, traceback.format_exc())
