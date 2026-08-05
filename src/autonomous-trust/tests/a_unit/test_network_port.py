# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

"""Base-port resolution: config -> AT_COMM_PORT -> default.

The Python mirror of ``src/c/test/net_port_test.c``. Both sides also run the
same table through the conformance corpus (``scenarios/network/
port-resolution.yaml``); these tests cover the Python-only parts — the derived
ping/ntp ports, which C does not implement.
"""

import os
import socket

import pytest

from autonomous_trust.core._python import system as at_system
from autonomous_trust.core._python.system import PortSource, resolve_comm_port


@pytest.fixture(autouse=True)
def _clean_env():
    """AT_COMM_PORT must not leak between cases, or into the rest of the run."""
    saved = os.environ.get('AT_COMM_PORT')
    os.environ.pop('AT_COMM_PORT', None)
    yield
    if saved is None:
        os.environ.pop('AT_COMM_PORT', None)
    else:
        os.environ['AT_COMM_PORT'] = saved


def test_default_when_nothing_set():
    # A deployment with no knobs touched must see exactly the numbers it saw
    # before the resolver existed.
    port, src = resolve_comm_port()
    assert port == 27787
    assert port == at_system.default_comm_port
    assert src == PortSource.default


def test_config_beats_env():
    os.environ['AT_COMM_PORT'] = '31000'
    assert resolve_comm_port(28500) == (28500, PortSource.config)


def test_env_applies_only_when_config_silent():
    os.environ['AT_COMM_PORT'] = '31000'
    assert resolve_comm_port(0) == (31000, PortSource.env)
    assert resolve_comm_port(None or 0) == (31000, PortSource.env)


@pytest.mark.parametrize('val', ['1024', '65534'])
def test_env_bounds_are_usable(val):
    os.environ['AT_COMM_PORT'] = val
    assert resolve_comm_port(0) == (int(val), PortSource.env)


@pytest.mark.parametrize('bad', [
    'abc',          # unparseable
    '31000x',       # trailing garbage
    '',             # present but empty
    '0',            # the dangerous one
    '-1',           # negative
    '80',           # privileged, unbindable unprivileged
    '1023',         # just below the floor
    '65535',        # no room for the derived group port
    '99999',        # above the 16-bit space
    '2147483648',   # overflows a C long on some ABIs
])
def test_refuses_bad_env_and_never_yields_zero(bad):
    # Port 0 would ask the kernel for an ephemeral port and put the node where
    # no peer is looking. A silent unreachable node is worse than a refusal.
    os.environ['AT_COMM_PORT'] = bad
    port, src = resolve_comm_port(0)
    assert port != 0
    assert port == at_system.default_comm_port
    assert src == PortSource.default


@pytest.mark.parametrize('bad_cfg', [70000, -5, 80, 65535])
def test_refuses_bad_config_and_falls_through(bad_cfg):
    # A configured value is not trusted merely for coming from the config layer.
    assert resolve_comm_port(bad_cfg) == (27787, PortSource.default)
    os.environ['AT_COMM_PORT'] = '31000'
    assert resolve_comm_port(bad_cfg) == (31000, PortSource.env)


@pytest.mark.parametrize('val', [None, '1024', '31000', '65534', '65535', 'abc'])
def test_resolved_port_always_leaves_room_for_group_port(val):
    if val is None:
        os.environ.pop('AT_COMM_PORT', None)
    else:
        os.environ['AT_COMM_PORT'] = val
    port, _ = resolve_comm_port(0)
    assert at_system.comm_port_min <= port <= at_system.comm_port_max
    assert port + 1 <= 65535


def test_derived_ports_follow_the_base():
    # Python's ping/ntp ports derive from the base, so an override separates two
    # co-located nodes on every socket rather than only the peer one. C has no
    # counterpart for these three (it implements neither ping nor ntp).
    assert at_system.ping_at_rcv_port == at_system.comm_port + 2
    assert at_system.ping_at_snd_port == at_system.comm_port + 3
    assert at_system.ntp_port == at_system.comm_port + 4


def test_derived_ports_follow_an_override_on_reimport():
    # The module-level names are the defaults layer, resolved at import. Assert
    # the derivation holds for an overridden base too, which is what a
    # subprocess started with AT_COMM_PORT actually gets (as the diag harness
    # does in separate_by='port' mode).
    import importlib
    os.environ['AT_COMM_PORT'] = '31000'
    try:
        mod = importlib.reload(at_system)
        assert mod.comm_port == 31000
        assert mod.ping_at_rcv_port == 31002
        assert mod.ping_at_snd_port == 31003
        assert mod.ntp_port == 31004
    finally:
        os.environ.pop('AT_COMM_PORT', None)
        importlib.reload(at_system)
    assert at_system.comm_port == 27787


def test_two_bases_do_not_overlap_on_one_address():
    # The co-location property the resolver exists to provide, asserted on real
    # sockets. No SO_REUSEADDR: with it set on both sockets this kernel permits
    # a duplicate bind silently (see ISSUES.md), so a plain socket is the only
    # honest occupancy probe.
    base_a, base_b = 31300, 31400
    socks = []
    try:
        for base in (base_a, base_b):
            for port in (base, base + 1):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(('127.0.0.1', port))   # must not raise
                socks.append(s)
        assert len({s.getsockname()[1] for s in socks}) == 4
    finally:
        for s in socks:
            s.close()
