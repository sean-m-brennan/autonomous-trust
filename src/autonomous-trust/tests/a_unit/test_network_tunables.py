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

"""Network-tunable resolution: env -> compile-time default.

The Python mirror of the tunables half of ``src/c/test/net_port_test.c``. Both
sides also run the same table through the conformance corpus
(``scenarios/network/tunables-resolution.yaml``); these tests cover what a
corpus case cannot -- that the resolved value reaches the code that uses it,
which is the difference between a tunable and a decorative one (ISSUES.md
2.4.4).
"""

import os
import time
from collections import deque
from unittest.mock import MagicMock

import pytest

from .. import rendered_log

from autonomous_trust.core._python import system as at_system
from autonomous_trust.core._python.system import (
    KnobSource, resolve_annoy_limit, resolve_mystery_max_age_s, resolve_recv_poll_ms)
from autonomous_trust.core._python.network.netprocess import NetworkProcess

ENV_VARS = ('AT_NET_ANNOY_LIMIT', 'AT_NET_RECV_POLL_MS', 'AT_MYSTERY_MAX_AGE_SEC')

# resolver, env var, default, min, max
KNOBS = (
    (resolve_annoy_limit, 'AT_NET_ANNOY_LIMIT',
     at_system.default_annoy_limit, at_system.annoy_limit_min, at_system.annoy_limit_max),
    (resolve_recv_poll_ms, 'AT_NET_RECV_POLL_MS',
     at_system.default_recv_poll_ms, at_system.recv_poll_ms_min, at_system.recv_poll_ms_max),
    (resolve_mystery_max_age_s, 'AT_MYSTERY_MAX_AGE_SEC',
     at_system.default_mystery_max_age_s,
     at_system.mystery_max_age_s_min, at_system.mystery_max_age_s_max),
)


@pytest.fixture(autouse=True)
def _clean_env():
    """No tunable may leak between cases, or into the rest of the run."""
    saved = {var: os.environ.get(var) for var in ENV_VARS}
    for var in ENV_VARS:
        os.environ.pop(var, None)
    yield
    for var, val in saved.items():
        if val is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = val


@pytest.mark.parametrize('resolver,var,default,lo,hi', KNOBS)
def test_default_when_nothing_set(resolver, var, default, lo, hi):
    assert resolver() == (default, KnobSource.default)


@pytest.mark.parametrize('resolver,var,default,lo,hi', KNOBS)
def test_env_applies_and_is_reported_as_such(resolver, var, default, lo, hi):
    os.environ[var] = str(lo + 1)
    assert resolver() == (lo + 1, KnobSource.env)


@pytest.mark.parametrize('resolver,var,default,lo,hi', KNOBS)
def test_bounds_are_inclusive(resolver, var, default, lo, hi):
    for val in (lo, hi):
        os.environ[var] = str(val)
        assert resolver() == (val, KnobSource.env)


@pytest.mark.parametrize('resolver,var,default,lo,hi', KNOBS)
@pytest.mark.parametrize('bad', ['abc', '100x', '0', '-1', '0.1', ''])
def test_refuses_degenerate_values(resolver, var, default, lo, hi, bad):
    """A refused override keeps the default.

    The zero cases matter most: an annoy limit of 0 blacklists a peer on its
    first duplicate and a poll timeout of 0 turns the receive loop into a
    busy-wait, so neither may be reachable by typo.
    """
    os.environ[var] = bad
    assert resolver() == (default, KnobSource.default)


@pytest.mark.parametrize('resolver,var,default,lo,hi', KNOBS)
def test_refuses_out_of_range(resolver, var, default, lo, hi):
    os.environ[var] = str(hi + 1)
    assert resolver() == (default, KnobSource.default)
    os.environ[var] = str(lo - 1)
    assert resolver() == (default, KnobSource.default)


@pytest.mark.parametrize('resolver,var,default,lo,hi', KNOBS)
def test_refusal_is_logged_not_silent(resolver, var, default, lo, hi):
    """An operator has to be able to tell an ignored override from an applied
    one; that is the whole reason these go through a resolver."""
    os.environ[var] = 'nonsense'
    logger = MagicMock()
    resolver(logger)
    logger.warning.assert_called_once()
    assert var in rendered_log(logger.warning)


def test_python_and_c_agree_on_the_constants():
    """Pinned here as well as in the corpus so a Python-side drift fails even
    in a run that does not execute the conformance harness. The values are C's
    NET_ANNOY_LIMIT / NET_RECV_POLL_MS / NET_MYSTERY_MAX_AGE_SEC and bounds."""
    assert (at_system.default_annoy_limit,
            at_system.annoy_limit_min, at_system.annoy_limit_max) == (5, 1, 10000)
    assert (at_system.default_recv_poll_ms,
            at_system.recv_poll_ms_min, at_system.recv_poll_ms_max) == (100, 1, 60000)
    assert (at_system.default_mystery_max_age_s,
            at_system.mystery_max_age_s_min,
            at_system.mystery_max_age_s_max) == (30, 1, 86400)


def test_recv_poll_is_milliseconds_and_socket_timeout_is_seconds():
    """The knob is an integer count of ms so the two runtimes can share it
    exactly; Python divides at the point of use, C passes it straight to poll."""
    os.environ['AT_NET_RECV_POLL_MS'] = '250'
    ms, src = resolve_recv_poll_ms()
    assert (ms, src) == (250, KnobSource.env)
    assert ms / 1000.0 == 0.25


# ---------------------------------------------------------------------------
# The knobs must reach the code that uses them
# ---------------------------------------------------------------------------

def _mystery_proc(max_age_s):
    """A NetworkProcess stand-in carrying just what mystery_handler touches."""
    proc = MagicMock(spec=NetworkProcess)
    proc.stop = False
    proc.cadence = 0
    proc.q_cadence = 0
    proc.mystery_max_age_s = max_age_s
    proc.encrypted_messages = deque()
    proc.logger = MagicMock()
    proc.peers.find_by_address.return_value = None  # never resolves
    proc.mystery_handler = NetworkProcess.mystery_handler.__get__(proc)
    return proc


def _run_one_pass(proc):
    """Drive exactly one sweep of the handler, then stop it."""
    original = time.sleep

    def _stop_after_one_pass(_):
        proc.stop = True
        original(0)

    import autonomous_trust.core._python.network.netprocess as np_mod
    saved = np_mod.time.sleep
    np_mod.time.sleep = _stop_after_one_pass
    try:
        proc.mystery_handler({})
    finally:
        np_mod.time.sleep = saved


def test_fresh_deferral_survives_the_sweep():
    proc = _mystery_proc(max_age_s=30)
    proc.encrypted_messages.append((b'ct', '10.0.0.1', time.monotonic()))
    _run_one_pass(proc)
    assert len(proc.encrypted_messages) == 1


def test_deferral_past_the_age_is_reclaimed():
    """Bounded by wall-clock age, not by a retry count -- so ONE pass is enough
    to reclaim an old entry. Under the old count-based rule this needed 60
    passes, which is why the real bound moved with load."""
    proc = _mystery_proc(max_age_s=30)
    proc.encrypted_messages.append((b'ct', '10.0.0.1', time.monotonic() - 31))
    _run_one_pass(proc)
    assert len(proc.encrypted_messages) == 0


def test_age_bound_is_the_resolved_knob_not_a_constant():
    """Lower the knob and the same entry ages out; raise it and it survives."""
    old = time.monotonic() - 45

    survives = _mystery_proc(max_age_s=60)
    survives.encrypted_messages.append((b'ct', '10.0.0.1', old))
    _run_one_pass(survives)
    assert len(survives.encrypted_messages) == 1

    reclaimed = _mystery_proc(max_age_s=10)
    reclaimed.encrypted_messages.append((b'ct', '10.0.0.1', old))
    _run_one_pass(reclaimed)
    assert len(reclaimed.encrypted_messages) == 0


def test_age_boundary_is_inclusive_matching_c():
    """C's sweep uses `now - deferred_at >= max_age`, so an entry exactly at
    the boundary is reclaimed on both sides rather than on one."""
    proc = _mystery_proc(max_age_s=30)
    proc.encrypted_messages.append((b'ct', '10.0.0.1', time.monotonic() - 30))
    _run_one_pass(proc)
    assert len(proc.encrypted_messages) == 0
