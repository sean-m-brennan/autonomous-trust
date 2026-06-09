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

"""Unit tests for BootstrapWorker.

These exercise the tick logic directly (no Process loop) by constructing
the worker with hand-rolled fixtures. The integration story — does the
negotiation pipeline actually fan out at.handshake invitations — is
covered separately by the conformance harness and the live demos.
"""

import os
import queue
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from autonomous_trust.core.bootstrap_worker import BootstrapWorker
from autonomous_trust.core.bootstrap_capabilities import (
    BOOTSTRAP_CAPABILITY_NAMES, register_bootstrap_capabilities,
)
from autonomous_trust.core.capabilities import Capabilities, PeerCapabilities
from autonomous_trust.core.negotiation import NegotiationProtocol, Task
from autonomous_trust.core.network import Message
from autonomous_trust.core.system import CfgIds


def _make_worker(env_overrides=None, peer_count=3, register_caps=True,
                 caps_config=None):
    """Build a BootstrapWorker with the minimum-viable configs.
    `register_caps=False` simulates AT_BOOTSTRAP_DISABLED at the cap-
    registration boundary (the worker should still init cleanly and
    just emit zero pairs).

    The worker owns its own bootstrap Capabilities (it does NOT read
    configs[CfgIds.capabilities], which in the live runtime is the
    PeerCapabilities map), so the disable path is driven by the env var
    the worker actually honors, not by withholding an injected object."""
    env_overrides = dict(env_overrides or {})
    if not register_caps:
        env_overrides.setdefault('AT_BOOTSTRAP_DISABLED', '1')
    # Hold a token outside the patch so the test isolates env state.
    saved = {k: os.environ.get(k) for k in env_overrides}
    for k, v in env_overrides.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        caps = Capabilities()
        if register_caps:
            register_bootstrap_capabilities(caps)
        identity = MagicMock()
        identity.uuid = str(uuid4())
        peers = MagicMock()
        peer_objs = []
        for _ in range(peer_count):
            p = MagicMock()
            p.uuid = str(uuid4())
            p.nickname = 'peer-' + p.uuid[:8]
            peer_objs.append(p)
        peers.all = peer_objs

        # caps_config lets a test pin what sits at CfgIds.capabilities to
        # reproduce the live runtime, where that key is a PeerCapabilities
        # (Automate._configure default) rather than a Capabilities. The
        # worker must not depend on this object.
        configurations = {
            CfgIds.identity: identity,
            CfgIds.peers: peers,
            CfgIds.capabilities: caps if caps_config is None else caps_config,
            'processes': [],
        }
        log_q = queue.Queue()
        worker = BootstrapWorker(
            configurations, MagicMock(), log_q,
            dependencies=[],   # bypass dep check (no real procs in test)
            suppress_log=True,
        )
        return worker, peer_objs
    finally:
        for k, original in saved.items():
            if original is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = original


class TestBootstrapWorkerInit:
    def test_default_config(self, setup_teardown):
        worker, _ = _make_worker(env_overrides={
            'AT_BOOTSTRAP_DURATION_SEC': None,
            'AT_BOOTSTRAP_PAIRS': None,
            'AT_BOOTSTRAP_SEED': None,
        })
        assert worker.duration_sec == BootstrapWorker.DEFAULT_DURATION_SEC
        assert worker.pairs_target == BootstrapWorker.DEFAULT_PAIRS_TARGET
        assert worker._pairs_issued == 0
        assert worker._window_start is None

    def test_env_override(self, setup_teardown):
        worker, _ = _make_worker(env_overrides={
            'AT_BOOTSTRAP_DURATION_SEC': '5.5',
            'AT_BOOTSTRAP_PAIRS': '7',
        })
        assert worker.duration_sec == 5.5
        assert worker.pairs_target == 7

    def test_seeded_rng_deterministic(self, setup_teardown):
        # Same seed → identical tick sequences. This is what the
        # conformance scenario will rely on for reproducible asserts.
        w1, _ = _make_worker(env_overrides={'AT_BOOTSTRAP_SEED': '42'})
        w2, _ = _make_worker(env_overrides={'AT_BOOTSTRAP_SEED': '42'})
        seq1 = [w1._rng.randint(0, 1000) for _ in range(10)]
        seq2 = [w2._rng.randint(0, 1000) for _ in range(10)]
        assert seq1 == seq2


class TestTryIssuePair:
    def test_no_peers_returns_false(self, setup_teardown):
        worker, _ = _make_worker(peer_count=0)
        queues = {CfgIds.negotiation: queue.Queue()}
        assert worker._try_issue_pair(queues) is False
        assert worker._pairs_issued == 0
        assert queues[CfgIds.negotiation].empty()

    def test_no_bootstrap_caps_returns_false(self, setup_teardown):
        # `register_caps=False`: caps dict is empty, so the chosen
        # `at.*` name isn't present locally and the worker skips.
        worker, _ = _make_worker(register_caps=False)
        queues = {CfgIds.negotiation: queue.Queue()}
        assert worker._try_issue_pair(queues) is False
        assert queues[CfgIds.negotiation].empty()

    def test_issues_task_to_negotiation_queue(self, setup_teardown):
        worker, _ = _make_worker(env_overrides={'AT_BOOTSTRAP_SEED': '1'})
        queues = {CfgIds.negotiation: queue.Queue()}
        assert worker._try_issue_pair(queues) is True
        assert worker._pairs_issued == 1
        msg = queues[CfgIds.negotiation].get_nowait()
        assert isinstance(msg, Message)
        assert msg.function == NegotiationProtocol.start
        assert isinstance(msg.obj, Task)
        # The cap on the Task must be one of the three bootstrap caps.
        assert msg.obj.capability.name in BOOTSTRAP_CAPABILITY_NAMES

    def test_issues_with_live_peercapabilities_config(self, setup_teardown):
        # Regression: in the live runtime configs[CfgIds.capabilities] is a
        # PeerCapabilities (Automate._configure default), NOT a Capabilities.
        # The worker previously read that key into self.capabilities and
        # called .to_list() on it -> AttributeError every _tick -> no pairs
        # issued -> peers never admitted -> reputations frozen at 0.5. The
        # worker must own its own bootstrap Capabilities and issue normally
        # regardless of what sits at that config key.
        worker, _ = _make_worker(env_overrides={'AT_BOOTSTRAP_SEED': '1'},
                                  caps_config=PeerCapabilities())
        assert isinstance(worker.capabilities, Capabilities)
        assert sorted(worker.capabilities.to_list()) == sorted(BOOTSTRAP_CAPABILITY_NAMES)
        queues = {CfgIds.negotiation: queue.Queue()}
        assert worker._try_issue_pair(queues) is True
        msg = queues[CfgIds.negotiation].get_nowait()
        assert isinstance(msg.obj, Task)
        assert msg.obj.capability.name in BOOTSTRAP_CAPABILITY_NAMES

    def test_args_per_cap_shape(self, setup_teardown):
        # Each cap takes a specific kwarg shape; the function-args
        # builder is the contract with bootstrap_capabilities.py.
        worker, _ = _make_worker(env_overrides={'AT_BOOTSTRAP_SEED': '7'})
        # at.handshake -> {'nonce': int}
        _, kw_h = worker._build_task_args('at.handshake')
        assert 'nonce' in kw_h
        assert isinstance(kw_h['nonce'], int)
        # at.time-attest -> ()
        a_t, kw_t = worker._build_task_args('at.time-attest')
        assert a_t == ()
        assert kw_t == {}
        # at.echo-challenge -> {'payload': str}
        _, kw_e = worker._build_task_args('at.echo-challenge')
        assert 'payload' in kw_e
        assert isinstance(kw_e['payload'], str)


class TestTickWindow:
    def test_window_opens_on_first_peer(self, setup_teardown):
        # Worker starts with peers already present (the typical case
        # once `_configure` has run); the first tick opens the window.
        worker, _ = _make_worker(env_overrides={
            'AT_BOOTSTRAP_PAIRS': '5',
            'AT_BOOTSTRAP_DURATION_SEC': '999',
        })
        queues = {CfgIds.negotiation: queue.Queue()}
        assert worker._window_start is None
        worker._tick(queues)
        assert worker._window_start is not None
        assert worker._pairs_issued == 1

    def test_window_idles_without_peers(self, setup_teardown):
        worker, _ = _make_worker(peer_count=0)
        queues = {CfgIds.negotiation: queue.Queue()}
        worker._tick(queues)
        assert worker._window_start is None
        assert worker._pairs_issued == 0

    def test_stops_at_pairs_target(self, setup_teardown):
        worker, _ = _make_worker(env_overrides={
            'AT_BOOTSTRAP_PAIRS': '3',
            'AT_BOOTSTRAP_DURATION_SEC': '999',  # window stays open
            'AT_BOOTSTRAP_SEED': '17',
        })
        queues = {CfgIds.negotiation: queue.Queue()}
        for _ in range(10):
            worker._tick(queues)
        # No more than pairs_target Tasks should have been emitted.
        assert worker._pairs_issued == 3
        n = 0
        while True:
            try:
                queues[CfgIds.negotiation].get_nowait()
                n += 1
            except queue.Empty:
                break
        assert n == 3

    def test_stops_after_window_closes(self, setup_teardown):
        worker, _ = _make_worker(env_overrides={
            'AT_BOOTSTRAP_PAIRS': '999',           # cap not the limit
            'AT_BOOTSTRAP_DURATION_SEC': '0.0001',
        })
        queues = {CfgIds.negotiation: queue.Queue()}
        worker._tick(queues)  # opens window + issues 1 pair
        # Force window-elapsed clock past duration; the next tick
        # should be a no-op despite peers + pairs_remaining. Use
        # tz-aware datetime since system.now() returns one.
        worker._window_start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        for _ in range(5):
            worker._tick(queues)
        # Exactly 1 pair issued at t=0; nothing more.
        assert worker._pairs_issued == 1


class TestBootstrapCoverage:
    def test_all_three_caps_exercised_over_a_run(self, setup_teardown):
        # The §6.5 conformance pin is that all three at.* caps fire at
        # least once. With a fixed seed + generous pair budget the
        # uniform-random selector hits each — verify the unit test
        # surface mirrors the scenario's contract.
        worker, _ = _make_worker(env_overrides={
            'AT_BOOTSTRAP_PAIRS': '30',
            'AT_BOOTSTRAP_DURATION_SEC': '999',
            'AT_BOOTSTRAP_SEED': '12345',
        })
        queues = {CfgIds.negotiation: queue.Queue()}
        for _ in range(30):
            worker._tick(queues)
        for cap_name in BOOTSTRAP_CAPABILITY_NAMES:
            assert worker._counts_by_cap[cap_name] >= 1, (
                f'{cap_name} never fired (counts={worker._counts_by_cap})'
            )
