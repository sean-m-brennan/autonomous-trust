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
"""
Smoke test for the in-process multi-peer harness. Skipped where the
loopback aliasing or 127/8 broadcast prereqs aren't met (macOS, some
sandboxed CI envs).

Convergence-level tests should be added here too — for now we only
prove peers come up and write their initial Peers config to disk.
"""
from __future__ import annotations

import platform

import pytest

from .harness import (
    MultiPeerHarness,
    loopback_aliases_supported,
    loopback_broadcast_supported,
)


_ADDRS = ['127.0.0.2', '127.0.0.3']

_skip_loopback = pytest.mark.skipif(
    platform.system() != 'Linux'
    or not loopback_aliases_supported(_ADDRS)
    or not loopback_broadcast_supported(),
    reason='Harness requires Linux loopback aliasing + /8 broadcast')


@_skip_loopback
def test_harness_starts_two_peers():
    """Two peers reach AT bootstrap (each writes its identity config
    to disk). This is a low bar — the smoke test exists so a future
    breakage of the spawn path fails noisily, before we go after
    convergence assertions."""
    with MultiPeerHarness(n_peers=2, runtime_sec=12, log_level='warning') as h:
        # The harness's start() already waits on ready signals; if we
        # got here, both peers passed config generation. Verify each
        # peer's identity file landed on disk.
        import os
        for p in h.peers:
            ident = os.path.join(p.cfg_dir, 'identity.cfg.json')
            assert os.path.exists(ident), \
                f'peer {p.idx}: identity not persisted ({ident})'
            assert p.error is None, \
                f'peer {p.idx} reported error: {p.error}'


@_skip_loopback
@pytest.mark.slow
def test_harness_two_peers_converge():
    """Convergence: each peer's persisted Peers list eventually
    contains the other's address. Marked `slow` because bootstrap
    takes ~30s wall clock by default."""
    with MultiPeerHarness(n_peers=2, runtime_sec=45, log_level='warning') as h:
        converged = h.wait_until_all_peers_grouped(timeout=40, poll=2.0)
        if not converged:
            views = {p.idx: h.peers_known_by(p.idx) for p in h.peers}
            pytest.fail(
                f'peers did not converge within 40s. Views={views}. '
                f'Configs preserved at {h.tmp_root}')


@_skip_loopback
@pytest.mark.slow
def test_harness_three_peers_converge():
    """N-peer convergence beyond the trivial pair. With three peers
    the welcoming-committee handoff must propagate through more than
    one direct link — a regression here typically means the group
    update protocol regressed or the second admission round dropped
    a peer."""
    with MultiPeerHarness(n_peers=3, runtime_sec=50, log_level='warning') as h:
        converged = h.wait_until_all_peers_grouped(timeout=45, poll=2.0)
        if not converged:
            views = {p.idx: h.peers_known_by(p.idx) for p in h.peers}
            pytest.fail(
                f'3 peers did not converge within 45s. Views={views}. '
                f'Configs preserved at {h.tmp_root}')


@_skip_loopback
@pytest.mark.slow
def test_harness_drain_loop_actually_bursts():
    """Probe-driven counterpart to test_drain_loop_pacing_not_reverted:
    confirm that the drain loop in idproc / negproc / repproc actually
    drains >1 message per iter when the queue has a backlog. With the
    old sleep_until(cadence) pattern this would be near-zero — every
    iter would dequeue at most one. Bootstrap traffic is bursty enough
    that at least the identity process should hit `iter_drained=N>=2`
    in some snapshots."""
    with MultiPeerHarness(n_peers=3, runtime_sec=45, log_level='warning',
                          capture_probes=True) as h:
        h.wait_until_all_peers_grouped(timeout=40, poll=2.0)
    # The drained-count snapshot reason can be a small int
    # (typically 0 / 1 in steady state; 2+ during bootstrap bursts).
    # Sum across peers and snapshots; we only need ONE bursty snapshot
    # to prove the loop is drain-shaped.
    total_id_bursts = h.drain_bursts('proc.identity', min_drained=2)
    total_neg_bursts = h.drain_bursts('proc.negotiation', min_drained=2)
    total_rep_bursts = h.drain_bursts('proc.reputation', min_drained=2)
    total_net_bursts = h.drain_bursts('proc.network', min_drained=2)
    # Identity + network are the most reliably bursty during bootstrap.
    # Neg + rep may be quiet on a 3-peer mesh — count them all together.
    total = (total_id_bursts + total_neg_bursts +
             total_rep_bursts + total_net_bursts)
    assert total > 0, (
        f'no drain-loop bursts observed across id/neg/rep/net — drain '
        f'pattern may have regressed. Configs at {h.tmp_root}')


@_skip_loopback
@pytest.mark.slow
def test_harness_two_peers_no_unhandled_cascade():
    """Probe-driven invariant: bootstrap should not produce a flood of
    `unhandled:*` events (the dispatch-table mismatch cascade we hit
    during Stage-3b debugging). A handful per run is normal — anything
    over the threshold indicates a real handler-registration gap."""
    with MultiPeerHarness(n_peers=2, runtime_sec=35, log_level='warning',
                          capture_probes=True) as h:
        h.wait_until_all_peers_grouped(timeout=30, poll=2.0)
    # Read after teardown so per-process probe writers have flushed.
    h.assert_no_unhandled_cascade(max_count=20)
