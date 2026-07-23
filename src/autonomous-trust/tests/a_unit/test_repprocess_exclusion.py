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
"""Communication cut-off / exclusion + explicit-rehabilitation tests.

Focused coverage for the "signed-scale-that-isn't" threshold work
(REPUTATION_THRESHOLDS_TODO.md), on the [0, 1] scale with COMM_CUTOFF at 0.1
and PREREP_NEUTRAL at 0.2:

  * a cut-off crossing publishes a Network.exclude control message (and the
    reverse crossing publishes Network.readmit);
  * the persistence filter is two-sided (self + trusted + excluded), so an
    excluded peer is carried across a restart and boot-reseeds into _excluded;
  * REASON_REHABILITATE lifts the score to PREREP_NEUTRAL (0.2) and clears the
    slash floor AND the running-EMA latch (_consensus_ema / _consensus_folded_idx
    / _consensus_last) so the lift is visible to _running_consensus;
  * the netprocess inbound-drop / outbound-skip gate rejects an excluded
    address and readmit reverses it.

Dependency-light: reuses the slashing-test fixture pattern (MagicMock configs)
and constructs a bare NetworkProcess via __new__ for the gate methods.
"""
import queue
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.reputation.repprocess import (
    ReputationProcess, REPUTATION_PERSIST_THRESHOLD,
)
from autonomous_trust.core.reputation.reputation import SlashAttestation
from autonomous_trust.core.network.network import Network
from autonomous_trust.core.network.netprocess import NetworkProcess
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds


# --- fixtures ---------------------------------------------------------------

def _make_rep_process(self_uuid=None):
    log_q = queue.Queue()
    identity = MagicMock()
    identity.uuid = self_uuid or uuid4()
    identity.sign = lambda m: b'\x01\x02\x03\x04'
    procs = []
    for nm in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
               CfgIds.reputation):
        p = MagicMock()
        p.name = nm
        procs.append(p)
    configs = {
        'processes': procs,
        CfgIds.identity: identity,
        CfgIds.peers: MagicMock(),
        CfgIds.group: MagicMock(),
    }
    rp = ReputationProcess(configs, ProcessTracker(), log_q, suppress_log=True)
    rp.protocol.group.uuid = uuid4()
    return rp


def _att(slasher, target, reason=SlashAttestation.REASON_SUSTAINED_ANOMALY,
         floor=0.0, epoch=1):
    return SlashAttestation(slasher_uuid=slasher, target_uuid=target,
                            reason=reason, floor_score=floor, epoch=epoch)


def _ipc_queues():
    return {CfgIds.network: queue.Queue(),
            CfgIds.identity: queue.Queue(),
            CfgIds.negotiation: queue.Queue()}


def _drain(q):
    while not q.empty():
        q.get_nowait()


def _bare_netproc():
    """A NetworkProcess with only the attributes the gate methods touch,
    built without the heavy multiprocessing __init__."""
    np = NetworkProcess.__new__(NetworkProcess)
    np._rejected_addresses = set()
    np.acceptance = None
    np.protocol = MagicMock()  # .peers reached via the `peers` property
    np.logger = MagicMock()
    return np


# --- cut-off crossing -> exclude/readmit control messages -------------------

class TestCutoffCrossing:
    def _rp_with_addr(self, addr='10.0.0.9'):
        rp = _make_rep_process()
        rp.protocol.peers = MagicMock()
        rp.protocol.peers.find_by_uuid.return_value = SimpleNamespace(address=addr)
        return rp

    def test_crossing_below_cutoff_publishes_exclude(self):
        rp = self._rp_with_addr('10.0.0.9')
        peer = uuid4()
        q = _ipc_queues()
        # Start above the cut-off (tier 0, not excluded), then drop below it.
        rp._publish_tier_change(q, peer, 0.3)
        _drain(q[CfgIds.network])
        _drain(q[CfgIds.identity])
        rp._publish_tier_change(q, peer, 0.05)
        assert str(peer) in rp._excluded
        msg = q[CfgIds.network].get_nowait()
        assert msg.function == Network.exclude
        assert msg.obj == '10.0.0.9'

    def test_reverse_crossing_publishes_readmit(self):
        rp = self._rp_with_addr('10.0.0.9')
        peer = uuid4()
        q = _ipc_queues()
        rp._publish_tier_change(q, peer, 0.05)   # exclude
        _drain(q[CfgIds.network])
        rp._publish_tier_change(q, peer, 0.3)    # back above the cut-off
        assert str(peer) not in rp._excluded
        msg = q[CfgIds.network].get_nowait()
        assert msg.function == Network.readmit
        assert msg.obj == '10.0.0.9'

    def test_no_publish_when_staying_below_cutoff(self):
        # 0.08 -> 0.04 is a tier-0 -> tier-0, excluded -> excluded no-op:
        # already excluded, so no duplicate control message is emitted.
        rp = self._rp_with_addr()
        peer = uuid4()
        q = _ipc_queues()
        rp._publish_tier_change(q, peer, 0.08)
        _drain(q[CfgIds.network])
        rp._publish_tier_change(q, peer, 0.04)
        assert q[CfgIds.network].empty()
        assert str(peer) in rp._excluded


# --- two-sided persistence filter + boot reseed -----------------------------

class TestPersistenceTwoSided:
    def _seed_current(self, rp, mapping):
        cur = rp.reputations.current
        cur.clear()
        for u, s in mapping.items():
            cur[u] = s

    def test_persist_keeps_self_trusted_and_excluded(self):
        rp = _make_rep_process()
        self_uuid = rp.identity.uuid
        trusted, midband, excluded = uuid4(), uuid4(), uuid4()
        self._seed_current(rp, {self_uuid: 0.95, trusted: 0.8,
                                midband: 0.3, excluded: 0.05})
        assert 0.8 > REPUTATION_PERSIST_THRESHOLD > 0.3  # sanity on the band
        captured = {}

        def fake_filtered(keep):
            captured['keep'] = set(keep)
            snap = MagicMock()
            snap.to_file = lambda path: None
            return snap

        rp.reputations.filtered_for_persist = fake_filtered
        rp._persist_reputations()
        keep = captured['keep']
        assert self_uuid in keep          # self always
        assert trusted in keep            # > persist threshold
        assert excluded in keep           # < comm cut-off (must survive restart)
        assert midband not in keep        # ordinary mid-band peer is dropped

    def test_boot_reseeds_excluded_from_snapshot(self):
        rp = _make_rep_process()
        self_uuid = rp.identity.uuid
        low, high = uuid4(), uuid4()
        self._seed_current(rp, {self_uuid: 0.9, low: 0.05, high: 0.7})
        rp._excluded.clear()
        rp._seed_exclusions_from_snapshot()
        assert str(low) in rp._excluded        # below cut-off -> stays excluded
        assert str(high) not in rp._excluded   # trusted -> not excluded
        assert str(self_uuid) not in rp._excluded


# --- explicit rehabilitation ------------------------------------------------

class TestRehabilitation:
    def test_rehab_lifts_to_neutral_and_clears_latches(self):
        rp = _make_rep_process()
        target = uuid4()
        tkey = str(target)
        # Slash to the floor: excluded, and the sticky/EMA latches pinned low.
        rp._apply_slash(_att(rp.identity.uuid, target, floor=0.0, epoch=1))
        rp._consensus_ema[tkey] = 0.0
        rp._consensus_folded_idx[tkey] = 5
        rp._consensus_last[tkey] = 0.0
        assert rp._is_excluded(rp._consensus_reputation(target))

        rp._apply_slash(_att(rp.identity.uuid, target,
                             reason=SlashAttestation.REASON_REHABILITATE,
                             floor=0.0, epoch=2))
        # Hard floor released.
        assert tkey not in rp._slashed
        # Running-EMA latch cleared so the lift is visible to _running_consensus
        # (clearing only _consensus_last used to leave the floored EMA pinned).
        assert tkey not in rp._consensus_ema
        assert tkey not in rp._consensus_folded_idx
        assert tkey not in rp._consensus_last
        # Lifted to PREREP_NEUTRAL (0.2), above the cut-off -> re-admitted.
        assert rp._consensus_reputation(target) == pytest.approx(0.2)
        assert not rp._is_excluded(rp._consensus_reputation(target))


# --- netprocess inbound-drop / outbound-skip gate ---------------------------

class TestNetprocessGate:
    def test_norm_addr_strips_suffix(self):
        assert NetworkProcess._norm_addr('10.0.0.5/24') == '10.0.0.5'
        assert NetworkProcess._norm_addr('10.0.0.5') == '10.0.0.5'
        assert NetworkProcess._norm_addr(None) is None

    def test_handle_exclude_rejects_inbound(self):
        np = _bare_netproc()
        np.handle_exclude({}, SimpleNamespace(obj='10.0.0.5/24'))
        # Keyed on the normalized address, so both raw and suffixed match.
        assert np.reject_message('10.0.0.5') is True
        assert np.reject_message('10.0.0.5/24') is True
        # Inbound frames from an excluded peer are dropped even if known.
        assert np.accept_peer_message('10.0.0.5') is False

    def test_handle_readmit_reverses_exclusion(self):
        np = _bare_netproc()
        np.acceptance = lambda addr: True  # known/acceptable once readmitted
        np.handle_exclude({}, SimpleNamespace(obj='10.0.0.5'))
        assert np.accept_peer_message('10.0.0.5') is False
        np.handle_readmit({}, SimpleNamespace(obj='10.0.0.5'))
        assert np.reject_message('10.0.0.5') is False
        assert np.accept_peer_message('10.0.0.5') is True

    def test_blacklist_uses_normalized_address(self):
        np = _bare_netproc()
        np.blacklist_address('10.0.0.7/24')
        assert np.reject_message('10.0.0.7') is True
