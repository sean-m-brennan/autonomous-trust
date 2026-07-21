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
"""Idle reputation-decay (warm-start staleness) tests.

A peer's operational reputation is a memory of past AT-bounded activity.
The longer since we last transacted with a peer, the closer that memory
relaxes toward "almost-but-not-quite neutral" (the asymptote, just above
0.50) — never to neutral, and crucially ASYMMETRICALLY: absence erodes
earned *high* trust but never rehabilitates a distrusted/corrupt node.
See repprocess.ReputationProcess.REPUTATION_DECAY_* and
doc/architecture/persistent-cohort.md.
"""
import queue
from uuid import uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.reputation import repprocess
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import Reputations
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds


R = ReputationProcess
A = R.REPUTATION_DECAY_ASYMPTOTE
ONSET = R.REPUTATION_DECAY_ONSET
HL = R.REPUTATION_DECAY_HALF_LIFE


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


# --- pure decay function -----------------------------------------------------

class TestDecayedScore:
    def test_within_onset_grace_is_unchanged(self):
        assert R._decayed_score(0.9, ONSET) == 0.9
        assert R._decayed_score(0.9, ONSET - 1) == 0.9

    def test_one_half_life_halves_the_gap_above_asymptote(self):
        v = R._decayed_score(0.9, ONSET + HL)
        assert v == pytest.approx(A + (0.9 - A) * 0.5)

    def test_approaches_but_never_crosses_asymptote(self):
        v = R._decayed_score(0.9, ONSET + 50 * HL)
        assert v >= A
        assert v == pytest.approx(A, abs=1e-3)

    def test_asymmetry_distrust_is_never_rehabilitated(self):
        # corrupt / distrusted nodes (at or below the asymptote) stay put no
        # matter how long idle -- so an excluded peer (< 0.1 comm cut-off)
        # can never idle its way back above the cut-off.
        assert R._decayed_score(0.05, ONSET + 99 * HL) == 0.05  # excluded
        assert R._decayed_score(0.15, ONSET + 99 * HL) == 0.15  # low/degraded
        assert R._decayed_score(A, ONSET + 99 * HL) == A

    def test_none_is_safe(self):
        assert R._decayed_score(None, 99999) is None

    def test_monotonic_in_idle_time(self):
        prev = 1.0
        for k in (0, 1, 2, 4, 8, 16):
            cur = R._decayed_score(0.95, ONSET + k * HL)
            assert cur <= prev + 1e-12
            prev = cur


# --- periodic sweep ----------------------------------------------------------

class TestDecaySweep:
    def test_sweep_decays_idle_erodes_high_keeps_low_and_active(self):
        rp = _make_rep_process()
        rp._publish_tier_change = MagicMock()
        rp._persist_reputations = MagicMock()
        self_u = rp.identity.uuid
        idle, active, corrupt, slashed = uuid4(), uuid4(), uuid4(), uuid4()
        rp.reputations = Reputations(current={
            idle: 0.90, active: 0.90, corrupt: 0.20,
            slashed: 0.90, self_u: 0.99,
        })
        present = 10 * HL + ONSET + 1_000_000.0
        rp._last_interaction = {
            str(idle): present - 10 * HL,     # long idle -> decays
            str(active): present,             # just transacted -> untouched
            str(corrupt): present - 10 * HL,  # idle but low -> asymmetry
            str(slashed): present - 10 * HL,  # idle but slashed -> skipped
        }
        rp._slashed[str(slashed)] = (0.1, 1)
        rp._last_decay_sweep = 0.0

        rp._decay_reputations({}, present)

        assert rp.reputations.current[idle] < 0.90
        assert rp.reputations.current[idle] == pytest.approx(A, abs=1e-2)
        assert rp.reputations.current[active] == 0.90
        assert rp.reputations.current[corrupt] == 0.20
        assert rp.reputations.current[slashed] == 0.90  # slash floor authoritative
        assert rp.reputations.current[self_u] == 0.99   # self never decayed
        # only the eroded peer triggers a tier republish + a persist
        published = {str(c.args[1]) for c in rp._publish_tier_change.call_args_list}
        assert published == {str(idle)}
        rp._persist_reputations.assert_called_once()

    def test_sweep_is_throttled(self):
        rp = _make_rep_process()
        rp._publish_tier_change = MagicMock()
        rp._persist_reputations = MagicMock()
        idle = uuid4()
        rp.reputations = Reputations(current={idle: 0.90})
        present = 10 * HL + ONSET + 1_000_000.0
        rp._last_interaction = {str(idle): present - 10 * HL}
        rp._last_decay_sweep = 0.0

        rp._decay_reputations({}, present)
        first = rp.reputations.current[idle]
        assert first < 0.90
        # immediate second call within SWEEP_INTERVAL is a no-op
        rp._decay_reputations({}, present)
        assert rp.reputations.current[idle] == first
        rp._persist_reputations.assert_called_once()

    def test_consensus_channel_decays_in_lockstep(self):
        rp = _make_rep_process()
        rp._publish_tier_change = MagicMock()
        rp._persist_reputations = MagicMock()
        idle = uuid4()
        rp.reputations = Reputations(current={idle: 0.90})
        rp._consensus_last[str(idle)] = 0.90
        present = 10 * HL + ONSET + 1_000_000.0
        rp._last_interaction = {str(idle): present - 10 * HL}
        rp._last_decay_sweep = 0.0

        rp._decay_reputations({}, present)
        assert rp._consensus_last[str(idle)] < 0.90


# --- interaction stamping ----------------------------------------------------

class TestNoteInteraction:
    def test_note_resets_idle_clock_and_blocks_decay(self):
        rp = _make_rep_process()
        rp._publish_tier_change = MagicMock()
        rp._persist_reputations = MagicMock()
        peer = uuid4()
        rp.reputations = Reputations(current={peer: 0.90})
        rp._note_interaction(peer)
        assert str(peer) in rp._last_interaction
        present = rp._last_interaction[str(peer)] + 1.0  # just barely later
        rp._last_decay_sweep = 0.0
        rp._decay_reputations({}, present)
        assert rp.reputations.current[peer] == 0.90  # too recent to decay

    def test_self_interaction_is_ignored(self):
        rp = _make_rep_process()
        rp._note_interaction(rp.identity.uuid)
        assert str(rp.identity.uuid) not in rp._last_interaction


# --- warm-start seed from persisted snapshot --------------------------------

class TestSeedIdleFromSnapshot:
    def test_offline_gap_decays_loaded_cohort(self, monkeypatch):
        rp = _make_rep_process()
        peer, low = uuid4(), uuid4()
        rp.reputations = Reputations(current={peer: 0.90, low: 0.20})
        rp._last_interaction = {}
        present = repprocess.now().timestamp()
        mtime = present - 10 * HL
        monkeypatch.setattr(repprocess.os.path, 'getmtime', lambda _p: mtime)

        rp._seed_idle_from_snapshot()

        # high score faded by the offline gap; low score untouched
        assert rp.reputations.current[peer] < 0.90
        assert rp.reputations.current[low] == 0.20
        # idle clocks back-dated to the snapshot instant
        assert rp._last_interaction[str(peer)] == mtime

    def test_cold_start_no_snapshot_is_noop(self, monkeypatch):
        rp = _make_rep_process()
        peer = uuid4()
        rp.reputations = Reputations(current={peer: 0.90})
        rp._last_interaction = {}

        def _raise(_p):
            raise OSError('no such file')
        monkeypatch.setattr(repprocess.os.path, 'getmtime', _raise)

        rp._seed_idle_from_snapshot()
        assert rp.reputations.current[peer] == 0.90
        assert rp._last_interaction == {}
