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
"""Unit tests for the detector ensemble + sustained-anomaly state machine (B3).

Demonstrates the core O3 behavior in microcosm: a compromised-but-credentialed
peer that drifts from its learned behavioral envelope is eventually flagged,
while a steady peer is not, and a single anomalous spike does NOT trip an
exclusion (the base-rate guard). Determinism is pinned throughout.
"""
import random

from autonomous_trust.behaviour import (AccessEvent, BehaviorMonitor,
                                        SlashProposal, REASON_SUSTAINED_ANOMALY)
from autonomous_trust.behaviour.ensemble import PeerRoleDetector, _entity_seed


# Small windows so the test streams warm quickly but the logic is identical.
DET_KW = dict(hst_window=60, hst_trees=15, hst_height=10,
              hbos_window=120, hbos_refit_every=20, hbos_warmup=70,
              calib_warmup=30, min_obs=90, feature_window=48,
              enter=0.9, dwell_target=8, leak=2, calib_min_std=0.10)

_NORMAL_CAPS = ('telemetry.report', 'data.publish', 'status.ping')
_NORMAL_CPS = ('peer-A', 'peer-B', 'peer-C')


def _normal(rng, t):
    """A *realistic* normal event: a small mix of routine capabilities and
    counterparties, the occasional refusal, good (jittered) transaction scores,
    and a roughly-periodic cadence. Real normal traffic has spread -- so the
    learned envelope does too, which is what makes the detector robust to a
    lone perturbation (a zero-variance baseline would be a hair-trigger)."""
    ev = AccessEvent(
        time=t,
        capability=rng.choice(_NORMAL_CAPS),
        refused=(rng.random() < 0.05),
        score=min(1.0, max(0.0, rng.gauss(0.85, 0.05))),
        counterparty=rng.choice(_NORMAL_CPS))
    return ev, max(0.1, rng.gauss(1.0, 0.2))


def _malicious(rng, t):
    """Compromised-but-credentialed behavior: erratic capability probing, ~50%
    refusals, poor transaction scores, scattered counterparties, bursty timing
    -- many features sustained off-envelope at once."""
    ev = AccessEvent(
        time=t,
        capability=f'probe-{rng.randrange(10)}',
        refused=(rng.random() < 0.5),
        score=min(1.0, max(0.0, rng.gauss(0.15, 0.05))),
        counterparty=f'cp-{rng.randrange(10)}')
    return ev, rng.choice((0.05, 0.1, 2.0, 3.0))


def _feed(det, gen, n, rng, start=0.0):
    t = start
    last = None
    peak = 0.0
    for _ in range(n):
        ev, dt = gen(rng, t)
        last = det.observe(ev)
        peak = max(peak, last.score)
        t += dt
    return last, t, peak


class TestSustainedAnomaly:
    def test_steady_peer_never_alarms(self):
        det = PeerRoleDetector('p', 'sensor', seed=1, **DET_KW)
        rng = random.Random(100)
        last, _, _ = _feed(det, _normal, 400, rng)
        assert det.warm
        assert last.alarmed is False

    def test_compromised_peer_is_eventually_excluded(self):
        det = PeerRoleDetector('p', 'sensor', seed=1, **DET_KW)
        rng = random.Random(100)
        # learn the normal envelope
        _, t, _ = _feed(det, _normal, 250, rng)
        assert det.warm and not det.alarmed
        # sustained compromise -> alarm, and the score climbs well into anomaly
        last, _, peak = _feed(det, _malicious, 80, rng, start=t)
        assert last.alarmed is True
        assert peak >= 0.8
        # the explanation points at genuinely-shifted features
        top = dict(last.top_features(8))
        assert top.get('refusal', 0) > 0.3 or top.get('txn_score', 0) > 0.3

    def test_single_spike_does_not_alarm(self):
        det = PeerRoleDetector('p', 'sensor', seed=1, **DET_KW)
        rng = random.Random(100)
        _, t, _ = _feed(det, _normal, 250, rng)
        # one lone anomalous event, then a sustained return to normal: the dwell
        # window leaks back down before reaching the alarm target
        ev, _dt = _malicious(rng, t)
        det.observe(ev)
        last, _, _ = _feed(det, _normal, 80, rng, start=t + 1.0)
        assert last.alarmed is False

    def test_no_alarm_before_warmup(self):
        det = PeerRoleDetector('p', 'sensor', seed=1, **DET_KW)
        rng = random.Random(100)
        # feed only malicious traffic from the start: until warm, no alarm fires
        t = 0.0
        for _ in range(DET_KW['min_obs'] - 1):
            ev, dt = _malicious(rng, t)
            d = det.observe(ev)
            assert d.alarmed is False
            assert d.warm is False
            t += dt

    def test_reset_alarm_clears(self):
        det = PeerRoleDetector('p', 'sensor', seed=1, **DET_KW)
        rng = random.Random(100)
        _, t, _ = _feed(det, _normal, 250, rng)
        _feed(det, _malicious, 80, rng, start=t)
        assert det.alarmed
        det.reset_alarm()
        assert not det.alarmed


class TestDeterminism:
    def test_identical_streams_identical_decisions(self):
        def run():
            det = PeerRoleDetector('p', 'sensor', seed=5, **DET_KW)
            rng = random.Random(100)   # same seed => same event sequence
            out = []
            _, t, _ = _feed(det, _normal, 250, rng)
            for _ in range(60):
                ev, dt = _malicious(rng, t)
                out.append(det.observe(ev).score)
                t += dt
            return out, det.alarmed
        a_scores, a_alarm = run()
        b_scores, b_alarm = run()
        assert a_scores == b_scores       # bit-identical score stream
        assert a_alarm == b_alarm

    def test_entity_seed_is_stable(self):
        # stable across calls/processes (unlike builtin hash)
        assert _entity_seed(7, ('peer-1', 'gateway')) == \
            _entity_seed(7, ('peer-1', 'gateway'))
        assert _entity_seed(7, ('peer-1', 'gateway')) != \
            _entity_seed(7, ('peer-2', 'gateway'))

    def test_monitor_routes_per_entity_and_is_reproducible(self):
        def run():
            mon = BehaviorMonitor(base_seed=3, **DET_KW)
            rng = random.Random(100)
            t = 0.0
            last = {}
            for _ in range(250):
                eg, _d = _normal(rng, t)
                eb, dt = _normal(rng, t)
                last['good'] = mon.observe('good', 'sensor', eg)
                last['bad'] = mon.observe('bad', 'sensor', eb)
                t += dt
            for _ in range(80):
                eb, dt = _malicious(rng, t)
                eg, _d = _normal(rng, t)
                last['bad'] = mon.observe('bad', 'sensor', eb)
                last['good'] = mon.observe('good', 'sensor', eg)
                t += dt
            return mon, last
        mon, last = run()
        assert set(mon.entities) == {('good', 'sensor'), ('bad', 'sensor')}
        assert last['bad'].alarmed is True
        assert last['good'].alarmed is False
        # only the compromised entity is in the alarmed snapshot
        assert [d.peer_id for d in mon.alarmed()] == ['bad']
        # reproducible across runs
        mon2, _last2 = run()
        assert [d.peer_id for d in mon2.alarmed()] == ['bad']


class TestProposals:
    """The library's neutral, node-agnostic output -- the rising-edge
    SlashProposal stream the host-side adapter (and the C port) consume."""

    def _run(self, mon, seed=100):
        rng = random.Random(seed)
        t = 0.0
        for _ in range(250):
            ev, dt = _normal(rng, t)
            mon.observe('p', 'sensor', ev)
            t += dt
        for _ in range(80):
            ev, dt = _malicious(rng, t)
            mon.observe('p', 'sensor', ev)
            t += dt
        return t, rng

    def test_rising_edge_emits_one_proposal(self):
        mon = BehaviorMonitor(base_seed=1, **DET_KW)
        self._run(mon)
        props = mon.poll_proposals()
        assert len(props) == 1
        p = props[0]
        assert isinstance(p, SlashProposal)
        assert p.peer_id == 'p' and p.role == 'sensor'
        assert p.reason == REASON_SUSTAINED_ANOMALY
        assert p.floor == mon.slash_floor
        assert p.attributions                      # the explainable "why"
        assert mon.poll_proposals() == []          # drained; one per rising edge

    def test_no_proposal_for_steady_peer(self):
        mon = BehaviorMonitor(base_seed=1, **DET_KW)
        rng = random.Random(100)
        t = 0.0
        for _ in range(400):
            ev, dt = _normal(rng, t)
            mon.observe('p', 'sensor', ev)
            t += dt
        assert mon.poll_proposals() == []

    def test_latched_alarm_does_not_re_propose(self):
        mon = BehaviorMonitor(base_seed=1, **DET_KW)
        t, rng = self._run(mon)
        assert len(mon.poll_proposals()) == 1
        for _ in range(40):                        # keep abusing -> still latched
            ev, dt = _malicious(rng, t)
            mon.observe('p', 'sensor', ev)
            t += dt
        assert mon.poll_proposals() == []          # no duplicate proposal

    def test_reset_alarm_clears_latch_and_rearms_rising_edge(self):
        # reset_alarm clears the detector latch AND the monitor's rising-edge
        # bookkeeping, so a future alarm can propose again. (We assert the
        # contract directly rather than re-feeding malicious traffic: the
        # detector correctly *adapts* to a sustained pattern, so replaying the
        # same abuse no longer trips it -- that adaptation is intended.)
        mon = BehaviorMonitor(base_seed=1, **DET_KW)
        self._run(mon)
        assert len(mon.poll_proposals()) == 1
        det = mon.detector_for('p', 'sensor')
        assert det.alarmed is True
        mon.reset_alarm('p', 'sensor')
        assert det.alarmed is False and det._dwell == 0
        assert mon._alarm_state[('p', 'sensor')] is False

    def test_configured_floor_in_proposal(self):
        mon = BehaviorMonitor(base_seed=1, slash_floor=0.3, **DET_KW)
        self._run(mon)
        assert mon.poll_proposals()[0].floor == 0.3

    def test_proposals_are_deterministic(self):
        def run():
            mon = BehaviorMonitor(base_seed=2, **DET_KW)
            self._run(mon)
            p = mon.poll_proposals()[0]
            return (p.peer_id, p.role, p.reason, p.floor,
                    round(p.score, 9), tuple(sorted(p.attributions.items())))
        assert run() == run()
