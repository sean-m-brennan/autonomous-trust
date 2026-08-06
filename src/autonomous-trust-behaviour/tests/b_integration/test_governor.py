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
"""Governed-path tests (B4): the PeerBehaviourGovernor a node embeds to monitor
its OWN peers, turning a *sustained* anomaly into a real core SlashAttestation on
the reputation queue -- "ML proposes, deterministic consensus disposes".

The governor is the host-side adapter; it is exercised here against fakes for the
node surfaces it touches (identity, peers, queue), so the governance wiring is
pinned deterministically without a live mesh. The slash it emits is the genuine
``autonomous_trust.core.reputation.reputation.SlashAttestation`` carrying the real
``REASON_SUSTAINED_ANOMALY``, so a mismatch with the core contract fails here. The
pure library that produces the proposals is tested in test_ensemble.py.
"""
import random
from queue import Full
from uuid import UUID

import pytest

# The governor imports autonomous_trust.core; the package conftest puts the
# sibling `autonomous-trust` source on the path. Skip cleanly if it is absent.
behaviour = pytest.importorskip('autonomous_trust.behaviour')
if not hasattr(behaviour, 'PeerBehaviourGovernor'):
    pytest.skip('core not importable', allow_module_level=True)

from autonomous_trust.core import CfgIds  # noqa: E402
from autonomous_trust.core.reputation.reputation import SlashAttestation  # noqa: E402
from autonomous_trust.behaviour import (AccessEvent, PeerBehaviourGovernor,  # noqa: E402
                                        DEFAULT_SLASH_FLOOR)

# Small windows so the streams warm fast; identical tuning to the ensemble tests.
DET_KW = dict(hst_window=60, hst_trees=15, hst_height=10,
              hbos_window=120, hbos_refit_every=20, hbos_warmup=70,
              calib_warmup=30, min_obs=90, feature_window=48,
              enter=0.9, dwell_target=8, leak=2, calib_min_std=0.10)

_NORMAL_CAPS = ('telemetry.report', 'data.publish', 'status.ping')
_NORMAL_CPS = ('peer-A', 'peer-B', 'peer-C')


def _normal(rng, t):
    ev = AccessEvent(time=t, capability=rng.choice(_NORMAL_CAPS),
                     refused=(rng.random() < 0.05),
                     score=min(1.0, max(0.0, rng.gauss(0.85, 0.05))),
                     counterparty=rng.choice(_NORMAL_CPS))
    return ev, max(0.1, rng.gauss(1.0, 0.2))


def _malicious(rng, t):
    ev = AccessEvent(time=t, capability=f'probe-{rng.randrange(10)}',
                     refused=(rng.random() < 0.5),
                     score=min(1.0, max(0.0, rng.gauss(0.15, 0.05))),
                     counterparty=f'cp-{rng.randrange(10)}')
    return ev, rng.choice((0.05, 0.1, 2.0, 3.0))


# --- fakes for the node surfaces the governor reads -----------------------

class _Identity:
    def __init__(self, uuid):
        self.uuid = uuid
        self.nickname = 'me'


class _Peers:
    def __init__(self, peers):
        self._by_uuid = {p.uuid: p for p in peers}

    def find_by_uuid(self, uuid):
        return self._by_uuid.get(uuid)


class _Host:
    """Minimal stand-in for the node: just what the governor reads."""
    def __init__(self, self_uuid, peer_uuids=()):
        self.identity = _Identity(self_uuid)
        peers = [type('P', (), {'uuid': u, 'nickname': 'p%d' % i})()
                 for i, u in enumerate(peer_uuids)]
        self.peers = _Peers(peers)


class _Queue:
    def __init__(self, full=False):
        self.items = []
        self._full = full

    def put(self, obj, block=True, timeout=None):
        if self._full:
            raise Full()
        self.items.append(obj)


def _uid(n):
    """A deterministic target UUID. The per-entity detector seed derives from
    (base_seed, peer_id, role), so the target must be fixed for latching to be
    reproducible -- a random uuid4 would make the alarm seed-flaky across runs."""
    return UUID(int=n)


def _governor(self_uuid, peer_uuids, **kw):
    kw.setdefault('detector_kwargs', DET_KW)
    return PeerBehaviourGovernor(_Host(self_uuid, peer_uuids), **kw)


def _slashes(queues):
    return [m for m in queues[CfgIds.reputation].items
            if isinstance(m, SlashAttestation)]


def _drive(gov, target, rng, n_normal=250, n_mal=80):
    t = 0.0
    for _ in range(n_normal):
        ev, dt = _normal(rng, t)
        gov.observe(target, 'sensor', ev)
        t += dt
    for _ in range(n_mal):
        ev, dt = _malicious(rng, t)
        gov.observe(target, 'sensor', ev)
        t += dt
    return t


# --------------------------------------------------------------------------
# Autonomous governed path (auto_slash=True)
# --------------------------------------------------------------------------

class TestAutonomousSlash:
    def test_sustained_anomaly_submits_one_slash(self):
        target = _uid(1)
        gov = _governor(_uid(99), (target,), auto_slash=True, base_seed=1)
        queues = {CfgIds.reputation: _Queue()}
        _drive(gov, str(target), random.Random(100))
        gov.enforce(queues)

        slashes = _slashes(queues)
        assert len(slashes) == 1
        att = slashes[0]
        assert att.target_uuid == target
        assert att.slasher_uuid == gov.host.identity.uuid
        assert att.reason == SlashAttestation.REASON_SUSTAINED_ANOMALY
        assert att.floor_score == DEFAULT_SLASH_FLOOR
        assert att.evidence_ref['kind'] == 'behavioural_anomaly'
        assert att.evidence_ref['attributions']  # non-empty "why"

    def test_slash_is_idempotent_across_ticks(self):
        target = _uid(2)
        gov = _governor(_uid(99), (target,), auto_slash=True, base_seed=1)
        queues = {CfgIds.reputation: _Queue()}
        t = _drive(gov, str(target), random.Random(100))
        gov.enforce(queues)
        rng = random.Random(7)
        for _ in range(40):
            ev, dt = _malicious(rng, t)
            gov.observe(str(target), 'sensor', ev)
            t += dt
        gov.enforce(queues)
        assert len(_slashes(queues)) == 1

    def test_steady_peer_no_slash(self):
        target = _uid(3)
        gov = _governor(_uid(99), (target,), auto_slash=True, base_seed=1)
        queues = {CfgIds.reputation: _Queue()}
        rng = random.Random(100)
        t = 0.0
        for _ in range(400):
            ev, dt = _normal(rng, t)
            gov.observe(str(target), 'sensor', ev)
            t += dt
        gov.enforce(queues)
        assert _slashes(queues) == []
        assert gov.recommendations == []

    def test_single_spike_no_slash(self):
        target = _uid(4)
        gov = _governor(_uid(99), (target,), auto_slash=True, base_seed=1)
        queues = {CfgIds.reputation: _Queue()}
        rng = random.Random(100)
        t = 0.0
        for _ in range(250):
            ev, dt = _normal(rng, t)
            gov.observe(str(target), 'sensor', ev)
            t += dt
        ev, _dt = _malicious(rng, t)      # one lone spike
        gov.observe(str(target), 'sensor', ev)
        for _ in range(80):               # then a sustained return to normal
            ev, dt = _normal(rng, t)
            gov.observe(str(target), 'sensor', ev)
            t += dt
        gov.enforce(queues)
        assert _slashes(queues) == []

    def test_never_slashes_self(self):
        me = _uid(5)
        gov = _governor(me, (me,), auto_slash=True, base_seed=1)
        queues = {CfgIds.reputation: _Queue()}
        _drive(gov, str(me), random.Random(100))
        gov.enforce(queues)
        assert _slashes(queues) == []

    def test_unknown_target_not_governed(self):
        stranger = _uid(6)
        gov = _governor(_uid(99), (), auto_slash=True, base_seed=1)  # no peers
        queues = {CfgIds.reputation: _Queue()}
        _drive(gov, str(stranger), random.Random(100))
        gov.enforce(queues)
        assert _slashes(queues) == []
        assert gov.recommendations == []

    def test_transient_queue_full_retries(self):
        # a full queue must not consume the one-shot: the proposal is kept and
        # a later enforce on a working queue submits it.
        target = _uid(7)
        gov = _governor(_uid(99), (target,), auto_slash=True, base_seed=1)
        _drive(gov, str(target), random.Random(100))
        gov.enforce({CfgIds.reputation: _Queue(full=True)})
        assert str(target) not in gov._acted
        ok = {CfgIds.reputation: _Queue()}
        gov.enforce(ok)                       # no new observations needed
        assert len(_slashes(ok)) == 1


# --------------------------------------------------------------------------
# Human-on-the-loop (default, auto_slash=False)
# --------------------------------------------------------------------------

class TestHumanOnTheLoop:
    def test_default_is_recommend_not_submit(self):
        target = _uid(8)
        gov = _governor(_uid(99), (target,), base_seed=1)  # auto_slash off
        assert gov.auto_slash is False
        queues = {CfgIds.reputation: _Queue()}
        _drive(gov, str(target), random.Random(100))
        gov.enforce(queues)
        assert _slashes(queues) == []          # nothing autonomously submitted
        assert len(gov.recommendations) == 1   # surfaced for an operator
        rec = gov.recommendations[0]
        assert rec.target_uuid == str(target)
        assert rec.reason == SlashAttestation.REASON_SUSTAINED_ANOMALY
        assert rec.floor == DEFAULT_SLASH_FLOOR
        assert rec.attributions


# --------------------------------------------------------------------------
# Observation seam
# --------------------------------------------------------------------------

class _Msg:
    def __init__(self, function, from_uuid, cap=None, refused=False):
        self.function = function
        self.from_whom = type('I', (), {'uuid': from_uuid})()
        self.obj = type('O', (), {'capability': type('C', (), {'name': cap})()})() \
            if cap is not None else None
        self.refused = refused


class TestObservationSeam:
    def test_access_event_from_translates_capability_message(self):
        gov = _governor(_uid(99), ())
        actor = _uid(1)
        triple = gov.access_event_from(_Msg('negotiate', actor,
                                            cap='data.publish', refused=True))
        assert triple is not None
        peer_id, role, ev = triple
        assert peer_id == str(actor)
        assert role == gov.default_role
        assert ev.capability == 'data.publish'
        assert ev.refused is True
        assert ev.counterparty == str(gov.host.identity.uuid)

    def test_access_event_from_ignores_uncapability_messages(self):
        gov = _governor(_uid(99), ())
        assert gov.access_event_from(_Msg('ping', _uid(1))) is None  # no cap
        assert gov.access_event_from(type('X', (), {})()) is None    # no fn

    def test_ingest_message_observes(self):
        target = _uid(1)
        gov = _governor(_uid(99), (target,), base_seed=1)
        for _ in range(5):
            gov.ingest_message(_Msg('negotiate', target, cap='data.publish'))
        det = gov.monitor.detector_for(str(target), gov.default_role)
        assert det._n == 5
        assert gov.ingest_message(_Msg('ping', target)) is None  # not an event


# --------------------------------------------------------------------------
# Determinism (the admissibility property)
# --------------------------------------------------------------------------

class TestDeterminism:
    def test_same_stream_same_slash_evidence(self):
        target = _uid(9)

        def run():
            gov = _governor(_uid(99), (target,), auto_slash=True, base_seed=2)
            queues = {CfgIds.reputation: _Queue()}
            _drive(gov, str(target), random.Random(100))
            gov.enforce(queues)
            return _slashes(queues)

        a, b = run(), run()
        assert len(a) == len(b) == 1
        assert a[0].evidence_ref == b[0].evidence_ref     # bit-identical "why"
        assert a[0].floor_score == b[0].floor_score
