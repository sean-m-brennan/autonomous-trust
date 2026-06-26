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
"""Detector ensemble + sustained-anomaly state machine (SOW Task 3.1/3.3 logic).

One :class:`PeerRoleDetector` per peer×role couples the feature extractor, the
two detectors (Half-Space Trees + HBOS) and their calibrators, and a
*sustained-anomaly* state machine. The state machine is the crux of "ML proposes,
deterministic consensus disposes": a single anomalous spike must NOT trip an
exclusion (the base-rate-fallacy risk the survey calls out). Only a *sustained*
deviation — exceedance held over a dwell window, tolerant of brief dips — raises
an alarm that the governed path (B4) turns into a slashing attestation.

:class:`BehaviorMonitor` routes events to the right per-entity detector, creating
each lazily with a per-entity seed derived deterministically (stable hash, not
Python's salted ``hash()``) from a base seed + the entity key — so every node
runs the *same* model for the same peer×role and produces the same score (the
determinism that makes the score admissible as signed evidence).

Everything here is deterministic and bounded-memory; the only per-entity growth
is one detector set per distinct peer×role seen, which is the intended model.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .detectors import RiverHalfSpaceTrees, PyODHBOS, StreamingCalibrator
from .features import AccessEvent, BehaviorFeatures, FEATURE_NAMES


#: The sole reason this library proposes. A plain string, intentionally NOT
#: imported from ``autonomous_trust.core`` -- the library has no core dependency
#: (it is the future standalone ``.so``); the host-side adapter maps it onto
#: ``SlashAttestation.REASON_SUSTAINED_ANOMALY`` (same value) at submission time.
REASON_SUSTAINED_ANOMALY = 'sustained_anomaly'


def _entity_seed(base_seed: int, key: Tuple[str, str]) -> int:
    """Deterministic per-entity seed (stable across processes/nodes, unlike the
    salted builtin ``hash``)."""
    h = hashlib.blake2b(f'{base_seed}:{key[0]}:{key[1]}'.encode(),
                        digest_size=4).digest()
    return int.from_bytes(h, 'big')


@dataclass(frozen=True)
class AnomalyDecision:
    """The per-event verdict for one peer×role."""
    peer_id: str
    role: str
    score: float                 # combined, calibrated anomaly score in [0,1]
    alarmed: bool                # sustained anomaly tripped (governed-path input)
    pressure: float              # dwell / dwell_target in [0,1] (how close to alarm)
    n_obs: int
    warm: bool
    hst_score: float = 0.0       # calibrated HST contribution
    hbos_score: float = 0.0      # calibrated HBOS contribution
    attributions: Dict[str, float] = field(default_factory=dict)  # HBOS "why"

    def top_features(self, k: int = 3) -> List[Tuple[str, float]]:
        return sorted(self.attributions.items(), key=lambda kv: kv[1],
                      reverse=True)[:k]


@dataclass(frozen=True)
class SlashProposal:
    """A neutral, runtime-agnostic descriptor the library emits on the rising
    edge of a sustained anomaly. It carries *what the detector found* -- no node,
    queue, identity, or wire type. The host-side adapter is what turns this into
    a signed ``SlashAttestation`` and submits it. This is the cross-language
    output the Task 3.5 conformance corpus pins (same stream -> same proposals)."""
    peer_id: str
    role: str
    reason: str                  # REASON_SUSTAINED_ANOMALY
    floor: float                 # reputation floor the host should pin the peer to
    score: float                 # combined calibrated anomaly score at the trip
    n_obs: int
    attributions: Dict[str, float] = field(default_factory=dict)  # the "why"

    def top_features(self, k: int = 3) -> List[Tuple[str, float]]:
        return sorted(self.attributions.items(), key=lambda kv: kv[1],
                      reverse=True)[:k]


class PeerRoleDetector:
    """Couples features + HST + HBOS + calibrators + the sustained-anomaly state
    machine for a single peer×role.

    Args:
        peer_id, role: the entity this detector models.
        seed:          PRNG seed for the HST (derived per-entity by the monitor).
        enter:         calibrated-score threshold that adds dwell pressure.
        dwell_target:  consecutive (leak-tolerant) exceedances before an alarm.
        leak:          dwell decremented by this when below ``enter`` (so brief
                       dips don't reset a genuine sustained anomaly, but a single
                       spike decays away).
        min_obs:       minimum observations before an alarm can fire.
        hst_weight:    blend weight for HST vs HBOS in the combined score.
    """

    def __init__(self, peer_id: str, role: str, seed: int = 0,
                 enter: float = 0.9, dwell_target: int = 8, leak: int = 2,
                 min_obs: int = 60, hst_weight: float = 0.5,
                 feature_window: int = 64, hst_window: int = 250,
                 hst_trees: int = 25, hst_height: int = 12,
                 hbos_bins: int = 20, hbos_window: int = 400,
                 hbos_refit_every: int = 50, hbos_warmup: int = 200,
                 calib_warmup: int = 50, calib_min_std: float = 0.10,
                 calib_k: float = 1.0):
        self.peer_id = peer_id
        self.role = role
        self.enter = float(enter)
        self.dwell_target = int(dwell_target)
        self.leak = int(leak)
        self.min_obs = int(min_obs)
        self.hst_weight = float(hst_weight)

        # Detectors via River/PyOD (SOW Task 3.2).
        self.hst = RiverHalfSpaceTrees(FEATURE_NAMES, n_trees=hst_trees,
                                       height=hst_height, window_size=hst_window,
                                       seed=seed)
        self.hbos = PyODHBOS(FEATURE_NAMES, n_bins=hbos_bins, window=hbos_window,
                             refit_every=hbos_refit_every, warmup=hbos_warmup)
        self.features = BehaviorFeatures(window=feature_window)
        self._cal_hst = StreamingCalibrator(warmup=calib_warmup, k=calib_k,
                                            min_std=calib_min_std)
        self._cal_hbos = StreamingCalibrator(warmup=calib_warmup, k=calib_k,
                                             min_std=calib_min_std)
        self._dwell = 0
        self._alarmed = False
        self._n = 0

    @property
    def warm(self) -> bool:
        return (self.hst.warm and self.hbos.warm
                and self._cal_hst.warm and self._cal_hbos.warm
                and self._n >= self.min_obs)

    @property
    def alarmed(self) -> bool:
        return self._alarmed

    def reset_alarm(self) -> None:
        """Clear the latched alarm (e.g. after a rehabilitate decision)."""
        self._alarmed = False
        self._dwell = 0

    def observe(self, event: AccessEvent) -> AnomalyDecision:
        """Fold one event in and return the current verdict.

        Strict evaluate-then-learn order at every layer: the event is scored
        against the model as it stands BEFORE being learned, so an attacker's
        own anomalous traffic cannot train the model to accept itself."""
        self.features.observe(event)
        vec = self.features.vector()

        # Score against the current model, then calibrate against the current
        # score distribution (evaluate), before learning anything (learn).
        hst_raw = self.hst.score_one(vec)
        hbos_raw = self.hbos.score_one(vec)
        hst_cal = self._cal_hst.calibrate(hst_raw)
        hbos_cal = self._cal_hbos.calibrate(hbos_raw)
        combined = self.hst_weight * hst_cal + (1.0 - self.hst_weight) * hbos_cal

        attribs = self.hbos.attributions(vec)

        # Sustained-anomaly state machine (only once warm).
        if self.warm:
            if combined >= self.enter:
                self._dwell = min(self.dwell_target, self._dwell + 1)
            else:
                self._dwell = max(0, self._dwell - self.leak)
            if self._dwell >= self.dwell_target:
                self._alarmed = True

        decision = AnomalyDecision(
            peer_id=self.peer_id, role=self.role, score=combined,
            alarmed=self._alarmed,
            pressure=(self._dwell / self.dwell_target if self.dwell_target else 0.0),
            n_obs=self._n, warm=self.warm,
            hst_score=hst_cal, hbos_score=hbos_cal, attributions=attribs)

        # Learn (update every layer) after scoring. Calibrators are fed a
        # detector's raw score only once that detector is warm, so the cold-
        # start sentinel (1.0 before the first window/warmup) does not pollute
        # the calibration distribution.
        if self.hst.warm:
            self._cal_hst.update(hst_raw)
        if self.hbos.warm:
            self._cal_hbos.update(hbos_raw)
        self.hst.learn_one(vec)
        self.hbos.learn_one(vec)
        self._n += 1
        return decision


class BehaviorMonitor:
    """The portable per-node behavioural-anomaly engine (the future ``.so``).

    A node feeds it the access events of *its own* peers; it routes each to a
    per-peer×role detector (created lazily, deterministically seeded) and, on the
    rising edge of a sustained alarm, emits a :class:`SlashProposal`. It is pure:
    deterministic, bounded-memory, no node/queue/identity/wire dependency and no
    I/O. The host-side adapter drains :meth:`poll_proposals` and decides what to
    do with them (submit a slash, or surface for a human).

    Args:
        base_seed:  combined with the entity key to seed each detector's HST, so
                    every node runs the same model for the same peer (the
                    determinism that makes a proposal admissible as evidence).
        slash_floor: reputation floor carried in each emitted proposal.
        reason:      reason string carried in each proposal.
        detector_kwargs: forwarded to every :class:`PeerRoleDetector`.
    """

    def __init__(self, base_seed: int = 0, slash_floor: float = 0.45,
                 reason: str = REASON_SUSTAINED_ANOMALY, **detector_kwargs):
        self.base_seed = int(base_seed)
        self.slash_floor = float(slash_floor)
        self.reason = str(reason)
        self._kwargs = detector_kwargs
        self._detectors: Dict[Tuple[str, str], PeerRoleDetector] = {}
        # Rising-edge bookkeeping so one sustained alarm yields one proposal.
        self._alarm_state: Dict[Tuple[str, str], bool] = {}
        self._pending: List[SlashProposal] = []

    def detector_for(self, peer_id: str, role: str) -> PeerRoleDetector:
        key = (str(peer_id), str(role))
        det = self._detectors.get(key)
        if det is None:
            det = PeerRoleDetector(
                peer_id=key[0], role=key[1],
                seed=_entity_seed(self.base_seed, key), **self._kwargs)
            self._detectors[key] = det
        return det

    def observe(self, peer_id: str, role: str,
                event: AccessEvent) -> AnomalyDecision:
        """Fold one peer event in and detect the rising edge of a sustained
        alarm, queuing a :class:`SlashProposal` for :meth:`poll_proposals`."""
        key = (str(peer_id), str(role))
        decision = self.detector_for(peer_id, role).observe(event)
        if decision.alarmed and not self._alarm_state.get(key, False):
            self._pending.append(SlashProposal(
                peer_id=key[0], role=key[1], reason=self.reason,
                floor=self.slash_floor, score=decision.score,
                n_obs=decision.n_obs, attributions=dict(decision.attributions)))
        self._alarm_state[key] = decision.alarmed
        return decision

    def poll_proposals(self) -> List[SlashProposal]:
        """Drain and return the proposals accumulated since the last poll (one
        per peer×role per rising edge). Pull model -- no callbacks into the host."""
        out = self._pending
        self._pending = []
        return out

    def reset_alarm(self, peer_id: str, role: str) -> None:
        """Clear a latched alarm so a future sustained anomaly can re-propose
        (e.g. after the host rehabilitates the peer)."""
        key = (str(peer_id), str(role))
        det = self._detectors.get(key)
        if det is not None:
            det.reset_alarm()
        self._alarm_state[key] = False

    def alarmed(self) -> List[AnomalyDecision]:
        """Snapshot of currently-alarmed entities (diagnostics / introspection)."""
        out = []
        for (pid, role), det in self._detectors.items():
            if det.alarmed:
                out.append(AnomalyDecision(
                    peer_id=pid, role=role, score=1.0, alarmed=True,
                    pressure=1.0, n_obs=det._n, warm=det.warm))
        return out

    @property
    def entities(self) -> List[Tuple[str, str]]:
        return list(self._detectors.keys())
