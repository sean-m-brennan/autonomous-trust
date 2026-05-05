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

"""FEMA data-fusion service.

Consumes multiple upstream streams (weather, seismic, air-quality) and
emits a summarized situational picture at a slower cadence. Listeners
see a single stream with trust-weighted means per data type.

The fusion process does NOT itself validate; it weights incoming
readings by the upstream peer's current reputation (supplied by the
demo wiring via set_reputation_lookup). Low-reputation peers have
diminishing influence on the fused output -- the 'soft exclusion'
effect that makes the compromise visible in downstream feeds before
the reputation system hard-cuts the rogue peer.
"""

from __future__ import annotations

import statistics
from collections import defaultdict, deque
from datetime import timedelta
from functools import partial
from typing import Callable, Optional

from autonomous_trust.core import ProcMeta

from ..data.reading import Reading
from .base import EnvDataProcess


# Reputation lookup signature: peer_name -> score in [0, 1]. If unset,
# everyone is weighted equally (1.0).
ReputationLookup = Callable[[str], float]

_FUSION_WINDOW = 30          # recent readings per (peer, type)
_FUSION_EMIT_CADENCE = 5.0   # sec between fused outputs (slower than sources)


class DataFusionProcess(EnvDataProcess, metaclass=ProcMeta,
                        proc_name='data-fusion',
                        description='Multi-agency fused environmental picture',
                        cfg_name='data-fusion'):
    capability_name = 'data_fusion'

    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        # partial(...) instead of `lambda: deque(maxlen=_FUSION_WINDOW)`
        # because the AT framework pickles the Process instance across
        # the multiprocessing.pool fork boundary, and a lambda factory
        # crashes every fema-fusion worker with `Can't get local object`
        # at startup. partial is picklable; lambdas in __init__ are not.
        self._inbound: dict[tuple[str, str], deque] = defaultdict(
            partial(deque, maxlen=_FUSION_WINDOW))
        self._reputation: Optional[ReputationLookup] = None
        self._last_emit: float = -_FUSION_EMIT_CADENCE

    # --- Late-bound peer reputation lookup from demo wiring ---

    def set_reputation_lookup(self, lookup: ReputationLookup):
        self._reputation = lookup

    def _peer_weight(self, peer_name: str) -> float:
        if self._reputation is None:
            return 1.0
        try:
            return max(0.0, min(1.0, float(self._reputation(peer_name))))
        except Exception:
            return 1.0

    # --- Consumer-side hook: call for every received Reading ---

    def ingest(self, reading: Reading):
        key = (reading.peer_name, reading.data_type)
        self._inbound[key].append(reading.value)

    # --- Fuse + emit ---

    def _fuse(self, data_type: str) -> Optional[float]:
        """Trust-weighted mean across peers for this data type."""
        num = 0.0
        den = 0.0
        for (peer, t), window in self._inbound.items():
            if t != data_type or not window:
                continue
            w = self._peer_weight(peer)
            if w <= 0.0:
                continue
            # Use the window mean so momentary noise doesn't dominate.
            val = statistics.fmean(window)
            num += w * val
            den += w
        if den == 0.0:
            return None
        return num / den

    def tick_once(self, elapsed: timedelta) -> Optional[dict]:
        """Emit a fused snapshot at the fusion cadence."""
        t_sec = elapsed.total_seconds()
        if t_sec - self._last_emit < _FUSION_EMIT_CADENCE:
            return None
        self._last_emit = t_sec

        fused: dict[str, float] = {}
        for dtype in {t for _, t in self._inbound.keys()}:
            v = self._fuse(dtype)
            if v is not None:
                fused[dtype] = round(v, 4)
        if not fused:
            return None

        # Fold everything into one synthetic Reading carrying the fused
        # dict in metadata. Callers can consume per-dtype via metadata.
        peer = self._env_cfg.peer_name if self._env_cfg else "fusion"
        reading = Reading(
            timestamp=elapsed,
            peer_name=peer,
            data_type="fused_picture",
            value=float(len(fused)),
            unit="count",
            quality=1.0,
            metadata={"fused": fused, "source_peer_count": sum(
                1 for _, t in self._inbound.keys()
                if t in fused)},
        )
        return reading.to_dict()

    # Override acquire() to emit fused snapshots instead of a generator.
    def acquire(self):
        if not self.active:
            return None
        # Reuse the same scenario-relative clock as base EnvDataProcess.
        from datetime import datetime
        if self._start_wall is None:
            self.set_start_time()
        elapsed = datetime.utcnow() - self._start_wall
        return self.tick_once(elapsed)
