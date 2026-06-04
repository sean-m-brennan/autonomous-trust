"""
Cross-source validation task for the multi-agency disaster response demo.

This is the mechanism by which the network detects the compromised
NOAA sensor.  FEMA fusion nodes compare temperature readings from
multiple NOAA stations.  When one station's readings diverge beyond
a threshold, the fusion node flags it as anomalous and reduces the
transaction score for that peer.

The validation is automatic and continuous — it runs as part of the
fusion process, not as a separate human-initiated action.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading


@dataclass
class ValidationResult:
    """Result of cross-source validation for a single reading.

    Attributes:
        peer_name:     Peer whose reading was validated
        data_type:     What type of data
        timestamp:     When the reading was produced
        is_anomalous:  True if the reading deviates beyond threshold
        deviation:     How far the reading deviates from consensus
        consensus:     Median value from other sources
        threshold:     The deviation threshold that was used
    """
    peer_name: str
    data_type: str
    timestamp: timedelta
    is_anomalous: bool
    deviation: float
    consensus: float
    threshold: float

    def to_dict(self) -> dict:
        return {
            "peer": self.peer_name,
            "type": self.data_type,
            "t": self.timestamp.total_seconds(),
            "anomalous": self.is_anomalous,
            "deviation": round(self.deviation, 3),
            "consensus": round(self.consensus, 3),
            "threshold": self.threshold,
        }


class CrossSourceValidator:
    """Validates readings from multiple sources of the same data type.

    Consensus is the median of ALL current sources (including the reading
    under test); a reading is flagged when it deviates from that consensus
    beyond ``threshold``.

    Using the median of *all* sources — rather than the median of the
    *others* — is what makes a single liar identifiable without smearing
    the blame onto the honest majority. With "median of others" and only
    two other sources, the consensus is their *average*, which a lone
    outlier drags halfway toward itself: every honest source then reads as
    deviating by ~half the gap and the validator flags the whole bucket
    (the MQ-800 false-positive that also condemned both honest RQ-86s when
    the swarm had moved out of range, leaving just the recon pair + the
    rogue). The median of all sources is robust to a *minority* of liars:
    with 2 honest + 1 rogue it equals the honest cluster, so only the rogue
    deviates. ``min_sources`` (default 3) keeps the two-source case — where
    no median can distinguish liar from honest — from validating at all.

    Args:
        data_type:       Which reading type to validate (e.g. "temperature")
        threshold:       Maximum acceptable deviation from consensus
        min_sources:     Minimum sources needed for validation (default 3)
        window_sec:      Time window for collecting readings (default 15s)
    """

    def __init__(self, data_type: str, threshold: float,
                 min_sources: int = 3, window_sec: float = 15.0):
        self.data_type = data_type
        self.threshold = threshold
        self.min_sources = min_sources
        self.window_sec = window_sec
        # Buffer key is (peer_name, world_uid) so two peers reporting
        # different targets of the same data_type don't get smeared
        # into one consensus bucket. world_uid defaults to "_default"
        # for readings without that metadata (e.g. weather sensors),
        # preserving prior per-peer-only behaviour.
        self._buffer: dict[tuple[str, str], list[Reading]] = {}

    @staticmethod
    def _bucket_key(reading: Reading) -> tuple[str, str]:
        return (reading.peer_name,
                str(reading.metadata.get("world_uid", "_default")))

    def submit(self, reading: Reading) -> Optional[ValidationResult]:
        """Submit a reading for validation.

        Returns a ValidationResult if enough sources are available
        to perform cross-validation, otherwise None.
        """
        if reading.data_type != self.data_type:
            return None

        # Add to buffer (keyed by (peer, world_uid))
        key = self._bucket_key(reading)
        self._buffer.setdefault(key, []).append(reading)

        # Trim old readings
        cutoff = reading.timestamp - timedelta(seconds=self.window_sec)
        for k in self._buffer:
            self._buffer[k] = [
                r for r in self._buffer[k]
                if r.timestamp >= cutoff
            ]

        # Cross-validation only compares within the same target bucket
        # (same world_uid) — distinct targets get distinct consensus.
        target_uid = key[1]
        active_sources = {
            k[0]: readings[-1]                     # peer_name -> latest
            for k, readings in self._buffer.items()
            if readings and k[1] == target_uid
        }
        if len(active_sources) < self.min_sources:
            return None

        # Consensus = median of ALL current sources (including this reading).
        # The median is robust to a minority of liars, so the honest cluster
        # sets the consensus and only a true outlier deviates from it — see
        # the class docstring for why "median of others" was wrong here.
        all_values = sorted(r.value for r in active_sources.values())
        mid = len(all_values) // 2
        if len(all_values) % 2 == 0:
            consensus = (all_values[mid - 1] + all_values[mid]) / 2
        else:
            consensus = all_values[mid]

        deviation = abs(reading.value - consensus)
        is_anomalous = deviation > self.threshold

        return ValidationResult(
            peer_name=reading.peer_name,
            data_type=self.data_type,
            timestamp=reading.timestamp,
            is_anomalous=is_anomalous,
            deviation=deviation,
            consensus=consensus,
            threshold=self.threshold,
        )


# Default validators for the multi-agency demo. The coordinator
# applies each one to incoming readings whose data_type matches; the
# rest stay no-ops. Bundled in ALL_VALIDATORS so the coordinator can
# install the whole set with one import.
TEMPERATURE_VALIDATOR = CrossSourceValidator(
    data_type="temperature",
    threshold=5.0,      # Flag if >5C from consensus
    min_sources=3,
    window_sec=15.0,
)

# Wind speed (m/s) — the NOAA stations' wind sensors. min_sources=2
# because the baseline scenario has only 3 NOAA peers and we need to
# detect divergence even when noaa-3 is the rogue.
WIND_VALIDATOR = CrossSourceValidator(
    data_type="wind",
    threshold=4.0,      # m/s deviation from consensus
    min_sources=2,
    window_sec=15.0,
)

# Pressure (hPa) — secondary weather signal; smaller thresholds since
# pressure varies slowly and divergence is meaningful at lower deltas.
PRESSURE_VALIDATOR = CrossSourceValidator(
    data_type="pressure",
    threshold=8.0,
    min_sources=2,
    window_sec=15.0,
)

# Seismic magnitude (USGS) — paired sensors, so min_sources=2.
MAGNITUDE_VALIDATOR = CrossSourceValidator(
    data_type="magnitude",
    threshold=0.6,      # Richter-scale-ish; same-event readings should agree
    min_sources=2,
    window_sec=15.0,
)

# Air-quality index (EPA late-joiner) — single source most of the run
# (no peer to cross-check against). min_sources=1 short-circuits the
# consensus check and the validator effectively never fires; kept for
# symmetry so the dispatch loop has no special cases.
AQI_VALIDATOR = CrossSourceValidator(
    data_type="aqi",
    threshold=50.0,
    min_sources=1,
    window_sec=15.0,
)


ALL_VALIDATORS = [
    TEMPERATURE_VALIDATOR,
    WIND_VALIDATOR,
    PRESSURE_VALIDATOR,
    MAGNITUDE_VALIDATOR,
    AQI_VALIDATOR,
]
