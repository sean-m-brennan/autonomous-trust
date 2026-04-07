"""
Cross-source validation task for the civilian disaster response demo.

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

    Compares each source against the median of all other sources.
    If a source deviates beyond `threshold`, it is flagged as anomalous.

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
        self._buffer: dict[str, list[Reading]] = {}

    def submit(self, reading: Reading) -> Optional[ValidationResult]:
        """Submit a reading for validation.

        Returns a ValidationResult if enough sources are available
        to perform cross-validation, otherwise None.
        """
        if reading.data_type != self.data_type:
            return None

        # Add to buffer
        if reading.peer_name not in self._buffer:
            self._buffer[reading.peer_name] = []
        self._buffer[reading.peer_name].append(reading)

        # Trim old readings
        cutoff = reading.timestamp - timedelta(seconds=self.window_sec)
        for peer in self._buffer:
            self._buffer[peer] = [
                r for r in self._buffer[peer]
                if r.timestamp >= cutoff
            ]

        # Need enough sources
        active_sources = {
            peer: readings[-1]
            for peer, readings in self._buffer.items()
            if readings
        }
        if len(active_sources) < self.min_sources:
            return None

        # Compute consensus (median of other sources)
        values = {peer: r.value for peer, r in active_sources.items()}
        other_values = sorted(
            v for p, v in values.items() if p != reading.peer_name
        )
        if not other_values:
            return None

        # Median
        mid = len(other_values) // 2
        if len(other_values) % 2 == 0:
            consensus = (other_values[mid - 1] + other_values[mid]) / 2
        else:
            consensus = other_values[mid]

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


# Default validators for the civilian demo
TEMPERATURE_VALIDATOR = CrossSourceValidator(
    data_type="temperature",
    threshold=5.0,      # Flag if >5C from consensus
    min_sources=3,
    window_sec=15.0,
)
