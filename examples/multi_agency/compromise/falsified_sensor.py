"""
Compromised NOAA sensor behavior for the civilian demo.

noaa-sensor-3 at Topsail Beach is compromised at T+4:00 (Phase 4).
Its temperature readings diverge from the other two NOAA sensors.

Supports two modes (selectable at runtime):
  - GradualDrift: Temperature slowly drifts upward (+0.5C/min),
    taking ~60s for detection.  More realistic.
  - AbruptDeviation: Temperature instantly jumps +15C.
    More dramatic — easier for audience to see the divergence.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from autonomous_trust.evaluation.redteam.compromise import GradualDrift, AbruptDeviation
from examples.multi_agency.generators.weather import TemperatureGenerator


def create_compromised_temperature(
    peer_name: str = "noaa-sensor-3",
    activate_at: timedelta = timedelta(minutes=4),
    mode: str = "abrupt",
    seed: Optional[int] = None,
) -> GradualDrift | AbruptDeviation:
    """Create a compromised temperature generator.

    Args:
        peer_name:   Peer to bind to
        activate_at: When compromise begins (scenario-relative)
        mode:        "gradual" or "abrupt"
        seed:        Random seed for reproducibility

    Returns:
        A CompromiseBehavior wrapping a TemperatureGenerator
    """
    honest = TemperatureGenerator(peer_name, seed=seed)

    if mode == "gradual":
        return GradualDrift(
            honest_generator=honest,
            activate_at=activate_at,
            drift_rate=0.5,      # +0.5C per minute
            max_drift=20.0,      # cap at +20C
            direction=1.0,       # upward drift
        )
    else:
        return AbruptDeviation(
            honest_generator=honest,
            activate_at=activate_at,
            offset=15.0,         # +15C instant jump
        )
