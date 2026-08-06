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

"""Space link physics for asteroid-belt scale simulation.

Provides free-space path loss, light-delay calculation, and sun
occultation line-of-sight checks.  All functions are pure (no side
effects) and operate in SI units unless noted.
"""

import math

from autonomous_trust.services.peer.position import Position

# Physical constants
C_M_S = 299_792_458.0          # Speed of light (m/s)
AU_M = 149_597_870_700.0       # Astronomical unit (m)
SUN_RADIUS_M = 696_340_000.0   # Solar radius (m)


def light_delay_s(distance_m: float) -> float:
    """One-way light propagation time in seconds."""
    if distance_m <= 0:
        return 0.0
    return distance_m / C_M_S


def free_space_path_loss_db(distance_m: float, freq_hz: float) -> float:
    """Free-space path loss in dB.

    FSPL = 20*log10(d) + 20*log10(f) + 20*log10(4*pi/c)
    The constant 20*log10(4*pi/c) ≈ -147.55 dB.
    """
    if distance_m <= 0 or freq_hz <= 0:
        return 0.0
    return (20.0 * math.log10(distance_m)
            + 20.0 * math.log10(freq_hz)
            - 147.55)


def sun_occluded(pos_a: Position, pos_b: Position, sun_pos: Position,
                 sun_radius_m: float = SUN_RADIUS_M) -> bool:
    """Check if the line segment A->B is occluded by the Sun.

    Projects the Sun's center onto line AB and checks if the closest
    point on the segment is within the Sun's radius.

    Uses easting/northing as 2D heliocentric x/y coordinates.
    """
    # Vector AB
    ab_x = pos_b.easting - pos_a.easting
    ab_y = pos_b.northing - pos_a.northing
    ab_sq = ab_x * ab_x + ab_y * ab_y
    if ab_sq == 0:
        return False  # A and B are coincident

    # Vector A->Sun
    as_x = sun_pos.easting - pos_a.easting
    as_y = sun_pos.northing - pos_a.northing

    # Parametric projection of sun onto line AB: t in [0, 1] means
    # closest point is on the segment
    t = (as_x * ab_x + as_y * ab_y) / ab_sq
    t = max(0.0, min(1.0, t))

    # Closest point on segment to sun center
    closest_x = pos_a.easting + t * ab_x
    closest_y = pos_a.northing + t * ab_y

    # Distance from closest point to sun center
    dx = closest_x - sun_pos.easting
    dy = closest_y - sun_pos.northing
    dist_sq = dx * dx + dy * dy

    return dist_sq < sun_radius_m * sun_radius_m
