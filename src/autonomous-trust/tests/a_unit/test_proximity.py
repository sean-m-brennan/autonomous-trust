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

"""Private-proximity grid-tag + band contract (Phase 2).

Pins the tag vector the C twin (identity/proximity.c, test/proximity_test.c)
must match: the tags are byte-identical across runtimes, or a mixed C/Python
cohort's probes never match. The PINNED tags below equal the C prox_vec output
for key=0x42*32, salt=0x01*16, (37.7749, -122.4194).
"""
import math

from autonomous_trust.core._python.identity import proximity as p

KEY = bytes([0x42]) * 32
SALT = bytes([0x01]) * 16

# Byte-identical to the C proximity_test / prox_vec vector.
PINNED = [
    "620275198e3b2ef250a082dddd6a3314",
    "284ac192269d7c9be7582f1727cfac4d",
    "d6882704c29779769683969ece15ca05",
    "c52ccfcc3c4f595c3a9fcc9bb6e4e2bf",
    "ccea7da14a5f4a94d467cb2e24f97569",
    "91d7d604906326ffffc57cf89eb89fed",
]


def _lat_shift(lat_deg, dy_m):
    return math.degrees(math.radians(lat_deg) + dy_m / proximity_R())


def proximity_R():
    return p.EARTH_R


def test_tag_vector_matches_c_twin():
    got = p.tags_to_hex(p.compute_tags(37.7749, -122.4194, KEY, SALT))
    assert got == PINNED


def test_identical_position_is_near():
    a = p.compute_tags(37.7749, -122.4194, KEY, SALT)
    b = p.compute_tags(37.7749, -122.4194, KEY, SALT)
    assert p.band(a, b) == p.ProxBand.NEAR


def test_two_km_is_mid():
    a = p.compute_tags(1.0, 1.0, KEY, SALT)
    b = p.compute_tags(_lat_shift(1.0, 2000.0), 1.0, KEY, SALT)
    assert p.band(a, b) == p.ProxBand.MID


def test_twenty_km_is_far():
    a = p.compute_tags(1.0, 1.0, KEY, SALT)
    b = p.compute_tags(_lat_shift(1.0, 20000.0), 1.0, KEY, SALT)
    assert p.band(a, b) == p.ProxBand.FAR


def test_no_shared_key_no_match():
    a = p.compute_tags(10.0, 10.0, bytes([1]) * 32, SALT)
    b = p.compute_tags(10.0, 10.0, bytes([2]) * 32, SALT)
    assert p.band(a, b) == p.ProxBand.FAR


def test_hex_round_trip():
    a = p.compute_tags(48.85, 2.35, KEY, SALT)
    back = p.tags_from_hex(p.tags_to_hex(a))
    assert back == a
    assert p.tags_from_hex(["00"]) is None


def test_out_of_range_rejected():
    import pytest
    with pytest.raises(ValueError):
        p.compute_tags(91.0, 0.0, KEY, SALT)
    with pytest.raises(ValueError):
        p.compute_tags(0.0, 181.0, KEY, SALT)
