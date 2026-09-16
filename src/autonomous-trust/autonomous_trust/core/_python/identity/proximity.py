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

"""Private-proximity testing (Phase 2) — the Python twin of identity/proximity.c.

Two CONNECTED peers learn a coarse distance BAND (near / mid / far) without
revealing exact coordinates. Each side quantizes its position to grid cells at
two resolutions (~1 km, ~5 km) with overlapping offset grids, derives a keyed
BLAKE2b tag per (resolution, grid) using the pairwise box secret plus a per-probe
salt, and the two exchange and intersect tag sets. The finest resolution with any
match is the band.

The tag derivation is a CROSS-LANGUAGE CONTRACT: the bytes hashed here MUST match
identity/proximity.c exactly, or a mixed C/Python cohort never matches. The
pinned vector in the module self-test (and test_proximity.py) is byte-identical to
the C proximity_test vector.
"""
import math
import struct
import hashlib
from enum import IntEnum

# Earth radius (metres), spherical — a coarse band needs no ellipsoid.
EARTH_R = 6371000.0
# Domain-separation prefix; mirrors AT_PROX_DOMAIN[] = "at-proximity-v1" in C,
# whose sizeof INCLUDES the terminating NUL, so it is hashed too.
DOMAIN = b"at-proximity-v1\x00"

NRES = 2
NGRID = 3
NTAGS = NRES * NGRID
TAG_LEN = 16
SALT_LEN = 16
# Cell edge (metres) per resolution, finest first: ~1 km, ~5 km.
CELL_M = [1000.0, 5000.0]


class ProxBand(IntEnum):
    UNKNOWN = 0
    NEAR = 1
    MID = 2
    FAR = 3


def _project(lat_deg, lon_deg):
    """Equirectangular projection with a cos(lat) east-west correction — the
    same formula as C _project()."""
    lat_rad = math.radians(lat_deg)
    lon_rad = math.radians(lon_deg)
    return EARTH_R * lon_rad * math.cos(lat_rad), EARTH_R * lat_rad


def compute_tags(lat_deg, lon_deg, key, salt):
    """This node's tag set for (lat, lon) under `key` (32-byte pairwise secret)
    and `salt` (SALT_LEN bytes). Returns a list of NTAGS raw 16-byte tags,
    indexed tags[res * NGRID + grid]. Raises ValueError on out-of-range coords."""
    if not (-90.0 <= lat_deg <= 90.0):
        raise ValueError("latitude out of range")
    if not (-180.0 <= lon_deg <= 180.0):
        raise ValueError("longitude out of range")
    x, y = _project(lat_deg, lon_deg)
    tags = []
    for r in range(NRES):
        cell = CELL_M[r]
        for g in range(NGRID):
            off = cell * g / NGRID
            cx = math.floor((x + off) / cell)
            cy = math.floor((y + off) / cell)
            msg = (DOMAIN + salt + bytes([r, g])
                   + struct.pack('<q', cx) + struct.pack('<q', cy))
            tags.append(hashlib.blake2b(msg, digest_size=TAG_LEN, key=key).digest())
    return tags


def band(mine, theirs):
    """Decide the band by intersecting two tag sets. Finest resolution with any
    (res, grid) match wins; no match -> FAR."""
    for r in range(NRES):
        for g in range(NGRID):
            i = r * NGRID + g
            if mine[i] == theirs[i]:
                return ProxBand.NEAR if r == 0 else ProxBand.MID
    return ProxBand.FAR


def tags_to_hex(tags):
    """Serialize a tag set to a list of lowercase-hex strings (the wire form)."""
    return [t.hex() for t in tags]


def tags_from_hex(arr):
    """Parse a tag set from a list of hex strings, or None if malformed."""
    if not isinstance(arr, (list, tuple)) or len(arr) != NTAGS:
        return None
    try:
        out = [bytes.fromhex(s) for s in arr]
    except (ValueError, TypeError):
        return None
    if any(len(t) != TAG_LEN for t in out):
        return None
    return out


def derive_key(their_public, our_private):
    """The pairwise proximity key (crypto_box_beforenm) from our X25519 private
    key and the peer's public key. `their_public`/`our_private` are PyNaCl
    PublicKey/PrivateKey. Symmetric with the C side."""
    from nacl.public import Box
    # Box(sk, pk).shared_key() is crypto_box_beforenm(pk, sk).
    return Box(our_private, their_public).shared_key()


if __name__ == "__main__":  # cross-language pinned-vector self-test
    key = bytes([0x42]) * 32
    salt = bytes([0x01]) * 16
    got = tags_to_hex(compute_tags(37.7749, -122.4194, key, salt))
    # Byte-identical to the C proximity_test / prox_vec vector.
    pinned = [
        "620275198e3b2ef250a082dddd6a3314",
        "284ac192269d7c9be7582f1727cfac4d",
        "d6882704c29779769683969ece15ca05",
        "c52ccfcc3c4f595c3a9fcc9bb6e4e2bf",
        "ccea7da14a5f4a94d467cb2e24f97569",
        "91d7d604906326ffffc57cf89eb89fed",
    ]
    assert got == pinned, f"tag vector drift:\n got={got}\n exp={pinned}"
    print("proximity.py: pinned C-parity vector OK")
