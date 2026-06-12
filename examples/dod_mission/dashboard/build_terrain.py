"""Offline DEM builder for the DoD-mission isometric Tactical Map.

The isometric view (``target_position_map.py`` iso mode) drapes assets over a
terrain surface. That surface comes from a small, pre-baked elevation grid
clipped to the Madison County, AL area of operations and committed alongside
this module as ``terrain_madison.npy`` (+ ``terrain_madison.json`` metadata).

This script is the *one-time* tool that produces those artifacts. It is NOT
imported by the dashboard at runtime — the demo loads only the bundled ``.npy``
(see :func:`load_terrain`), so it never touches the network.

Source: AWS "Terrain Tiles" open dataset, ``skadi`` endpoint, which serves raw
SRTM ``.hgt`` tiles gzipped — decodable with the standard library + numpy only
(no GDAL / rasterio / API key). The AOI sits inside tile ``N34W087``.

    https://registry.opendata.aws/terrain-tiles/
    https://s3.amazonaws.com/elevation-tiles-prod/skadi/N34/N34W087.hgt.gz

Regenerate (requires the firewall open to ``s3.amazonaws.com:443``)::

    python -m examples.dod_mission.dashboard.build_terrain

Tune the AOI / output resolution via the constants below, then re-run.
"""

from __future__ import annotations

import gzip
import json
import math
import os
import urllib.request
from typing import Optional

import numpy as np


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

# SRTM tile covering the AOI. Tile "N34W087" spans lat [34, 35), lon [-87, -86).
_TILE = "N34W087"
_SKADI_URL = (
    "https://s3.amazonaws.com/elevation-tiles-prod/skadi/"
    f"{_TILE[:3]}/{_TILE}.hgt.gz"
)

# Area of operations bounding box (decimal degrees). Chosen to comfortably
# contain the scenario landmarks (squad insertion 34.7065/-86.6337, objective
# 34.7235/-86.6379, exfil 34.6996/-86.6686) with margin so assets near the
# edges still sit over terrain. Mirror these in target_position_map if the AOI
# moves.
AOI_SOUTH = 34.66
AOI_NORTH = 34.77
AOI_WEST = -86.70
AOI_EAST = -86.57

# Output grid resolution (samples per side after downsampling). ~150 keeps the
# Plotly Surface mesh light (~22k vertices) while preserving the local relief.
OUT_SIZE = 150

# SRTM void sentinel.
_VOID = -32768

_HERE = os.path.dirname(os.path.abspath(__file__))
NPY_PATH = os.path.join(_HERE, "terrain_madison.npy")
JSON_PATH = os.path.join(_HERE, "terrain_madison.json")


# ----------------------------------------------------------------------
# Fetch + parse
# ----------------------------------------------------------------------

def _download_hgt(url: str = _SKADI_URL) -> np.ndarray:
    """Download + gunzip an SRTM .hgt tile into a square int elevation grid.

    SRTM .hgt is headerless, big-endian int16, row-major from the NW corner.
    Tiles are 3601x3601 (SRTM1, 1") or 1201x1201 (SRTM3, 3"); the side length
    is inferred from the payload size.
    """
    with urllib.request.urlopen(url, timeout=120) as resp:
        raw = gzip.decompress(resp.read())
    arr = np.frombuffer(raw, dtype=">i2").astype(np.int32)
    side = int(round(math.sqrt(arr.size)))
    if side * side != arr.size:
        raise ValueError(
            f"{url}: {arr.size} samples is not a perfect square (corrupt tile?)")
    return arr.reshape((side, side))


def _fill_voids(grid: np.ndarray) -> np.ndarray:
    """Replace SRTM void cells with the grid's mean of valid cells.

    The AOI is inland Alabama with no expected voids, so a flat fill is
    sufficient; we keep it rather than failing if a stray void appears.
    """
    valid = grid != _VOID
    if valid.all():
        return grid
    fill = int(round(grid[valid].mean())) if valid.any() else 0
    out = grid.copy()
    out[~valid] = fill
    return out


def _clip_and_downsample(grid: np.ndarray) -> tuple[np.ndarray, dict]:
    """Clip the full tile to the AOI bbox and downsample to OUT_SIZE per side.

    Tile geometry: ``side`` samples span exactly 1 degree per axis. Row 0 is
    the NORTH edge (lat = tile_north), so latitude decreases with row index;
    column 0 is the WEST edge.
    """
    side = grid.shape[0]
    # Integer tile corner from the tile name (N34W087 -> south=34, west=-87).
    tile_south = int(_TILE[1:3])
    tile_west = -int(_TILE[4:7])
    tile_north = tile_south + 1
    step = 1.0 / (side - 1)  # degrees per sample

    # Row index increases southward from the north edge.
    row_lo = int(math.floor((tile_north - AOI_NORTH) / step))
    row_hi = int(math.ceil((tile_north - AOI_SOUTH) / step))
    col_lo = int(math.floor((AOI_WEST - tile_west) / step))
    col_hi = int(math.ceil((AOI_EAST - tile_west) / step))
    row_lo, row_hi = max(0, row_lo), min(side, row_hi + 1)
    col_lo, col_hi = max(0, col_lo), min(side, col_hi + 1)

    sub = grid[row_lo:row_hi, col_lo:col_hi]

    # Exact lat/lon bounds of the clipped (pre-downsample) window.
    north = tile_north - row_lo * step
    south = tile_north - (row_hi - 1) * step
    west = tile_west + col_lo * step
    east = tile_west + (col_hi - 1) * step

    # Downsample by index selection (cheap, adequate for a presentation
    # surface). Flip rows so output row 0 is the SOUTH edge -> increasing
    # latitude with row index, which the panel maps to +north (ENU Y).
    ri = np.linspace(0, sub.shape[0] - 1, OUT_SIZE).round().astype(int)
    ci = np.linspace(0, sub.shape[1] - 1, OUT_SIZE).round().astype(int)
    out = sub[np.ix_(ri, ci)][::-1, :].astype(np.float32)

    meta = {
        "tile": _TILE,
        "south": south, "north": north, "west": west, "east": east,
        "rows": OUT_SIZE, "cols": OUT_SIZE,
        "row0_is_south": True,
        "source": _SKADI_URL,
        "min_m": float(out.min()), "max_m": float(out.max()),
    }
    return out, meta


# ----------------------------------------------------------------------
# Runtime loader (used by the panel) + builder entry point
# ----------------------------------------------------------------------

def load_terrain() -> Optional[tuple[np.ndarray, dict]]:
    """Load the bundled terrain grid + metadata, or None if not built yet.

    Returns ``(grid, meta)`` where ``grid`` is a float32 (rows, cols) array of
    elevations in metres (row 0 = south, col 0 = west) and ``meta`` carries the
    lat/lon bounds. The panel falls back to a flat plane when this is None.
    """
    if not (os.path.exists(NPY_PATH) and os.path.exists(JSON_PATH)):
        return None
    grid = np.load(NPY_PATH)
    with open(JSON_PATH) as f:
        meta = json.load(f)
    return grid, meta


def main() -> None:
    print(f"Fetching {_SKADI_URL} ...")
    tile = _download_hgt()
    print(f"  tile shape {tile.shape}, range "
          f"{tile.min()}..{tile.max()} m")
    tile = _fill_voids(tile)
    grid, meta = _clip_and_downsample(tile)
    np.save(NPY_PATH, grid)
    with open(JSON_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"  clipped to AOI {AOI_SOUTH}..{AOI_NORTH} N, "
          f"{AOI_WEST}..{AOI_EAST} E")
    print(f"  wrote {NPY_PATH} ({grid.shape}, "
          f"{meta['min_m']:.0f}..{meta['max_m']:.0f} m)")
    print(f"  wrote {JSON_PATH}")


if __name__ == "__main__":
    main()
