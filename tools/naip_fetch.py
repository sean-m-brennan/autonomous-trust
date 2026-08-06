# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Fetch a NAIP panorama tile for the DoD demo's detection prep.

Stretch Goal 2, Phase 1 (STRETCH_GOAL_2_DETECTION_PLAN.md section 4.1).
Downloads a centred 4 km x 4 km, 1 m/px aerial panorama from the USGS
National Map's NAIPImagery ImageServer, plus a sidecar JSON describing
the projection and per-pixel scale. Output is consumed by
``tools/detection_prep.py``.

Source: USGS NAIPImagery ImageServer ``exportImage`` REST endpoint.
Public-domain imagery (NAIP is a USDA product distributed by USGS).

Dependencies (provided by the ``autonomous_trust`` conda env --
see environment.yml; ``conda activate autonomous_trust``)::

    pyproj Pillow

Pillow is used only to verify the JPEG decodes after download; pyproj
converts the user-facing WGS84 centre to the UTM-16N bbox that the
ImageServer uses to return pixels at exactly the requested resolution.

Typical invocation::

    python3 -m tools.naip_fetch                       # defaults: Huntsville AO
    python3 -m tools.naip_fetch --force               # re-download even if cached
    python3 -m tools.naip_fetch --extent-m 2048       # half-size AO for fast iter

Output files (default)::

    examples/dod_mission/assets/video/naip_huntsville.jpg
    examples/dod_mission/assets/video/naip_huntsville.geo.json

Both are .gitignored; regenerate on a fresh checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# Defaults align with examples/dod_mission/scenario.py GROUND_MID / RQ86_ORBIT.
DEFAULT_CENTER_LAT = 34.724448
DEFAULT_CENTER_LON = -86.639802
DEFAULT_EXTENT_M = 4096
DEFAULT_RESOLUTION_M = 1.0
DEFAULT_OUTPUT_BASENAME = "naip_huntsville"

NAIP_EXPORT_URL = (
    "https://imagery.nationalmap.gov/arcgis/rest/services/"
    "USGSNAIPImagery/ImageServer/exportImage"
)

# USGSNAIPImagery ImageServer caps exportImage at 4000x4000 px per call;
# we tile larger requests into a grid that respects this.
MAX_TILE_PX = 4000

# UTM 16N covers ~-90 to -84 longitude. Huntsville (-86.64) is inside.
UTM_ZONE_16N_EPSG = 32616
WGS84_EPSG = 4326


@dataclass(frozen=True)
class FetchRequest:
    center_lat: float
    center_lon: float
    extent_m: int
    resolution_m: float

    @property
    def size_px(self) -> int:
        return int(round(self.extent_m / self.resolution_m))

    def cache_key(self) -> str:
        # Sidecar carries the same key; we use it for is-cached comparisons.
        payload = json.dumps({
            "center_lat": self.center_lat,
            "center_lon": self.center_lon,
            "extent_m": self.extent_m,
            "resolution_m": self.resolution_m,
            "url": NAIP_EXPORT_URL,
        }, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16]


def _utm_bbox(req: FetchRequest) -> dict:
    """WGS84 centre -> UTM-16N square bbox of ``extent_m`` width."""
    try:
        from pyproj import Transformer
    except ModuleNotFoundError as e:
        raise SystemExit(
            "pyproj is required: conda activate autonomous_trust"
        ) from e
    to_utm = Transformer.from_crs(WGS84_EPSG, UTM_ZONE_16N_EPSG,
                                  always_xy=True)
    cx, cy = to_utm.transform(req.center_lon, req.center_lat)
    half = req.extent_m / 2.0
    return {
        "epsg": UTM_ZONE_16N_EPSG,
        "xmin": cx - half, "ymin": cy - half,
        "xmax": cx + half, "ymax": cy + half,
        "center_utm_e": cx, "center_utm_n": cy,
    }


def _build_export_url(bbox: dict, size_w: int, size_h: int) -> str:
    params = {
        "bbox": f"{bbox['xmin']},{bbox['ymin']},{bbox['xmax']},{bbox['ymax']}",
        "bboxSR": bbox["epsg"],
        "imageSR": bbox["epsg"],
        "size": f"{size_w},{size_h}",
        "format": "jpg",
        "pixelType": "U8",
        "noData": "",
        "interpolation": "RSP_BilinearInterpolation",
        "f": "image",
    }
    return f"{NAIP_EXPORT_URL}?{urllib.parse.urlencode(params)}"


def _plan_tiles(size_px: int, max_tile: int = MAX_TILE_PX
                ) -> list[tuple[int, int]]:
    """Return per-tile widths (or heights) along one axis summing to size_px."""
    if size_px <= max_tile:
        return [(0, size_px)]
    n = (size_px + max_tile - 1) // max_tile
    base = size_px // n
    rem = size_px - base * n
    widths = [base + (1 if i < rem else 0) for i in range(n)]
    spans: list[tuple[int, int]] = []
    cursor = 0
    for w in widths:
        spans.append((cursor, w))
        cursor += w
    return spans


def _fetch_bytes(url: str, timeout: float = 120.0) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": "autonomous-trust-naip-fetch/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        raise SystemExit(
            f"USGS exportImage HTTP {e.code}: {e.reason}\n"
            f"URL: {url}"
        ) from e
    except urllib.error.URLError as e:
        raise SystemExit(f"USGS exportImage network error: {e.reason}") from e
    return body


def _open_jpeg(blob: bytes, expected_w: int, expected_h: int):
    try:
        from PIL import Image, UnidentifiedImageError
    except ModuleNotFoundError as e:
        raise SystemExit(
            "Pillow is required: conda activate autonomous_trust") from e
    try:
        img = Image.open(io.BytesIO(blob))
        img.load()
    except UnidentifiedImageError as e:
        snippet = blob[:200].decode("utf-8", errors="replace")
        raise SystemExit(
            f"USGS did not return a JPEG ({len(blob)} B); body starts:\n"
            f"  {snippet}"
        ) from e
    w, h = img.size
    if (w, h) != (expected_w, expected_h):
        raise SystemExit(
            f"Returned tile is {w}x{h}, expected {expected_w}x{expected_h}"
        )
    return img


def _fetch_tile(bbox: dict, size_w: int, size_h: int, *, quiet: bool):
    url = _build_export_url(bbox, size_w, size_h)
    if not quiet:
        print(f"[naip_fetch]   GET {size_w}x{size_h} "
              f"({bbox['xmin']:.0f},{bbox['ymin']:.0f} - "
              f"{bbox['xmax']:.0f},{bbox['ymax']:.0f})")
    return _open_jpeg(_fetch_bytes(url), size_w, size_h)


def _sidecar(req: FetchRequest, bbox: dict, size_px: int,
             jpeg_sha256: str) -> dict:
    return {
        "schema": "naip-fetch/v1",
        "panorama": {
            "size_px": [size_px, size_px],
            "extent_m": req.extent_m,
            "px_per_m": 1.0 / req.resolution_m,
            "resolution_m": req.resolution_m,
        },
        "center": {
            "lat": req.center_lat,
            "lon": req.center_lon,
        },
        "bbox": bbox,
        "source": {
            "name": "USGS NAIPImagery (USDA NAIP)",
            "endpoint": NAIP_EXPORT_URL,
            "licence": "public-domain (US federal product)",
        },
        "jpeg_sha256": jpeg_sha256,
        "cache_key": req.cache_key(),
    }


def _is_cached(req: FetchRequest, jpeg_path: Path, sidecar_path: Path) -> bool:
    if not jpeg_path.exists() or not sidecar_path.exists():
        return False
    try:
        sidecar = json.loads(sidecar_path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    return sidecar.get("cache_key") == req.cache_key()


def fetch(req: FetchRequest, jpeg_path: Path, sidecar_path: Path,
          *, force: bool = False, quiet: bool = False) -> dict:
    """Fetch the panorama if needed. Returns the sidecar dict."""
    if not force and _is_cached(req, jpeg_path, sidecar_path):
        if not quiet:
            print(f"[naip_fetch] cached: {jpeg_path} "
                  f"({jpeg_path.stat().st_size:,} B) — pass --force to refetch")
        return json.loads(sidecar_path.read_text())

    try:
        from PIL import Image
    except ModuleNotFoundError as e:
        raise SystemExit(
            "Pillow is required: conda activate autonomous_trust") from e

    bbox = _utm_bbox(req)
    size_px = req.size_px
    x_spans = _plan_tiles(size_px)
    y_spans = _plan_tiles(size_px)
    if not quiet:
        if len(x_spans) == 1 and len(y_spans) == 1:
            print(f"[naip_fetch] requesting {size_px}x{size_px} from USGS "
                  f"NAIPImagery (UTM-16N bbox {bbox['xmin']:.0f},"
                  f"{bbox['ymin']:.0f} - {bbox['xmax']:.0f},{bbox['ymax']:.0f})")
        else:
            print(f"[naip_fetch] requesting {size_px}x{size_px} via "
                  f"{len(x_spans)}x{len(y_spans)} tile grid "
                  f"(USGS max {MAX_TILE_PX}/side)")

    canvas = Image.new("RGB", (size_px, size_px))
    span_m = req.extent_m / size_px
    for ty, (y_off, h_tile) in enumerate(y_spans):
        for tx, (x_off, w_tile) in enumerate(x_spans):
            # Tile bbox in UTM. y_off counts from the *top* of the canvas
            # (north) so we flip when computing N.
            tile_bbox = {
                "epsg": bbox["epsg"],
                "xmin": bbox["xmin"] + x_off * span_m,
                "xmax": bbox["xmin"] + (x_off + w_tile) * span_m,
                "ymax": bbox["ymax"] - y_off * span_m,
                "ymin": bbox["ymax"] - (y_off + h_tile) * span_m,
            }
            tile_img = _fetch_tile(tile_bbox, w_tile, h_tile, quiet=quiet)
            canvas.paste(tile_img, (x_off, y_off))

    buf = io.BytesIO()
    canvas.save(buf, format="JPEG", quality=88, optimize=True)
    blob = buf.getvalue()
    if not quiet:
        print(f"[naip_fetch] encoded {len(blob):,} B JPEG "
              f"({size_px}x{size_px})")
    jpeg_sha = hashlib.sha256(blob).hexdigest()

    jpeg_path.parent.mkdir(parents=True, exist_ok=True)
    jpeg_path.write_bytes(blob)
    sidecar = _sidecar(req, bbox, size_px, jpeg_sha)
    sidecar_path.write_text(json.dumps(sidecar, indent=2) + "\n")

    if not quiet:
        print(f"[naip_fetch] wrote {jpeg_path}")
        print(f"[naip_fetch] wrote {sidecar_path}")
    return sidecar


def _arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--center-lat", type=float, default=DEFAULT_CENTER_LAT,
                   help=f"AO centre latitude (default {DEFAULT_CENTER_LAT})")
    p.add_argument("--center-lon", type=float, default=DEFAULT_CENTER_LON,
                   help=f"AO centre longitude (default {DEFAULT_CENTER_LON})")
    p.add_argument("--extent-m", type=int, default=DEFAULT_EXTENT_M,
                   help=f"AO side length in metres (default {DEFAULT_EXTENT_M})")
    p.add_argument("--resolution-m", type=float, default=DEFAULT_RESOLUTION_M,
                   help=f"Ground resolution per pixel in metres "
                        f"(default {DEFAULT_RESOLUTION_M})")
    p.add_argument("--output-dir", type=Path,
                   default=Path("examples/dod_mission/assets/video"),
                   help="Directory for the JPEG + sidecar")
    p.add_argument("--basename", default=DEFAULT_OUTPUT_BASENAME,
                   help="Output filename stem (default: %(default)s)")
    p.add_argument("--force", action="store_true",
                   help="Re-download even if cached")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress progress output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _arg_parser().parse_args(argv)
    req = FetchRequest(
        center_lat=args.center_lat,
        center_lon=args.center_lon,
        extent_m=args.extent_m,
        resolution_m=args.resolution_m,
    )
    output_dir = args.output_dir
    jpeg_path = output_dir / f"{args.basename}.jpg"
    sidecar_path = output_dir / f"{args.basename}.geo.json"
    fetch(req, jpeg_path, sidecar_path,
          force=args.force, quiet=args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
