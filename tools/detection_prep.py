# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Offline detection catalogue builder for the DoD demo.

Stretch Goal 2, Phase 1 (STRETCH_GOAL_2_DETECTION_PLAN.md sections 4.2-4.4).

Three passes:
  A. YOLOv8n-OBB sliding-window inference over the NAIP panorama.
  B. Scenario-overlay injection from ``overlay.json`` at confidence 1.0.
  C. 128x96 JPEG crops baked out per detection (with margin).

Output::

    examples/dod_mission/assets/detections/catalogue.json
    examples/dod_mission/assets/detections/crops/<world_uid>.jpg

Both are gitignored; regenerate after ``tools/naip_fetch.py``.

Dependencies (provided by the ``autonomous_trust`` conda env --
see environment.yml; ``conda activate autonomous_trust``)::

    ultralytics Pillow numpy pyproj

ultralytics pulls torch (~700 MB). Once the env is active, ``--no-real-detector``
lets you skip Pass A and rebuild only from the overlay (~1 s) for fast
iteration on the storyline-critical objects.

Typical invocation::

    python3 -m tools.detection_prep                  # full prep
    python3 -m tools.detection_prep --no-real-detector  # overlay-only
    python3 -m tools.detection_prep --force          # ignore cache

Weights default to ``~/.cache/at-detection-prep/yolov8n-obb.pt`` and are
fetched on first run by ultralytics.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

DEFAULT_PANORAMA_DIR = Path("examples/dod_mission/assets/video")
DEFAULT_PANORAMA_STEM = "naip_huntsville"
DEFAULT_OUTPUT_DIR = Path("examples/dod_mission/assets/detections")
DEFAULT_OVERLAY = DEFAULT_OUTPUT_DIR / "overlay.json"
DEFAULT_WEIGHTS_NAME = "yolov8n-obb.pt"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "at-detection-prep"

DEFAULT_TILE_SIZE = 1024
DEFAULT_TILE_OVERLAP = 128
DEFAULT_CONF_THRESHOLD = 0.45
DEFAULT_IOU_THRESHOLD = 0.45
DEFAULT_CROP_W = 128
DEFAULT_CROP_H = 96
CROP_MARGIN_FRACTION = 0.20

WGS84_EPSG = 4326
UTM_ZONE_16N_EPSG = 32616


@dataclass
class Sidecar:
    """Subset of naip_fetch.py's geo.json sidecar that this tool reads."""
    size_px: tuple[int, int]
    bbox_epsg: int
    bbox_xmin: float
    bbox_ymin: float
    bbox_xmax: float
    bbox_ymax: float
    px_per_m: float
    center_lat: float
    center_lon: float
    jpeg_sha256: str

    @classmethod
    def load(cls, path: Path) -> "Sidecar":
        raw = json.loads(path.read_text())
        bbox = raw["bbox"]
        return cls(
            size_px=tuple(raw["panorama"]["size_px"]),
            bbox_epsg=int(bbox["epsg"]),
            bbox_xmin=float(bbox["xmin"]), bbox_ymin=float(bbox["ymin"]),
            bbox_xmax=float(bbox["xmax"]), bbox_ymax=float(bbox["ymax"]),
            px_per_m=float(raw["panorama"]["px_per_m"]),
            center_lat=float(raw["center"]["lat"]),
            center_lon=float(raw["center"]["lon"]),
            jpeg_sha256=str(raw.get("jpeg_sha256", "")),
        )

    def world_to_pixel(self, e: float, n: float) -> tuple[float, float]:
        """UTM (E, N) -> panorama (px, py); py increases downward."""
        w, h = self.size_px
        px = (e - self.bbox_xmin) / (self.bbox_xmax - self.bbox_xmin) * w
        py = (self.bbox_ymax - n) / (self.bbox_ymax - self.bbox_ymin) * h
        return px, py

    def pixel_to_world(self, px: float, py: float) -> tuple[float, float]:
        """Panorama (px, py) -> UTM (E, N)."""
        w, h = self.size_px
        e = self.bbox_xmin + (px / w) * (self.bbox_xmax - self.bbox_xmin)
        n = self.bbox_ymax - (py / h) * (self.bbox_ymax - self.bbox_ymin)
        return e, n


@dataclass
class Detection:
    world_uid: str
    cls: str
    confidence: float
    source: str
    bbox_px: tuple[int, int, int, int]          # AABB (x1, y1, x2, y2)
    obb_px: list[tuple[float, float]]           # 4 corners (cw or ccw)
    bbox_utm: tuple[float, float, float, float] # (Emin, Nmin, Emax, Nmax)
    center_lat: float
    center_lon: float
    crop_relpath: str
    extra: dict = field(default_factory=dict)


# ---- Pass A: real detector ---------------------------------------------


def _ensure_weights(weights_path: Path, *, quiet: bool) -> Path:
    if weights_path.exists():
        return weights_path
    weights_path.parent.mkdir(parents=True, exist_ok=True)
    # ultralytics will auto-download to its own cache; redirect by copying
    # into our cache dir on first instantiation if needed.
    try:
        from ultralytics import YOLO
    except ModuleNotFoundError as e:
        raise SystemExit(
            "ultralytics is required for Pass A: "
            "conda activate autonomous_trust\n"
            "(or rerun with --no-real-detector to skip the real detector)"
        ) from e
    if not quiet:
        print(f"[detection_prep] fetching {weights_path.name} via ultralytics ...")
    # Setting YOLO_CONFIG_DIR keeps ultralytics' settings/state local to our cache.
    os.environ.setdefault("YOLO_CONFIG_DIR", str(weights_path.parent))
    # ultralytics resolves a bare weight name relative to the *current working
    # directory* and downloads there. Run the download from inside the cache
    # dir so the .pt lands in weights_path.parent instead of scattering into
    # whatever cwd the tool was launched from (e.g. the repo root).
    prev_cwd = Path.cwd()
    try:
        os.chdir(weights_path.parent)
        model = YOLO(weights_path.name)
    finally:
        os.chdir(prev_cwd)
    # Fallback: if ultralytics still resolved the checkpoint elsewhere, copy it
    # into the canonical cache path.
    src = Path(model.ckpt_path) if hasattr(model, "ckpt_path") else None
    if src and src.exists() and src.resolve() != weights_path.resolve():
        weights_path.write_bytes(src.read_bytes())
    return weights_path


def _iter_tiles(width: int, height: int, tile_size: int, overlap: int
                ) -> Iterable[tuple[int, int, int, int]]:
    step = tile_size - overlap
    if step <= 0:
        raise ValueError("tile overlap must be smaller than tile size")
    ys = list(range(0, max(height - overlap, 1), step))
    xs = list(range(0, max(width - overlap, 1), step))
    if ys[-1] + tile_size < height:
        ys.append(height - tile_size)
    if xs[-1] + tile_size < width:
        xs.append(width - tile_size)
    for y in ys:
        for x in xs:
            yield x, y, min(x + tile_size, width), min(y + tile_size, height)


def _obb_to_aabb(corners: list[tuple[float, float]]
                 ) -> tuple[float, float, float, float]:
    xs = [c[0] for c in corners]
    ys = [c[1] for c in corners]
    return min(xs), min(ys), max(xs), max(ys)


def _aabb_iou(a: tuple[float, float, float, float],
              b: tuple[float, float, float, float]) -> float:
    ix1 = max(a[0], b[0]); iy1 = max(a[1], b[1])
    ix2 = min(a[2], b[2]); iy2 = min(a[3], b[3])
    if ix2 <= ix1 or iy2 <= iy1:
        return 0.0
    inter = (ix2 - ix1) * (iy2 - iy1)
    ua = (a[2] - a[0]) * (a[3] - a[1])
    ub = (b[2] - b[0]) * (b[3] - b[1])
    return inter / (ua + ub - inter + 1e-9)


def _nms(detections: list[dict], iou_threshold: float) -> list[dict]:
    detections = sorted(detections, key=lambda d: d["confidence"], reverse=True)
    kept: list[dict] = []
    for det in detections:
        if any(_aabb_iou(det["aabb"], k["aabb"]) >= iou_threshold
               for k in kept if k["class"] == det["class"]):
            continue
        kept.append(det)
    return kept


def _stitch_obb_corners(corners_batch, confs, clses,
                        x_off: int, y_off: int, names: dict) -> list[dict]:
    """Convert one tile's OBB result rows into panorama-space raw detections.

    ``corners_batch`` is an (N, 4, 2) array of tile-local corner coordinates
    (ultralytics ``result.obb.xyxyxyxy``); ``confs``/``clses`` are the parallel
    (N,) confidence / class-index arrays. Each box is shifted by the tile's
    top-left offset so corners land in panorama pixel space, then reduced to an
    AABB for cross-tile NMS. Pulled out of :func:`_run_yolo_obb` so the
    offset/stitching arithmetic is unit-testable without torch or a real
    model."""
    out: list[dict] = []
    for corners, conf, cls in zip(corners_batch, confs, clses):
        corners = [(float(cx + x_off), float(cy + y_off)) for cx, cy in corners]
        out.append({
            "class": str(names.get(int(cls), str(int(cls)))),
            "confidence": float(conf),
            "aabb": _obb_to_aabb(corners),
            "obb": corners,
        })
    return out


def _run_yolo_obb(panorama_path: Path, weights_path: Path,
                  conf_threshold: float, tile_size: int, tile_overlap: int,
                  iou_threshold: float, *, quiet: bool) -> list[dict]:
    try:
        from PIL import Image
        from ultralytics import YOLO
    except ModuleNotFoundError as e:
        raise SystemExit(
            "ultralytics + Pillow required for Pass A "
            "(conda activate autonomous_trust, or pass --no-real-detector)"
        ) from e

    model = YOLO(str(weights_path))
    names = model.names if isinstance(model.names, dict) else dict(enumerate(model.names))
    img = Image.open(panorama_path).convert("RGB")
    width, height = img.size
    raw: list[dict] = []
    tiles = list(_iter_tiles(width, height, tile_size, tile_overlap))
    if not quiet:
        print(f"[detection_prep] Pass A: {len(tiles)} tiles "
              f"({tile_size}px, {tile_overlap}px overlap)")
    for i, (x1, y1, x2, y2) in enumerate(tiles, start=1):
        tile = img.crop((x1, y1, x2, y2))
        result = model.predict(tile, conf=conf_threshold, verbose=False)[0]
        if not getattr(result, "obb", None):
            continue
        # result.obb.xyxyxyxy shape: (N, 4, 2)
        corners_batch = result.obb.xyxyxyxy.cpu().numpy()
        confs = result.obb.conf.cpu().numpy()
        clses = result.obb.cls.cpu().numpy().astype(int)
        raw.extend(_stitch_obb_corners(corners_batch, confs, clses,
                                       x1, y1, names))
        if not quiet and (i % 4 == 0 or i == len(tiles)):
            print(f"[detection_prep]   tile {i}/{len(tiles)}: "
                  f"running total {len(raw)}")
    merged = _nms(raw, iou_threshold)
    if not quiet:
        print(f"[detection_prep] Pass A: {len(raw)} raw -> {len(merged)} after NMS")
    return merged


def _detections_from_yolo(raw: list[dict], sidecar: Sidecar
                          ) -> list[Detection]:
    detections: list[Detection] = []
    for idx, det in enumerate(raw, start=1):
        x1, y1, x2, y2 = det["aabb"]
        emin, nmax = sidecar.pixel_to_world(x1, y1)
        emax, nmin = sidecar.pixel_to_world(x2, y2)
        cx_px = 0.5 * (x1 + x2)
        cy_px = 0.5 * (y1 + y2)
        clat, clon = _utm_to_wgs84(*sidecar.pixel_to_world(cx_px, cy_px),
                                   epsg=sidecar.bbox_epsg)
        uid = f"obj-{idx:04d}"
        detections.append(Detection(
            world_uid=uid,
            cls=det["class"],
            confidence=det["confidence"],
            source="yolov8n-obb",
            bbox_px=(int(x1), int(y1), int(x2), int(y2)),
            obb_px=[(float(cx), float(cy)) for cx, cy in det["obb"]],
            bbox_utm=(min(emin, emax), min(nmin, nmax),
                      max(emin, emax), max(nmin, nmax)),
            center_lat=clat, center_lon=clon,
            crop_relpath=f"crops/{uid}.jpg",
        ))
    return detections


# ---- Pass B: scenario overlay ------------------------------------------


def _wgs84_to_utm(lat: float, lon: float, *, epsg: int) -> tuple[float, float]:
    from pyproj import Transformer
    tx = Transformer.from_crs(WGS84_EPSG, epsg, always_xy=True)
    e, n = tx.transform(lon, lat)
    return e, n


def _utm_to_wgs84(e: float, n: float, *, epsg: int) -> tuple[float, float]:
    from pyproj import Transformer
    tx = Transformer.from_crs(epsg, WGS84_EPSG, always_xy=True)
    lon, lat = tx.transform(e, n)
    return lat, lon


def _detections_from_overlay(overlay_path: Path, sidecar: Sidecar
                             ) -> list[Detection]:
    raw = json.loads(overlay_path.read_text())
    detections: list[Detection] = []
    for entry in raw.get("objects", []):
        lat = float(entry["lat"]); lon = float(entry["lon"])
        ext_w, ext_h = entry["bbox_extent_m"]
        e_center, n_center = _wgs84_to_utm(lat, lon, epsg=sidecar.bbox_epsg)
        emin, emax = e_center - ext_w / 2, e_center + ext_w / 2
        nmin, nmax = n_center - ext_h / 2, n_center + ext_h / 2
        # Corners cw from NW for the OBB field (axis-aligned for overlay objects).
        nw = sidecar.world_to_pixel(emin, nmax)
        ne = sidecar.world_to_pixel(emax, nmax)
        se = sidecar.world_to_pixel(emax, nmin)
        sw = sidecar.world_to_pixel(emin, nmin)
        obb = [nw, ne, se, sw]
        aabb = _obb_to_aabb(obb)
        uid = str(entry["world_uid"])
        extra = {
            k: entry[k]
            for k in ("ground_truth_label", "scenario_role",
                      "linked_peer", "_note")
            if k in entry
        }
        detections.append(Detection(
            world_uid=uid,
            cls=str(entry["class"]),
            confidence=1.0,
            source="scenario-overlay",
            bbox_px=tuple(int(round(v)) for v in aabb),
            obb_px=[(float(cx), float(cy)) for cx, cy in obb],
            bbox_utm=(emin, nmin, emax, nmax),
            center_lat=lat, center_lon=lon,
            crop_relpath=f"crops/{uid}.jpg",
            extra=extra,
        ))
    return detections


# ---- Pass C: crop bake-out ---------------------------------------------


def _bake_crops(panorama_path: Path, detections: list[Detection],
                output_dir: Path, crop_w: int, crop_h: int,
                *, quiet: bool) -> None:
    try:
        from PIL import Image
    except ModuleNotFoundError as e:
        raise SystemExit(
            "Pillow is required: conda activate autonomous_trust") from e
    crops_dir = output_dir / "crops"
    crops_dir.mkdir(parents=True, exist_ok=True)
    img = Image.open(panorama_path).convert("RGB")
    pw, ph = img.size
    written = 0
    for det in detections:
        x1, y1, x2, y2 = det.bbox_px
        w = x2 - x1; h = y2 - y1
        mw = int(w * CROP_MARGIN_FRACTION)
        mh = int(h * CROP_MARGIN_FRACTION)
        cx1 = max(0, x1 - mw); cy1 = max(0, y1 - mh)
        cx2 = min(pw, x2 + mw); cy2 = min(ph, y2 + mh)
        if cx2 <= cx1 or cy2 <= cy1:
            continue
        crop = img.crop((cx1, cy1, cx2, cy2))
        crop.thumbnail((crop_w, crop_h))
        crop.save(output_dir / det.crop_relpath, format="JPEG",
                  quality=82, optimize=True)
        written += 1
    if not quiet:
        print(f"[detection_prep] Pass C: wrote {written} crops to {crops_dir}/")


# ---- Catalogue serialization -------------------------------------------


def _cache_key(panorama_sha: str, overlay_sha: str, weights_sha: str,
               args_summary: dict) -> str:
    payload = json.dumps({
        "panorama_sha256": panorama_sha,
        "overlay_sha256": overlay_sha,
        "weights_sha256": weights_sha,
        "args": args_summary,
        "schema": "detection-prep/v1",
    }, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_catalogue(catalogue_path: Path, sidecar: Sidecar,
                     panorama_path: Path, detections: list[Detection],
                     detector_meta: dict, cache_key: str) -> None:
    objects = []
    for det in detections:
        obj = {
            "world_uid": det.world_uid,
            "class": det.cls,
            "confidence": round(det.confidence, 4),
            "source": det.source,
            "bbox_panorama_px": list(det.bbox_px),
            "obb_panorama_px": [[round(c[0], 2), round(c[1], 2)]
                                for c in det.obb_px],
            "bbox_utm_e_n": [round(v, 2) for v in det.bbox_utm],
            "bbox_utm_epsg": sidecar.bbox_epsg,
            "center_lat": round(det.center_lat, 7),
            "center_lon": round(det.center_lon, 7),
            "crop": det.crop_relpath,
        }
        obj.update(det.extra)
        objects.append(obj)
    catalogue = {
        "_schema": "detection-prep/v1",
        "panorama": {
            "path": str(panorama_path),
            "size_px": list(sidecar.size_px),
            "px_per_m": sidecar.px_per_m,
            "bbox_utm": {
                "epsg": sidecar.bbox_epsg,
                "xmin": sidecar.bbox_xmin, "ymin": sidecar.bbox_ymin,
                "xmax": sidecar.bbox_xmax, "ymax": sidecar.bbox_ymax,
            },
            "center": {"lat": sidecar.center_lat,
                       "lon": sidecar.center_lon},
            "sha256": sidecar.jpeg_sha256,
        },
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "detector": detector_meta,
        "cache_key": cache_key,
        "objects": objects,
    }
    catalogue_path.parent.mkdir(parents=True, exist_ok=True)
    catalogue_path.write_text(json.dumps(catalogue, indent=2) + "\n")


# ---- Driver ------------------------------------------------------------


def prep(panorama_path: Path, sidecar_path: Path, overlay_path: Path,
         output_dir: Path, weights_path: Path, *,
         use_real_detector: bool, conf_threshold: float,
         tile_size: int, tile_overlap: int, iou_threshold: float,
         crop_w: int, crop_h: int, force: bool, quiet: bool) -> dict:

    if not panorama_path.exists():
        raise SystemExit(
            f"Panorama not found: {panorama_path}\n"
            "Run tools/naip_fetch.py first."
        )
    if not sidecar_path.exists():
        raise SystemExit(f"Geo sidecar not found: {sidecar_path}")
    if not overlay_path.exists():
        raise SystemExit(f"Overlay JSON not found: {overlay_path}")

    sidecar = Sidecar.load(sidecar_path)
    panorama_sha = sidecar.jpeg_sha256 or _sha256_of_file(panorama_path)
    overlay_sha = _sha256_of_file(overlay_path)
    weights_sha = ""

    detector_meta: dict
    yolo_detections: list[Detection] = []
    if use_real_detector:
        weights_path = _ensure_weights(weights_path, quiet=quiet)
        weights_sha = _sha256_of_file(weights_path)
        raw_yolo = _run_yolo_obb(
            panorama_path, weights_path,
            conf_threshold=conf_threshold,
            tile_size=tile_size, tile_overlap=tile_overlap,
            iou_threshold=iou_threshold, quiet=quiet,
        )
        yolo_detections = _detections_from_yolo(raw_yolo, sidecar)
        detector_meta = {
            "name": "yolov8n-obb",
            "weights_path": str(weights_path),
            "weights_sha256": weights_sha,
            "conf_threshold": conf_threshold,
            "iou_threshold": iou_threshold,
            "tile_size": tile_size,
            "tile_overlap": tile_overlap,
        }
    else:
        detector_meta = {"name": "(skipped)", "_note":
                         "Pass A skipped via --no-real-detector"}

    overlay_detections = _detections_from_overlay(overlay_path, sidecar)
    if not quiet:
        print(f"[detection_prep] Pass B: {len(overlay_detections)} "
              f"scenario-overlay objects")

    all_detections = yolo_detections + overlay_detections

    args_summary = {
        "use_real_detector": use_real_detector,
        "conf_threshold": conf_threshold,
        "tile_size": tile_size,
        "tile_overlap": tile_overlap,
        "iou_threshold": iou_threshold,
        "crop_w": crop_w, "crop_h": crop_h,
    }
    cache_key = _cache_key(panorama_sha, overlay_sha, weights_sha, args_summary)

    catalogue_path = output_dir / "catalogue.json"
    if not force and catalogue_path.exists():
        try:
            prev = json.loads(catalogue_path.read_text())
        except json.JSONDecodeError:
            prev = {}
        if prev.get("cache_key") == cache_key:
            if not quiet:
                print(f"[detection_prep] catalogue up to date "
                      f"({len(prev.get('objects', []))} objects, cache "
                      f"key {cache_key}) — pass --force to rebuild")
            return prev

    _bake_crops(panorama_path, all_detections, output_dir,
                crop_w=crop_w, crop_h=crop_h, quiet=quiet)
    _write_catalogue(catalogue_path, sidecar, panorama_path,
                     all_detections, detector_meta, cache_key)

    if not quiet:
        print(f"[detection_prep] wrote {catalogue_path} "
              f"({len(all_detections)} objects)")
    return json.loads(catalogue_path.read_text())


def _arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--panorama-dir", type=Path, default=DEFAULT_PANORAMA_DIR)
    p.add_argument("--panorama-stem", default=DEFAULT_PANORAMA_STEM,
                   help="Filename stem; tool reads <stem>.jpg + <stem>.geo.json")
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY)
    p.add_argument("--weights", type=Path,
                   default=DEFAULT_CACHE_DIR / DEFAULT_WEIGHTS_NAME)
    p.add_argument("--no-real-detector", action="store_true",
                   help="Skip Pass A; build catalogue from overlay only")
    p.add_argument("--confidence-threshold", type=float,
                   default=DEFAULT_CONF_THRESHOLD)
    p.add_argument("--iou-threshold", type=float, default=DEFAULT_IOU_THRESHOLD)
    p.add_argument("--tile-size", type=int, default=DEFAULT_TILE_SIZE)
    p.add_argument("--tile-overlap", type=int, default=DEFAULT_TILE_OVERLAP)
    p.add_argument("--crop-w", type=int, default=DEFAULT_CROP_W)
    p.add_argument("--crop-h", type=int, default=DEFAULT_CROP_H)
    p.add_argument("--force", action="store_true",
                   help="Rebuild even if cache key matches")
    p.add_argument("--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _arg_parser().parse_args(argv)
    panorama_path = args.panorama_dir / f"{args.panorama_stem}.jpg"
    sidecar_path = args.panorama_dir / f"{args.panorama_stem}.geo.json"
    prep(
        panorama_path=panorama_path,
        sidecar_path=sidecar_path,
        overlay_path=args.overlay,
        output_dir=args.output_dir,
        weights_path=args.weights,
        use_real_detector=not args.no_real_detector,
        conf_threshold=args.confidence_threshold,
        tile_size=args.tile_size,
        tile_overlap=args.tile_overlap,
        iou_threshold=args.iou_threshold,
        crop_w=args.crop_w,
        crop_h=args.crop_h,
        force=args.force,
        quiet=args.quiet,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
