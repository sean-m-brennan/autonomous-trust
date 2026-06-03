# ******************
#  Copyright 2026 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Sparse Detection event source for the DoD demo.

Stretch Goal 2, Phase 2 (STRETCH_GOAL_2_DETECTION_PLAN.md sections
5.1-5.5). Per drone-role peer, this generator computes a role-specific
ground-plane FOV at construction, intersects it with the pre-built
catalogue of detectable objects, and emits a small set of Reading
events per tick:

  Reading(data_type="detection", value=<confidence>,
          metadata={world_uid, class, label, crop_id, bbox_in_view_px,
                    bbox_panorama_px})
  Reading(data_type="target_position_x", value=<UTM-E offset, m>,
          metadata={world_uid})
  Reading(data_type="target_position_y", value=<UTM-N offset, m>,
          metadata={world_uid})

Position values are reported as metres relative to the squad insertion
landmark (matching `examples/dod_mission/generators/isr.py`'s
synthetic target_position_x/y frame, so existing
`CrossSourceValidator` instances accept them without scale change).
The world_uid in `metadata` lets the validator bucket by target after
the Phase 2 tweak in `examples/multi_agency/tasks/validation.py`.

A heartbeat (data_type="detection_heartbeat", value=0.0) fires when
the peer's FOV holds no objects, so the inspector can distinguish
"active, no contacts" from "stale link."

The compromise wrapper for the MQ-800 lives in
`examples/dod_mission/compromise/contradictory_isr.py` and overrides
emit to substitute the decoy's position + crop while keeping the
honest `world_uid` (so the validator's same-target bucket sees the
disagreement).

For Phase 2 v1 the FOV polygon is a peer-local axis-aligned rectangle
(rotated by bearing); the plan's trapezoid/oblique geometry can land
in Phase 3 polish without changing this module's interface.
"""

from __future__ import annotations

import base64
import json
import logging
import math
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Iterable, Optional

from autonomous_trust.services.data import Reading


logger = logging.getLogger(__name__)


DEFAULT_CATALOGUE_PATH = Path(
    "examples/dod_mission/assets/detections/catalogue.json"
)
DEFAULT_TIME_FLOOR_SEC = 5.0
DEFAULT_SUPPRESSION_SEC = 30.0
DEFAULT_DRIFT_THRESHOLD_M = 25.0

# Squad insertion landmark (GROUND_START in examples/dod_mission/scenario.py).
# Position readings are reported as metres east/north of this point so they
# share a frame with isr.py's _target_true_xy synthetic generator.
SQUAD_ORIGIN_LAT = 34.706505
SQUAD_ORIGIN_LON = -86.633657

WGS84_EPSG = 4326
UTM_ZONE_16N_EPSG = 32616


# --- Role-specific FOV defaults -----------------------------------------


@dataclass(frozen=True)
class RoleFOV:
    """Ground-plane FOV approximation for a drone role.

    All distances are metres. The polygon is built as an axis-aligned
    rectangle in peer-local coordinates and then rotated to the peer's
    bearing; the peer sits at the rectangle's *rear* edge centre.

    Attributes:
        forward_m:  along-axis ground range (peer to far edge)
        back_m:     along-axis behind-peer range (usually 0 for fwd-looking)
        half_width_m: cross-axis half-width
        alt_m:      peer altitude (recorded in detection metadata)
    """
    forward_m: float
    back_m: float
    half_width_m: float
    alt_m: float


# Per-peer view-centre override (lat, lon), used when a peer's roster
# position is outside the AO panorama. MQ-800's roster ingress is
# 3.4 km east of the AO; we pin its detection vantage east of and
# between compound-alpha (target) and compound-bravo (decoy) so its
# west-facing (bearing 270deg) 600 m x 600 m FOV catches both: the decoy
# sits ~196 m forward and the target ~541 m forward, each ~158 m off the
# centreline (well inside the 300 m half-width). Microdrones / RQ-86s use
# their roster positions (no override entry). Keep in sync with the
# compound-alpha/bravo positions in assets/detections/overlay.json.
DETECTION_VIEW_CENTER_OVERRIDE: dict[str, tuple[float, float]] = {
    "mq800": (34.724940, -86.632000),
}


ROLE_FOV: dict[str, RoleFOV] = {
    # Microdrones: low + close, narrow-ish trapezoid approximated as a
    # forward rectangle (350 m fwd, 350 m wide). Plan section 5.2.
    "microdrone": RoleFOV(forward_m=350.0, back_m=0.0,
                          half_width_m=175.0, alt_m=200.0),
    # RQ-86: high + nadir; FOV covers a 10 km square centred on the peer.
    "recon-drone": RoleFOV(forward_m=5000.0, back_m=5000.0,
                           half_width_m=5000.0, alt_m=5000.0),
    # MQ-800: mid altitude, longer oblique trapezoid -> 600 m fwd,
    # 600 m wide. Plan section 5.2.
    "armed-drone": RoleFOV(forward_m=600.0, back_m=0.0,
                           half_width_m=300.0, alt_m=600.0),
}


# Per-role default bearing when the peer can't (or doesn't) supply one.
# Microdrones launch facing the target compound (north). RQ-86s orbit
# overhead — bearing irrelevant. MQ-800 ingresses westward toward the
# AO from its eastern roster position.
ROLE_DEFAULT_BEARING_DEG: dict[str, float] = {
    "microdrone": 0.0,
    "recon-drone": 0.0,
    "armed-drone": 270.0,
}


# --- Coordinate helpers -------------------------------------------------


def _wgs84_to_utm(lat: float, lon: float) -> tuple[float, float]:
    from pyproj import Transformer
    tx = Transformer.from_crs(WGS84_EPSG, UTM_ZONE_16N_EPSG, always_xy=True)
    e, n = tx.transform(lon, lat)
    return e, n


def _utm_to_squad_xy(e: float, n: float) -> tuple[float, float]:
    """UTM-16N (E, N) -> metres east/north of squad insertion landmark.

    Matches the local frame used by isr.py's _target_true_xy.
    """
    origin_e, origin_n = _wgs84_to_utm(SQUAD_ORIGIN_LAT, SQUAD_ORIGIN_LON)
    return e - origin_e, n - origin_n


# --- Catalogue ----------------------------------------------------------


@dataclass(frozen=True)
class CatalogueObject:
    world_uid: str
    cls: str
    confidence: float
    crop: str
    crop_b64: str                      # base64 of crop bytes (may be "")
    crop_size_px: tuple[int, int]      # (w, h) of the crop, post-thumbnail
    bbox_panorama_px: tuple[int, int, int, int]
    center_utm: tuple[float, float]    # (E, N)
    center_squad_xy: tuple[float, float]  # (x, y) relative to GROUND_START
    center_latlon: tuple[float, float]  # (lat, lon) for map markers
    label: str
    extra: dict


def _load_crop_b64(crop_relpath: str, crops_root: Path
                   ) -> tuple[str, tuple[int, int]]:
    """Return (base64 string, (width, height)). Empty/zero on missing."""
    if not crop_relpath:
        return "", (0, 0)
    path = crops_root / crop_relpath
    if not path.is_file():
        path = (crops_root.parent / crop_relpath
                if (crops_root.parent / crop_relpath).is_file() else path)
    if not path.is_file():
        logger.warning("Crop file missing: %s (expected under %s)",
                       crop_relpath, crops_root)
        return "", (0, 0)
    blob = path.read_bytes()
    w, h = 0, 0
    try:
        from PIL import Image
        import io as _io
        img = Image.open(_io.BytesIO(blob))
        w, h = img.size
    except Exception:  # noqa: BLE001 — PIL not strictly required
        pass
    return base64.b64encode(blob).decode("ascii"), (w, h)


def load_catalogue(path: Path,
                   crops_root: Optional[Path] = None) -> list[CatalogueObject]:
    """Load and pre-resolve a catalogue.json from disk.

    ``crops_root`` defaults to the catalogue file's parent directory
    (matching the layout produced by ``tools/detection_prep.py``).
    Crops are read once and base64-encoded into each CatalogueObject so
    the runtime never opens an image file per tick.
    """
    catalogue_path = Path(path)
    if crops_root is None:
        crops_root = catalogue_path.parent
    crops_root = Path(crops_root)
    raw = json.loads(catalogue_path.read_text())
    objects: list[CatalogueObject] = []
    for entry in raw.get("objects", []):
        emin, nmin, emax, nmax = entry["bbox_utm_e_n"]
        ce = 0.5 * (emin + emax)
        cn = 0.5 * (nmin + nmax)
        cx, cy = _utm_to_squad_xy(ce, cn)
        crop_relpath = str(entry.get("crop", ""))
        crop_b64, crop_size = _load_crop_b64(crop_relpath, crops_root)
        extra = {k: v for k, v in entry.items()
                 if k not in ("world_uid", "class", "confidence",
                              "crop", "bbox_panorama_px",
                              "obb_panorama_px", "bbox_utm_e_n",
                              "bbox_utm_epsg", "center_lat",
                              "center_lon")}
        objects.append(CatalogueObject(
            world_uid=str(entry["world_uid"]),
            cls=str(entry["class"]),
            confidence=float(entry["confidence"]),
            crop=crop_relpath,
            crop_b64=crop_b64,
            crop_size_px=crop_size,
            bbox_panorama_px=tuple(entry["bbox_panorama_px"]),
            center_utm=(ce, cn),
            center_squad_xy=(cx, cy),
            center_latlon=(float(entry.get("center_lat", 0.0)),
                           float(entry.get("center_lon", 0.0))),
            label=str(entry.get("ground_truth_label", entry["class"])),
            extra=extra,
        ))
    return objects


# --- FOV math -----------------------------------------------------------


def _is_in_fov(obj_utm: tuple[float, float],
               view_utm: tuple[float, float],
               bearing_deg: float, fov: RoleFOV) -> bool:
    """Point-in-rectangle in the peer's local axis-rotated frame."""
    dx = obj_utm[0] - view_utm[0]
    dy = obj_utm[1] - view_utm[1]
    # Bearing is compass: 0 = N (+y), 90 = E (+x). To put the bearing
    # axis along the local "forward" (+y) axis, rotate by -bearing.
    theta = math.radians(-bearing_deg)
    local_x = dx * math.cos(theta) + dy * math.sin(theta)
    local_y = -dx * math.sin(theta) + dy * math.cos(theta)
    if local_y < -fov.back_m or local_y > fov.forward_m:
        return False
    if abs(local_x) > fov.half_width_m:
        return False
    return True


def _visible_objects(catalogue: Iterable[CatalogueObject],
                     view_utm: tuple[float, float],
                     bearing_deg: float, fov: RoleFOV
                     ) -> list[CatalogueObject]:
    return [obj for obj in catalogue
            if _is_in_fov(obj.center_utm, view_utm, bearing_deg, fov)]


# --- Source --------------------------------------------------------------


@dataclass
class _EmitState:
    last_t_sec: float
    last_x: float
    last_y: float


class DetectionSource:
    """Per-peer sparse detection emitter.

    Construct once at participant startup; call ``tick(t)`` each
    sensor-loop iteration. Returns 0..N Readings (heartbeat included).

    Args:
        peer_name:           UUID / nickname used in Reading.peer_name
        role:                "microdrone" / "recon-drone" / "armed-drone"
        catalogue:           Loaded list of CatalogueObject (load via
                             load_catalogue() before constructing)
        view_center_latlon:  (lat, lon) FOV origin. Defaults to the
                             peer's roster position; MQ-800 overrides
                             this since its roster position is east of
                             the AO.
        bearing_deg:         Peer's facing direction (0=N). Defaults to
                             ROLE_DEFAULT_BEARING_DEG[role].
        fov:                 Optional RoleFOV override (mostly tests).
        link_quality:        0..1; sets Reading.quality on emissions.
        time_floor_sec:      Minimum gap between any emissions.
        suppression_sec:     Per-world_uid re-emit gap.
        drift_threshold_m:   Override suppression if position drifted
                             more than this between observations.
        seed:                Reserved for future jitter; v1 unused.
    """

    def __init__(self, peer_name: str, role: str,
                 catalogue: list[CatalogueObject],
                 view_center_latlon: tuple[float, float],
                 bearing_deg: Optional[float] = None,
                 fov: Optional[RoleFOV] = None,
                 link_quality: float = 0.95,
                 time_floor_sec: float = DEFAULT_TIME_FLOOR_SEC,
                 suppression_sec: float = DEFAULT_SUPPRESSION_SEC,
                 drift_threshold_m: float = DEFAULT_DRIFT_THRESHOLD_M,
                 seed: Optional[int] = None):
        if role not in ROLE_FOV and fov is None:
            raise ValueError(
                f"Unknown role {role!r}; pass fov= explicitly or use one "
                f"of {sorted(ROLE_FOV)}"
            )
        self.peer_name = peer_name
        self.role = role
        self.catalogue = catalogue
        self.fov = fov or ROLE_FOV[role]
        self.bearing_deg = (bearing_deg if bearing_deg is not None
                            else ROLE_DEFAULT_BEARING_DEG.get(role, 0.0))
        self.link_quality = link_quality
        self.time_floor_sec = time_floor_sec
        self.suppression_sec = suppression_sec
        self.drift_threshold_m = drift_threshold_m
        self._view_center_latlon = view_center_latlon
        self._view_utm = _wgs84_to_utm(*view_center_latlon)
        # Pre-compute the in-view subset; for the stationary-peer v1
        # this never changes.
        self._visible = _visible_objects(catalogue, self._view_utm,
                                         self.bearing_deg, self.fov)
        self._emit_state: dict[str, _EmitState] = {}
        self._last_tick_sec: float = -math.inf

    # --- public introspection ------------------------------------------

    @property
    def visible_uids(self) -> list[str]:
        return [obj.world_uid for obj in self._visible]

    def visible_objects(self) -> list[CatalogueObject]:
        return list(self._visible)

    # --- emit ----------------------------------------------------------

    def tick(self, t: timedelta) -> list[Reading]:
        t_sec = t.total_seconds()
        if t_sec - self._last_tick_sec < self.time_floor_sec:
            return []
        self._last_tick_sec = t_sec

        readings: list[Reading] = []
        for obj in self._visible:
            for r in self._emit_for(obj, t, t_sec):
                readings.append(r)
        if not readings:
            readings.append(self._heartbeat(t))
        return readings

    # --- hook for subclasses -------------------------------------------

    def _resolve_emission(self, obj: CatalogueObject
                          ) -> tuple[CatalogueObject, str]:
        """Return (catalogue object whose POSITION + CROP to report,
        world_uid label to attach to readings).

        Default: identity. The compromise subclass overrides this to
        return a *decoy* object while keeping the honest UID, so the
        cross-source validator catches the position lie inside the
        honest target's bucket.
        """
        return obj, obj.world_uid

    # --- internals -----------------------------------------------------

    def _emit_for(self, obj: CatalogueObject, t: timedelta,
                  t_sec: float) -> list[Reading]:
        reported_obj, world_uid = self._resolve_emission(obj)
        rx, ry = reported_obj.center_squad_xy
        prev = self._emit_state.get(world_uid)
        drifted = prev is not None and (
            abs(rx - prev.last_x) > self.drift_threshold_m
            or abs(ry - prev.last_y) > self.drift_threshold_m
        )
        if prev is not None and not drifted:
            if t_sec - prev.last_t_sec < self.suppression_sec:
                return []
        self._emit_state[world_uid] = _EmitState(t_sec, rx, ry)
        # bbox-in-crop is the full crop frame minus the 20% margin used
        # by detection_prep.py; we report the inner rectangle so the
        # inspector can overlay it directly on the rendered crop.
        cw, ch = reported_obj.crop_size_px
        if cw > 0 and ch > 0:
            mx = int(round(cw * 0.20 / (1 + 2 * 0.20)))
            my = int(round(ch * 0.20 / (1 + 2 * 0.20)))
            bbox_in_crop = [mx, my, max(cw - mx, mx + 1),
                            max(ch - my, my + 1)]
        else:
            bbox_in_crop = [0, 0, 0, 0]
        return [
            Reading(
                timestamp=t,
                peer_name=self.peer_name,
                data_type="detection",
                value=reported_obj.confidence,
                unit="conf",
                quality=self.link_quality,
                metadata={
                    "world_uid": world_uid,
                    "class": reported_obj.cls,
                    "label": reported_obj.label,
                    "crop_id": reported_obj.crop,
                    "crop_b64": reported_obj.crop_b64,
                    "crop_size_px": list(reported_obj.crop_size_px),
                    "bbox_in_crop_px": bbox_in_crop,
                    "bbox_panorama_px": list(reported_obj.bbox_panorama_px),
                    "target_latlon": list(reported_obj.center_latlon),
                    "view_center_latlon": list(self._view_center_latlon),
                    "view_bearing_deg": self.bearing_deg,
                    "view_alt_m": self.fov.alt_m,
                },
            ),
            Reading(
                timestamp=t,
                peer_name=self.peer_name,
                data_type="target_position_x",
                value=rx,
                unit="m",
                quality=self.link_quality,
                metadata={"world_uid": world_uid},
            ),
            Reading(
                timestamp=t,
                peer_name=self.peer_name,
                data_type="target_position_y",
                value=ry,
                unit="m",
                quality=self.link_quality,
                metadata={"world_uid": world_uid},
            ),
        ]

    def _heartbeat(self, t: timedelta) -> Reading:
        return Reading(
            timestamp=t,
            peer_name=self.peer_name,
            data_type="detection_heartbeat",
            value=0.0,
            unit="",
            quality=self.link_quality,
            metadata={"role": self.role,
                      "in_view_count": 0,
                      "view_center_latlon": list(self._view_center_latlon)},
        )


# --- Construction helper ------------------------------------------------


def build_detection_source(peer_name: str, role: str,
                           roster_latlon: tuple[float, float],
                           *,
                           catalogue_path: Path = DEFAULT_CATALOGUE_PATH,
                           view_center_override_latlon: Optional[
                               tuple[float, float]] = None,
                           bearing_deg: Optional[float] = None,
                           link_quality: float = 0.95,
                           seed: Optional[int] = None
                           ) -> Optional[DetectionSource]:
    """Convenience factory used by participant.py.

    Returns None (with a warning) if the catalogue is missing — so the
    demo runs even before tools/detection_prep.py has been executed.
    """
    if role not in ROLE_FOV:
        return None
    catalogue_path = Path(catalogue_path)
    if not catalogue_path.exists():
        logger.warning(
            "DetectionSource disabled for peer %s (%s): catalogue "
            "not found at %s. Run tools/detection_prep.py.",
            peer_name, role, catalogue_path,
        )
        return None
    try:
        catalogue = load_catalogue(catalogue_path)
    except (OSError, json.JSONDecodeError, KeyError) as e:
        logger.error("Failed to load catalogue %s: %s", catalogue_path, e)
        return None
    view_center = view_center_override_latlon or roster_latlon
    return DetectionSource(
        peer_name=peer_name,
        role=role,
        catalogue=catalogue,
        view_center_latlon=view_center,
        bearing_deg=bearing_deg,
        link_quality=link_quality,
        seed=seed,
    )
