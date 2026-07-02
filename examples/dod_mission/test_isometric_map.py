# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the Tactical-Map isometric (3D terrain) view.

Covers the parts of ``target_position_map.TargetPositionMapPanel`` that the
iso view adds: the bundled DEM loads, the 3D figure assembles with an
orthographic camera, asset altitude is datum-normalized (microdrone AGL vs
everything-else MSL) and log-compressed, and the default 2D map path is
unchanged. None of this needs a running cohort or Dash server.

Run from the repo root:
    pytest examples/dod_mission/test_isometric_map.py
"""

from __future__ import annotations

import math

import plotly.graph_objects as go
import pytest

from examples.dod_mission.dashboard.target_position_map import (
    TargetPositionMapPanel, SQUAD_ORIGIN_LAT, SQUAD_ORIGIN_LON,
)
from examples.dod_mission.dashboard import target_position_map as tpm
from examples.dod_mission.dashboard.build_terrain import load_terrain


# A point near the AOI centre so terrain sampling is well inside the grid.
_AOI_LAT, _AOI_LON = 34.72, -86.64


def _panel() -> TargetPositionMapPanel:
    return TargetPositionMapPanel(peer_colors={"rq86-1": "#E0A800",
                                               "mq800": "#F2B134"})


def _platforms() -> dict:
    """Assets spanning the altitude range; alts are MSL except microdrone
    (stored AGL), matching scenario.py."""
    return {
        "squad-1":      {"lat": SQUAD_ORIGIN_LAT, "lon": SQUAD_ORIGIN_LON,
                         "alt": 197.0, "kind": "soldier", "color": "#5B6E1F"},
        "microdrone-0": {"lat": 34.708, "lon": -86.635, "alt": 16.0,
                         "kind": "microdrone", "color": "#1FB8CD"},
        "mq800":        {"lat": 34.715, "lon": -86.620, "alt": 600.0,
                         "kind": "armed-drone", "color": "#F2B134"},
        "rq86-1":       {"lat": 34.724, "lon": -86.640, "alt": 5000.0,
                         "kind": "recon-drone", "color": "#E0A800"},
    }


def test_bundled_terrain_loads():
    loaded = load_terrain()
    assert loaded is not None, "run build_terrain.py to bundle terrain_madison.npy"
    grid, meta = loaded
    assert grid.shape == (meta["rows"], meta["cols"])
    # Madison County, AL: valley floor ~170 m, ridges ~380 m.
    assert 100 < float(grid.min()) < float(grid.max()) < 700
    assert meta["row0_is_south"] is True


def test_iso_figure_builds_orthographic():
    panel = _panel()
    panel.set_view_mode("iso")
    panel.set_platforms(_platforms(), t_seconds=380.0)
    fig = panel.figure()
    types = [type(t).__name__ for t in fig.data]
    # One terrain Surface + Scatter3d traces (insertion anchor, stalks, assets).
    assert "Surface" in types
    assert types.count("Scatter3d") >= 2
    assert fig.layout.scene.camera.projection.type == "orthographic"
    assert fig.layout.uirevision == tpm._ISO_UIREVISION


def test_terrain_surface_is_cached_across_ticks():
    """The DEM never changes, so the Surface trace object is built once and
    reused — the property that keeps per-tick cost to just the assets."""
    panel = _panel()
    panel.set_view_mode("iso")
    panel.set_platforms(_platforms(), t_seconds=100.0)
    panel.figure()
    first = panel._terrain_trace
    panel.set_platforms(_platforms(), t_seconds=101.0)
    panel.figure()
    assert panel._terrain_trace is first


def test_datum_normalization_microdrone_above_squad():
    """Microdrone alt is AGL (~16 m) and must render ABOVE a squad sitting at
    MSL ground level, not below it (the naive-plot bug)."""
    panel = _panel()
    panel.set_view_mode("iso")
    panel._ensure_terrain()
    # Same location so terrain is identical; only the kind/alt differ.
    _, _, z_ground, agl_g, _ = panel._asset_z(_AOI_LAT, _AOI_LON, 197.0, "soldier")
    _, _, z_drone, agl_d, _ = panel._asset_z(_AOI_LAT, _AOI_LON, 16.0, "microdrone")
    assert agl_d == pytest.approx(16.0)        # microdrone alt taken as AGL
    assert agl_g < 60.0                        # squad MSL ~= local terrain
    assert z_drone > z_ground


def test_asset_z_is_true_msl():
    """z values are now raw altitude in metres MSL (the log lives on the
    axis): each asset's z equals its MSL altitude, ordered above terrain."""
    panel = _panel()
    panel.set_view_mode("iso")
    panel._ensure_terrain()
    terr = panel._terrain_at(_AOI_LAT, _AOI_LON)
    _, _, z_low, _, _ = panel._asset_z(_AOI_LAT, _AOI_LON, 250.0, "armed-drone")
    _, _, z_mid, _, _ = panel._asset_z(_AOI_LAT, _AOI_LON, 600.0, "armed-drone")
    _, _, z_hi, _, _ = panel._asset_z(_AOI_LAT, _AOI_LON, 5000.0, "recon-drone")
    assert z_low == pytest.approx(250.0)
    assert z_mid == pytest.approx(600.0)
    assert z_hi == pytest.approx(5000.0)
    assert terr < z_low < z_mid < z_hi


def test_zaxis_is_log_with_real_ticks():
    """Terrain + assets share one LOG altitude axis showing real-metre ticks."""
    panel = _panel()
    panel.set_view_mode("iso")
    panel.set_platforms(_platforms(), t_seconds=380.0)
    z = panel.figure().layout.scene.zaxis
    assert z.type == "log"
    assert z.showticklabels is True
    assert list(z.tickvals) == tpm._ISO_ALT_TICKS
    # The terrain Surface carries true elevation (m), not an exaggerated value.
    surf = [t for t in panel.figure().data if type(t).__name__ == "Surface"][0]
    import numpy as _np
    assert 100 < float(_np.min(surf.z)) < float(_np.max(surf.z)) < 700


def test_iso_camera_emitted_every_frame_with_stable_uirevision():
    """The orthographic camera is emitted on EVERY iso frame, with a constant
    scene.uirevision. scene.camera is uirevision-governed, so re-sending the
    same value lets Plotly.react preserve the operator's rotate/zoom while
    keeping the configured orientation as the durable baseline. Omitting it on
    later frames (the prior behavior) made react fall back to Plotly's auto
    default — the configured view flashed once, then reverted."""
    panel = _panel()
    panel.set_view_mode("iso")
    panel.set_platforms(_platforms(), t_seconds=380.0)
    f1 = panel.figure()
    f2 = panel.figure()
    # Both frames carry the camera (no flash-then-revert), with the same eye.
    assert f1.layout.scene.camera.eye.x is not None
    assert f1.layout.scene.camera.projection.type == "orthographic"
    assert f2.layout.scene.camera.eye.x == f1.layout.scene.camera.eye.x
    assert f2.layout.scene.camera.eye.y == f1.layout.scene.camera.eye.y
    assert f2.layout.scene.camera.eye.z == f1.layout.scene.camera.eye.z
    # uirevision is constant so user rotations persist across ticks.
    assert f1.layout.scene.uirevision == f2.layout.scene.uirevision == tpm._ISO_UIREVISION


def test_iso_camera_override_persists_operator_view():
    """Once the operator rotates/zooms, the dashboard captures the live camera
    (graph relayoutData["scene.camera"]) and feeds it via set_iso_camera(); the
    panel then re-emits THAT camera on every subsequent iso render so the view
    persists across live/playback ticks instead of snapping back to the default
    eye. This is the durable fix (uirevision alone did not hold the view)."""
    panel = _panel()
    panel.set_view_mode("iso")
    panel.set_platforms(_platforms(), t_seconds=380.0)
    # Default eye until the operator interacts.
    assert panel.figure().layout.scene.camera.eye.y == tpm._ISO_CAMERA_EYE["y"]
    # Operator orbits the scene -> Plotly emits the live camera in relayoutData.
    operator_cam = {"eye": {"x": 1.5, "y": -0.4, "z": 2.0},
                    "projection": {"type": "orthographic"}}
    panel.set_iso_camera(operator_cam)
    for _ in range(3):  # every later tick keeps the operator's camera
        cam = panel.figure().layout.scene.camera
        assert (cam.eye.x, cam.eye.y, cam.eye.z) == (1.5, -0.4, 2.0)
    # A relayout event without a camera payload (e.g. autosize) must not wipe it.
    panel.set_iso_camera(None)
    assert panel.figure().layout.scene.camera.eye.x == 1.5
    # Re-entering iso re-frames to the default eye (fresh session).
    panel.set_view_mode("2d")
    panel.set_view_mode("iso")
    assert panel.figure().layout.scene.camera.eye.y == tpm._ISO_CAMERA_EYE["y"]


def test_asset_labels_show_altitude():
    """On-plot asset labels carry the (AGL) altitude, matching the height."""
    panel = _panel()
    panel.set_view_mode("iso")
    panel.set_platforms(_platforms(), t_seconds=380.0)
    assets = [t for t in panel.figure().data if t.name == "assets"][0]
    labels = {s.split("<br>")[0]: s for s in assets.text}
    assert "m AGL" in labels["rq86-1"]
    # RQ-86 at 5000 m MSL over ~200 m terrain reads as ~4800 m AGL.
    assert "4,8" in labels["rq86-1"]


def test_far_asset_hidden_until_within_aoi():
    """A far off-AOI asset (the jet's ~12-17 km hold) is NOT pinned to the AOI
    edge: its true position is returned (unclamped) and flagged off-map, and the
    renderer omits it entirely. As it crosses into the AOI on its strike run it
    appears at its true position, so the jet pops into view rather than being
    frozen on the boundary wall."""
    panel = _panel()
    panel.set_view_mode("iso")
    panel._ensure_terrain()
    ext_x, _ = panel._iso_extent
    e_hold, _, _, _, off_hold = panel._asset_z(34.7235, -86.453789, 4572.0, "fighter-jet")
    e_obj, _, _, _, off_obj = panel._asset_z(34.7235, -86.638, 4572.0, "fighter-jet")
    assert off_hold and abs(e_hold) > ext_x        # true (unclamped) pos, off-map
    assert not off_obj and abs(e_obj) < ext_x      # over objective => true pos, on-map
    assert abs(e_hold - e_obj) > 1000.0            # crossing in => moves

    # The off-map jet is omitted from the rendered assets; once inside the AOI
    # (over the objective) it is drawn.
    base = _platforms()
    base["jet-hold"] = {"lat": 34.7235, "lon": -86.453789, "alt": 4572.0,
                        "kind": "fighter-jet", "color": "#C0C0C0"}
    panel.set_platforms(base, t_seconds=380.0)
    assets = [t for t in panel.figure().data if t.name == "assets"][0]
    drawn = {s.split("<br>")[0] for s in assets.text}
    assert "jet-hold" not in drawn                 # off-map => not drawn

    base["jet-hold"]["lon"] = -86.638              # now over the objective
    panel.set_platforms(base, t_seconds=381.0)
    assets = [t for t in panel.figure().data if t.name == "assets"][0]
    drawn = {s.split("<br>")[0] for s in assets.text}
    assert "jet-hold" in drawn                      # within AOI => drawn


def test_terrain_surface_is_sunk_below_true_elevation():
    """The surface renders a bit below true elevation so ground units sit on
    top of it instead of being buried; the colour still keys off true elev."""
    panel = _panel()
    panel.set_view_mode("iso")
    panel._ensure_terrain()
    surf = panel._terrain_trace
    sunk_max = float(surf.z.max())
    true_max = float(panel._terrain_grid.max())
    assert true_max - sunk_max == pytest.approx(tpm._TERRAIN_SINK_M, abs=0.5)


def test_2d_path_unchanged():
    """Default view stays the MapLibre top-down map (regression guard)."""
    panel = _panel()
    panel.set_platforms(_platforms(), t_seconds=380.0)
    fig = panel.figure()              # default mode == "2d"
    assert all(type(t).__name__ == "Scattermap" for t in fig.data)
    assert fig.layout.map is not None
    assert fig.layout.scene.camera.projection.type is None  # no 3D scene


def test_iso_falls_back_to_2d_without_dem(monkeypatch):
    """If the bundled DEM is missing, the iso view degrades to the 2D map
    rather than blanking the panel."""
    monkeypatch.setattr(tpm, "load_terrain", lambda: None)
    panel = _panel()                  # fresh: no cached terrain
    panel.set_view_mode("iso")
    panel.set_platforms(_platforms(), t_seconds=380.0)
    fig = panel.figure()
    assert all(type(t).__name__ == "Scattermap" for t in fig.data)


def test_set_view_mode_rejects_garbage():
    panel = _panel()
    panel.set_view_mode("nonsense")
    assert panel._view_mode == "2d"
    panel.set_view_mode("iso")
    assert panel._view_mode == "iso"
