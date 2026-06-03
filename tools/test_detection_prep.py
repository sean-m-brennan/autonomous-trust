"""Unit tests for the Pass A (real YOLOv8-OBB) algorithmic core.

These cover the parts of ``detection_prep.py`` that run without torch /
ultralytics / Pillow: tiling, OBB→AABB reduction, IoU, cross-tile NMS, and the
per-tile coordinate stitching. The model load + image read + ``model.predict``
themselves need the heavy conda env and are exercised on the operator's side;
everything that decides *where* a detection lands and *whether* it survives
de-duplication is verified here.

Run: ``pytest tools/test_detection_prep.py``
"""
import sys
from pathlib import Path

import numpy as np
import pytest

# Make the import work whether pytest is run from tools/ or the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import detection_prep as dp


# ---- _iter_tiles --------------------------------------------------------

def test_iter_tiles_covers_full_image_with_overlap():
    tiles = list(dp._iter_tiles(2048, 1024, tile_size=1024, overlap=128))
    # Tiles never run past the image bounds.
    for x1, y1, x2, y2 in tiles:
        assert 0 <= x1 < x2 <= 2048
        assert 0 <= y1 < y2 <= 1024
    # Right and bottom edges are reached (last tile flush to the far edge).
    assert max(t[2] for t in tiles) == 2048
    assert max(t[3] for t in tiles) == 1024


def test_iter_tiles_last_start_within_one_tile_of_edge():
    # With step = tile_size - overlap, the largest start is always >= W -
    # tile_size, so the last (clamped) tile already reaches the far edge and
    # the flush-append branch stays defensive. Assert that invariant rather
    # than expecting an extra column the stride never needs.
    for width in (1300, 1500, 2200, 3000, 4096):
        tiles = list(dp._iter_tiles(width, 1024, tile_size=1024, overlap=128))
        last_start = max(t[0] for t in tiles)
        assert last_start >= width - 1024
        assert max(t[2] for t in tiles) == width   # far edge fully covered


def test_iter_tiles_image_smaller_than_tile():
    tiles = list(dp._iter_tiles(400, 300, tile_size=1024, overlap=128))
    assert tiles == [(0, 0, 400, 300)]


def test_iter_tiles_overlap_not_smaller_than_size_raises():
    with pytest.raises(ValueError):
        list(dp._iter_tiles(2048, 2048, tile_size=512, overlap=512))


# ---- _obb_to_aabb -------------------------------------------------------

def test_obb_to_aabb_rotated_box():
    # A diamond (rotated square) centred at (10, 10).
    corners = [(10, 0), (20, 10), (10, 20), (0, 10)]
    assert dp._obb_to_aabb(corners) == (0, 0, 20, 20)


# ---- _aabb_iou ----------------------------------------------------------

def test_aabb_iou_identical_is_one():
    box = (0, 0, 10, 10)
    assert dp._aabb_iou(box, box) == pytest.approx(1.0)


def test_aabb_iou_disjoint_is_zero():
    assert dp._aabb_iou((0, 0, 10, 10), (20, 20, 30, 30)) == 0.0


def test_aabb_iou_partial_overlap():
    # Two 10x10 boxes overlapping in a 5x5 corner: inter=25, union=175.
    iou = dp._aabb_iou((0, 0, 10, 10), (5, 5, 15, 15))
    assert iou == pytest.approx(25 / 175, rel=1e-6)


def test_aabb_iou_edge_touch_is_zero():
    # Sharing only an edge => no positive-area intersection.
    assert dp._aabb_iou((0, 0, 10, 10), (10, 0, 20, 10)) == 0.0


# ---- _nms ---------------------------------------------------------------

def _det(cls, conf, aabb):
    return {"class": cls, "confidence": conf, "aabb": aabb}


def test_nms_suppresses_lower_conf_same_class_overlap():
    high = _det("building", 0.9, (0, 0, 10, 10))
    low = _det("building", 0.6, (1, 1, 11, 11))   # ~0.68 IoU with high
    kept = dp._nms([low, high], iou_threshold=0.45)
    assert kept == [high]


def test_nms_keeps_overlapping_different_classes():
    a = _det("building", 0.9, (0, 0, 10, 10))
    b = _det("vehicle", 0.8, (1, 1, 11, 11))
    kept = dp._nms([a, b], iou_threshold=0.45)
    assert {d["class"] for d in kept} == {"building", "vehicle"}


def test_nms_keeps_same_class_when_below_threshold():
    a = _det("building", 0.9, (0, 0, 10, 10))
    b = _det("building", 0.8, (8, 8, 18, 18))   # small IoU
    kept = dp._nms([a, b], iou_threshold=0.45)
    assert len(kept) == 2


def test_nms_output_sorted_by_confidence_desc():
    dets = [_det("a", 0.3, (0, 0, 1, 1)),
            _det("b", 0.9, (10, 10, 11, 11)),
            _det("c", 0.6, (20, 20, 21, 21))]
    kept = dp._nms(dets, iou_threshold=0.45)
    confs = [d["confidence"] for d in kept]
    assert confs == sorted(confs, reverse=True)


# ---- _stitch_obb_corners ------------------------------------------------

NAMES = {0: "building", 1: "vehicle"}


def test_stitch_applies_tile_offset_to_corners():
    # One axis-aligned box at tile-local (0,0)-(10,10), tile offset (100, 200).
    corners_batch = np.array([[[0, 0], [10, 0], [10, 10], [0, 10]]], dtype=float)
    confs = np.array([0.8])
    clses = np.array([0])
    out = dp._stitch_obb_corners(corners_batch, confs, clses, 100, 200, NAMES)
    assert len(out) == 1
    det = out[0]
    assert det["class"] == "building"
    assert det["confidence"] == pytest.approx(0.8)
    # Corners shifted into panorama space.
    assert det["obb"] == [(100.0, 200.0), (110.0, 200.0),
                          (110.0, 210.0), (100.0, 210.0)]
    assert det["aabb"] == (100.0, 200.0, 110.0, 210.0)


def test_stitch_unknown_class_index_falls_back_to_string():
    corners_batch = np.array([[[0, 0], [1, 0], [1, 1], [0, 1]]], dtype=float)
    out = dp._stitch_obb_corners(corners_batch, np.array([0.5]),
                                 np.array([7]), 0, 0, NAMES)
    assert out[0]["class"] == "7"


def test_stitch_empty_batch_returns_empty():
    empty = np.zeros((0, 4, 2), dtype=float)
    out = dp._stitch_obb_corners(empty, np.zeros((0,)), np.zeros((0,), int),
                                 50, 50, NAMES)
    assert out == []


def test_stitch_multiple_boxes_preserved():
    corners_batch = np.array([
        [[0, 0], [2, 0], [2, 2], [0, 2]],
        [[5, 5], [9, 5], [9, 9], [5, 9]],
    ], dtype=float)
    out = dp._stitch_obb_corners(corners_batch, np.array([0.9, 0.7]),
                                 np.array([0, 1]), 10, 10, NAMES)
    assert [d["class"] for d in out] == ["building", "vehicle"]
    assert out[0]["aabb"] == (10.0, 10.0, 12.0, 12.0)
    assert out[1]["aabb"] == (15.0, 15.0, 19.0, 19.0)
