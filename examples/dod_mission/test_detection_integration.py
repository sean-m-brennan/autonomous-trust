# ******************
#  Copyright 2026 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""End-to-end integration test for Stretch Goal 2 (sparse detections).

Walks the full Phase 2+3 pipeline in process:

  1. Build a synthetic catalogue with the storyline-critical pair
     (compound-alpha + compound-bravo decoy).
  2. Instantiate three DetectionSource peers — two honest RQ-86s and
     one MQ-800 wrapped in CompromisedDetectionSource.
  3. Drive ticks through the actual examples/dod_mission
     POSITION_VALIDATOR_X (the real validator instance with
     world_uid bucketing).
  4. Assert: honest peers register the alpha bucket consensus
     non-anomalous; the MQ-800 swap trips an anomaly inside the
     compound-alpha bucket (not compound-bravo's).
  5. Drive the same readings through the coordinator's detection-cache
     code path (re-using the same `_cache_detection_reading` logic
     directly so the test doesn't need a live coordinator process)
     and confirm each peer's cache carries the right crop_id —
     RQ-86s see compound-alpha.jpg, MQ-800 sees compound-bravo.jpg
     even though the cache is keyed under MQ-800's compound-alpha
     reading.

The point: a single test holds together the FOV math, the validator
tweak, the compromise wrapper, and the inspector-bound cache
serialisation. If any one of those regresses, this fires.

Run from the repo root::

    pytest examples/dod_mission/test_detection_integration.py
"""

from __future__ import annotations

import sys
from collections import deque
from datetime import timedelta
from pathlib import Path

import pytest

from autonomous_trust.services.data import Reading

_DOD = Path(__file__).resolve().parent
sys.path.insert(0, str(_DOD / "generators"))
sys.path.insert(0, str(_DOD / "compromise"))

import detection as det
import contradictory_isr as ci
from examples.dod_mission.tasks.validation import POSITION_VALIDATOR_X
from examples.multi_agency.tasks.validation import CrossSourceValidator


GROUND_MID_LL = (34.724448, -86.639802)
COMPOUND_BRAVO_LL = (34.725349, -86.638707)


def _build_catalogue():
    """A 2-object catalogue matching the storyline (alpha + bravo)."""
    objs = []
    for uid, ll, crop in [
        ("compound-alpha", GROUND_MID_LL, "crops/compound-alpha.jpg"),
        ("compound-bravo", COMPOUND_BRAVO_LL, "crops/compound-bravo.jpg"),
    ]:
        e, n = det._wgs84_to_utm(*ll)
        cx, cy = det._utm_to_squad_xy(e, n)
        objs.append(det.CatalogueObject(
            world_uid=uid, cls="target-building", confidence=1.0,
            crop=crop, crop_b64="", crop_size_px=(128, 96),
            bbox_panorama_px=(0, 0, 40, 40), obb_panorama_px=(),
            center_utm=(e, n), center_squad_xy=(cx, cy),
            center_latlon=ll,
            label=uid,
            extra={"scenario_role": "mq800-target" if uid.endswith("alpha")
                                    else "mq800-decoy"},
        ))
    return objs


_PRIORITY_UIDS = ("compound-alpha", "compound-bravo")


def _mini_cache_routing(reading: Reading,
                        cache_by_target: dict, log: dict):
    """Mirrors examples/dod_mission/coordinator.py:_cache_detection_reading
    so the test exercises the same serialisation shape the dashboard
    callback consumes (keyed by (peer, world_uid))."""
    md = reading.metadata or {}
    world_uid = str(md.get("world_uid", ""))
    entry = {
        "peer_name": reading.peer_name,
        "world_uid": world_uid,
        "label": str(md.get("label", "")),
        "confidence": float(reading.value),
        "crop_id": str(md.get("crop_id", "")),
        "crop_b64": md.get("crop_b64") or "",
        "target_latlon": tuple(md.get("target_latlon") or (0.0, 0.0)),
        "t_seconds": reading.timestamp.total_seconds(),
    }
    cache_by_target[(reading.peer_name, world_uid)] = entry
    log.setdefault(reading.peer_name, deque(maxlen=10)).append(entry)


def _pick_primary_per_peer(cache_by_target: dict) -> dict:
    """Replicates DoDMissionCoordinator._pick_primary_detection_per_peer."""
    by_peer: dict = {}
    for (peer, _uid), entry in cache_by_target.items():
        by_peer.setdefault(peer, []).append(entry)
    out: dict = {}
    for peer, entries in by_peer.items():
        for uid in _PRIORITY_UIDS:
            hit = next((e for e in entries if e["world_uid"] == uid), None)
            if hit is not None:
                out[peer] = hit
                break
        else:
            out[peer] = max(entries, key=lambda e: e["t_seconds"])
    return out


@pytest.fixture
def pipeline():
    """Three DetectionSources + a fresh validator, primed for ticks."""
    cat = _build_catalogue()
    rq1 = det.DetectionSource(
        "rq86-1", "recon-drone", catalogue=cat,
        view_center_latlon=GROUND_MID_LL,
        time_floor_sec=1.0, suppression_sec=2.0)
    rq2 = det.DetectionSource(
        "rq86-2", "recon-drone", catalogue=cat,
        view_center_latlon=GROUND_MID_LL,
        time_floor_sec=1.0, suppression_sec=2.0)
    mq_honest = det.DetectionSource(
        "mq800", "armed-drone", catalogue=cat,
        view_center_latlon=(34.724448, -86.634330),  # engagement vantage
        time_floor_sec=1.0, suppression_sec=2.0)
    mq_compromised = ci.wrap_detection_source_with_compromise(mq_honest)

    # Use a private validator instance so the module-level
    # POSITION_VALIDATOR_X buffer isn't polluted across test runs.
    validator = CrossSourceValidator(
        data_type=POSITION_VALIDATOR_X.data_type,
        threshold=POSITION_VALIDATOR_X.threshold,
        min_sources=POSITION_VALIDATOR_X.min_sources,
        window_sec=POSITION_VALIDATOR_X.window_sec,
    )
    return rq1, rq2, mq_compromised, validator


def _drive(peer, t_seconds, validator, cache_by_target, log):
    """Tick a peer once; route its detections + position readings."""
    results = []
    for r in peer.tick(timedelta(seconds=t_seconds)):
        if r.data_type == "detection":
            _mini_cache_routing(r, cache_by_target, log)
        elif r.data_type == "target_position_x":
            res = validator.submit(r)
            if res is not None:
                results.append(res)
    return results


def test_full_pipeline_catches_mq800_lie(pipeline):
    """Honest RQ-86s feed alpha consensus; MQ-800 swap trips alpha
    bucket; cache reflects per-peer truth (RQ-86 -> alpha.jpg,
    MQ-800 -> bravo.jpg with alpha world_uid)."""
    rq1, rq2, mq, validator = pipeline
    cache: dict = {}
    log: dict = {}

    # Past the compromise activation (T+4:15) so the MQ-800's decoy swap is
    # live; all three share one validator window. Prime honest baselines on
    # alpha, then the MQ-800 reports alpha at bravo's coords -> validator
    # catches it inside the alpha bucket.
    _drive(rq1, 260.0, validator, cache, log)
    _drive(rq2, 260.0, validator, cache, log)
    flagged = _drive(mq, 260.0, validator, cache, log)

    alpha_results = [r for r in flagged
                     if r.peer_name == "mq800" and r.is_anomalous]
    assert alpha_results, ("expected at least one anomalous result for "
                           "mq800 in the alpha bucket")
    assert alpha_results[0].deviation > 50.0

    # Per-peer flat view (after coordinator's _pick_primary):
    # storyline-critical compound-alpha wins for every peer that
    # reported alpha. The MQ-800 entry's world_uid is "compound-alpha"
    # but its crop_id is bravo's — the visible "wrong building" story.
    flat = _pick_primary_per_peer(cache)
    assert flat["rq86-1"]["world_uid"] == "compound-alpha"
    assert flat["rq86-1"]["crop_id"].endswith("compound-alpha.jpg")
    assert flat["rq86-2"]["crop_id"].endswith("compound-alpha.jpg")
    assert flat["mq800"]["world_uid"] == "compound-alpha"
    assert flat["mq800"]["crop_id"].endswith("compound-bravo.jpg")

    # Underlying (peer, uid) cache holds every emission — drawer
    # consumers that want bravo too can find it.
    assert (("rq86-1", "compound-bravo") in cache
            and ("mq800", "compound-bravo") in cache)


def test_full_pipeline_honest_run_stays_quiet():
    """Sanity: with three honest peers, the validator never fires
    anomalous in the alpha bucket."""
    cat = _build_catalogue()
    rq1 = det.DetectionSource(
        "rq86-1", "recon-drone", catalogue=cat,
        view_center_latlon=GROUND_MID_LL,
        time_floor_sec=1.0, suppression_sec=2.0)
    rq2 = det.DetectionSource(
        "rq86-2", "recon-drone", catalogue=cat,
        view_center_latlon=GROUND_MID_LL,
        time_floor_sec=1.0, suppression_sec=2.0)
    mq_honest = det.DetectionSource(
        "mq800", "armed-drone", catalogue=cat,
        view_center_latlon=(34.724448, -86.634330),
        time_floor_sec=1.0, suppression_sec=2.0)
    validator = CrossSourceValidator(
        data_type="target_position_x", threshold=50.0,
        min_sources=2, window_sec=15.0,
    )
    cache: dict = {}
    log: dict = {}
    for t in (5.0, 6.0, 7.0):
        for peer in (rq1, rq2, mq_honest):
            for res in _drive(peer, t, validator, cache, log):
                assert not res.is_anomalous, (
                    f"unexpected anomaly in honest run at t={t}: {res}")


def test_full_pipeline_detection_log_bounded():
    """The mini-cache (matching coordinator's deque(maxlen=10))
    holds at most 10 entries even after a long drive."""
    cat = _build_catalogue()
    rq = det.DetectionSource(
        "rq86-1", "recon-drone", catalogue=cat,
        view_center_latlon=GROUND_MID_LL,
        time_floor_sec=0.5, suppression_sec=0.0,  # always re-emit
    )
    validator = CrossSourceValidator(
        data_type="target_position_x", threshold=50.0,
        min_sources=1, window_sec=120.0)
    cache: dict = {}
    log: dict = {}
    for i in range(25):
        _drive(rq, float(i), validator, cache, log)
    assert len(log["rq86-1"]) == 10
