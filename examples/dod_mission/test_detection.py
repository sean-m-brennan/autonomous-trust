# ******************
#  Copyright 2026 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the SG2 Phase 2 sparse-detection pipeline.

Covers:
  * DetectionSource FOV intersection per role
  * Cadence (time floor) and per-UID suppression
  * MQ-800 CompromisedDetectionSource UID/position swap
  * CrossSourceValidator world_uid bucketing tweak end-to-end

Run from the repo root::

    pytest examples/dod_mission/test_detection.py
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from autonomous_trust.services.data import Reading

_DOD = Path(__file__).resolve().parent
sys.path.insert(0, str(_DOD / "generators"))
sys.path.insert(0, str(_DOD / "compromise"))

import detection as det
import contradictory_isr as ci
from examples.multi_agency.tasks.validation import CrossSourceValidator


# --- Fixtures ----------------------------------------------------------

def _make_catalogue(*objects: tuple[str, float, float, str]) -> list:
    """Synthetic catalogue of (uid, lat, lon, scenario_role)."""
    result = []
    for uid, lat, lon, role in objects:
        e, n = det._wgs84_to_utm(lat, lon)
        cx, cy = det._utm_to_squad_xy(e, n)
        result.append(det.CatalogueObject(
            world_uid=uid, cls="building", confidence=1.0,
            crop=f"crops/{uid}.jpg", crop_b64="",
            crop_size_px=(128, 96),
            bbox_panorama_px=(0, 0, 10, 10),
            obb_panorama_px=(),
            center_utm=(e, n), center_squad_xy=(cx, cy),
            center_latlon=(lat, lon),
            label=uid, extra={"scenario_role": role},
        ))
    return result


# Locations: compound at GROUND_MID, decoy 100m NE, sensor far south
GROUND_MID_LL = (34.724448, -86.639802)
COMPOUND_BRAVO_LL = (34.725349, -86.638707)  # 100m N, 100m E
SQUAD_LL = (34.706505, -86.633657)            # GROUND_START


@pytest.fixture
def catalogue():
    return _make_catalogue(
        ("compound-alpha", *GROUND_MID_LL, "mq800-target"),
        ("compound-bravo", *COMPOUND_BRAVO_LL, "mq800-decoy"),
        ("squad-marker",   *SQUAD_LL,        "squad-start"),
    )


# --- FOV intersection --------------------------------------------------

def test_rq86_sees_entire_ao(catalogue):
    src = det.DetectionSource("rq86-1", "recon-drone",
                              catalogue=catalogue,
                              view_center_latlon=GROUND_MID_LL)
    # 10km square nadir at GROUND_MID covers everything in the 4km AO
    assert set(src.visible_uids) == {"compound-alpha", "compound-bravo",
                                     "squad-marker"}


def test_microdrone_fov_limited_to_350m_forward(catalogue):
    src = det.DetectionSource("microdrone-1", "microdrone",
                              catalogue=catalogue,
                              view_center_latlon=SQUAD_LL)
    # Squad faces north (default); compound at ~2km north is way out
    # of the 350m fwd rectangle, only squad-marker (right under) shows
    assert "squad-marker" in src.visible_uids
    assert "compound-alpha" not in src.visible_uids


def test_mq800_view_center_override(catalogue):
    # Roster position is 3.4km east of AO; without override it's blind
    blind = det.DetectionSource("mq800", "armed-drone",
                                catalogue=catalogue,
                                view_center_latlon=(34.715, -86.580))
    assert blind.visible_uids == []
    # With engagement vantage, it sees both targets
    engaged = det.DetectionSource("mq800", "armed-drone",
                                  catalogue=catalogue,
                                  view_center_latlon=(34.724448, -86.634330))
    assert set(engaged.visible_uids) >= {"compound-alpha", "compound-bravo"}


# --- Cadence + suppression --------------------------------------------

def test_time_floor_gates_rapid_ticks(catalogue):
    src = det.DetectionSource("rq86-1", "recon-drone",
                              catalogue=catalogue,
                              view_center_latlon=GROUND_MID_LL,
                              time_floor_sec=5.0)
    out_a = src.tick(timedelta(seconds=10))
    out_b = src.tick(timedelta(seconds=12))  # < 5s gap
    assert len(out_a) == 3 * 3                # 3 objects * (detection + x + y)
    assert out_b == []


def test_suppression_window_then_heartbeat(catalogue):
    # One-object catalogue makes the suppression branch deterministic.
    cat = _make_catalogue(("compound-alpha", *GROUND_MID_LL, "tgt"))
    src = det.DetectionSource("rq86-1", "recon-drone",
                              catalogue=cat,
                              view_center_latlon=GROUND_MID_LL,
                              time_floor_sec=1.0, suppression_sec=20.0)
    first = src.tick(timedelta(seconds=10))
    assert [r.data_type for r in first] == [
        "detection", "target_position_x", "target_position_y",
    ]
    # 5s later (past floor, within suppression, no position drift) ->
    # nothing new, fall through to heartbeat
    second = src.tick(timedelta(seconds=15))
    assert [r.data_type for r in second] == ["detection_heartbeat"]


def test_drift_overrides_suppression():
    # Stationary in this v1, but verify the drift threshold logic.
    cat = _make_catalogue(("compound-alpha", *GROUND_MID_LL, "tgt"))
    src = det.DetectionSource("rq86-1", "recon-drone",
                              catalogue=cat,
                              view_center_latlon=GROUND_MID_LL,
                              time_floor_sec=1.0, suppression_sec=30.0,
                              drift_threshold_m=25.0)
    src.tick(timedelta(seconds=10))
    # Force the cached position so the next tick's "drift" exceeds 25m
    state = src._emit_state["compound-alpha"]
    state.last_x += 100.0  # simulate object moved 100m east since last obs
    drifted = src.tick(timedelta(seconds=15))
    types = {r.data_type for r in drifted}
    assert "detection" in types  # re-emitted despite suppression window


# --- Compromise --------------------------------------------------------

def test_compromise_swaps_position_and_crop_keeps_uid(catalogue):
    honest = det.DetectionSource("mq800", "armed-drone",
                                 catalogue=catalogue,
                                 view_center_latlon=(34.724448, -86.634330))
    comp = ci.wrap_detection_source_with_compromise(honest)
    out = comp.tick(timedelta(seconds=10))
    by_uid = {}
    for r in out:
        if r.data_type == "detection":
            by_uid[r.metadata["world_uid"]] = r

    # Alpha emission carries bravo's crop_id but keeps the alpha UID
    # so the validator buckets it inside compound-alpha.
    assert by_uid["compound-alpha"].metadata["crop_id"] == "crops/compound-bravo.jpg"

    # Position-typed readings tagged compound-alpha should land at
    # bravo's coordinates, not alpha's.
    bravo_pos_x = next(r for r in out if r.data_type == "target_position_x"
                       and r.metadata["world_uid"] == "compound-bravo").value
    alpha_pos_x = next(r for r in out if r.data_type == "target_position_x"
                       and r.metadata["world_uid"] == "compound-alpha").value
    assert alpha_pos_x == bravo_pos_x


def test_compromise_falls_back_when_decoy_missing():
    # Catalogue without compound-bravo: compromise is inert.
    cat = _make_catalogue(("compound-alpha", *GROUND_MID_LL, "tgt"))
    honest = det.DetectionSource("mq800", "armed-drone",
                                 catalogue=cat,
                                 view_center_latlon=GROUND_MID_LL)
    comp = ci.wrap_detection_source_with_compromise(honest)
    out = comp.tick(timedelta(seconds=10))
    alpha = next(r for r in out if r.data_type == "detection")
    assert alpha.metadata["crop_id"] == "crops/compound-alpha.jpg"


# --- Validator integration --------------------------------------------

def _detection_position_x(peer: str, value: float, uid: str,
                          t_sec: float) -> Reading:
    return Reading(timestamp=timedelta(seconds=t_sec),
                   peer_name=peer, data_type="target_position_x",
                   value=value, unit="m",
                   metadata={"world_uid": uid})


def test_validator_buckets_by_world_uid():
    v = CrossSourceValidator(data_type="target_position_x",
                             threshold=50.0, min_sources=2,
                             window_sec=60.0)
    # Two RQ-86s honest on alpha
    v.submit(_detection_position_x("rq86-1", -570.0, "compound-alpha", 0))
    v.submit(_detection_position_x("rq86-2", -565.0, "compound-alpha", 1))
    # MQ-800 reports compound-bravo at -470 — different bucket, no
    # cross-comparison with alpha.
    isolated = v.submit(_detection_position_x("mq800", -470.0,
                                              "compound-bravo", 2))
    assert isolated is None


def test_validator_catches_mq800_alpha_lie():
    v = CrossSourceValidator(data_type="target_position_x",
                             threshold=50.0, min_sources=2,
                             window_sec=60.0)
    v.submit(_detection_position_x("rq86-1", -570.0, "compound-alpha", 0))
    v.submit(_detection_position_x("rq86-2", -565.0, "compound-alpha", 1))
    # MQ-800 claims alpha but reports bravo's position (100m off)
    lie = v.submit(_detection_position_x("mq800", -470.0,
                                         "compound-alpha", 2))
    assert lie is not None
    assert lie.is_anomalous
    assert lie.deviation > 50.0


def test_three_source_one_liar_does_not_flag_honest_sources():
    """Regression: the degenerate 3-source window (two honest recon + the
    lone rogue) must flag ONLY the rogue, never the honest pair.

    This is the live false-positive that condemned both RQ-86s: once the
    swarm exfiltrates, only rq86-1, rq86-2, and the MQ-800 remain on the
    primary target track. Under the old "median of others" consensus, each
    honest RQ-86 was judged against the average of {other RQ-86, MQ-800},
    dragged ~half the gap toward the lie, so all three tripped the 50 m
    threshold. With the median of ALL sources the honest cluster sets the
    consensus and only the rogue deviates."""
    v = CrossSourceValidator(data_type="target_position_x",
                             threshold=50.0, min_sources=3, window_sec=10.0)
    # Mirrors the real values around the recorded detection (~t+7:20).
    v.submit(_detection_position_x("rq86-1", -213.6, "compound-alpha", 0))
    v.submit(_detection_position_x("rq86-2", -212.5, "compound-alpha", 1))
    rogue = v.submit(_detection_position_x("mq800", 85.9,
                                           "compound-alpha", 2))
    assert rogue is not None and rogue.is_anomalous
    # Re-submit the honest pair now that all three sources are active; they
    # must read clean against the median-of-all consensus.
    h1 = v.submit(_detection_position_x("rq86-1", -213.6, "compound-alpha", 3))
    h2 = v.submit(_detection_position_x("rq86-2", -212.5, "compound-alpha", 4))
    assert h1 is not None and not h1.is_anomalous, h1.deviation
    assert h2 is not None and not h2.is_anomalous, h2.deviation


def test_load_catalogue_inlines_real_crops(tmp_path):
    """Real on-disk catalogue + crops -> crop_b64 populated, metadata
    on a detection Reading carries the base64 bytes."""
    pil = pytest.importorskip("PIL.Image")
    crops_dir = tmp_path / "crops"
    crops_dir.mkdir()
    img = pil.new("RGB", (128, 96), color=(120, 110, 100))
    img.save(crops_dir / "compound-alpha.jpg", format="JPEG", quality=70)
    cat_path = tmp_path / "catalogue.json"
    cat_path.write_text(json.dumps({
        "_schema": "detection-prep/v1",
        "objects": [{
            "world_uid": "compound-alpha",
            "class": "building",
            "confidence": 1.0,
            "crop": "crops/compound-alpha.jpg",
            "bbox_panorama_px": [0, 0, 40, 40],
            "obb_panorama_px": [[0, 0], [40, 0], [40, 40], [0, 40]],
            "bbox_utm_e_n": [532978.0, 3842525.0, 533018.0, 3842565.0],
            "bbox_utm_epsg": 32616,
            "center_lat": 34.724448, "center_lon": -86.639802,
            "ground_truth_label": "alpha",
        }],
    }))
    cat = det.load_catalogue(cat_path)
    assert cat[0].crop_b64
    assert cat[0].center_latlon == (34.724448, -86.639802)

    src = det.DetectionSource("rq86-1", "recon-drone",
                              catalogue=cat,
                              view_center_latlon=(34.724448, -86.639802))
    out = src.tick(timedelta(seconds=10))
    detection = next(r for r in out if r.data_type == "detection")
    assert detection.metadata["crop_b64"] == cat[0].crop_b64
    assert detection.metadata["target_latlon"] == [34.724448, -86.639802]
    assert detection.metadata["bbox_in_crop_px"][2] > 0


def test_agency_map_detection_layer():
    """AgencyMap renders one detection marker + sightline per peer
    and `clear_peer_detection` drops one cleanly."""
    pytest.importorskip("plotly")
    from autonomous_trust.inspector.dashboard.disaster_response_map import (
        AgencyMap, MapPeer)
    m = AgencyMap(agency_colors={"Air-Support": "#D4AF37",
                                 "Unknown-Air": "#C68A3F"})
    for name, agency, kind, lat, lon in [
        ("rq86-1", "Air-Support", "recon-drone", 34.724, -86.639),
        ("rq86-2", "Air-Support", "recon-drone", 34.728, -86.642),
        ("mq800",  "Unknown-Air", "armed-drone", 34.715, -86.580),
    ]:
        m.add_peer(MapPeer(name=name, agency=agency, kind=kind,
                           lat=lat, lon=lon))
    m.set_peer_detection("rq86-1", 34.7244, -86.6398, "compound-alpha")
    m.set_peer_detection("rq86-2", 34.7246, -86.6396, "compound-alpha")
    m.set_peer_detection("mq800",  34.7253, -86.6387, "compound-alpha")
    fig = m.figure()
    names = [t.name for t in fig.data]
    assert "detection-sightlines" in names
    assert "detection-targets" in names

    m.clear_peer_detection("mq800")
    fig2 = m.figure()
    targets = next(t for t in fig2.data if t.name == "detection-targets")
    assert len(targets.lat) == 2


def test_dashboard_helpers_resolve_cached_detection(tmp_path):
    """live_server detection_summary_for / log_for / push_to_agency_map
    bridge the coordinator's serialised cache to the inspector."""
    pytest.importorskip("plotly")
    pytest.importorskip("dash")
    pytest.importorskip("dash_extensions")
    sys.path.insert(0, str(_DOD / "dashboard"))
    import live_server as ls
    from autonomous_trust.inspector.dashboard.disaster_response_map import (
        AgencyMap, MapPeer)

    state = {
        "t_seconds": 50.0,
        "detection_per_peer": {
            "rq86-1": {
                "peer_name": "rq86-1",
                "world_uid": "compound-alpha",
                "label": "target-building",
                "confidence": 0.91,
                "crop_b64": "AAAA",
                "crop_size_px": (128, 96),
                "bbox_in_crop_px": (21, 16, 107, 80),
                "target_latlon": (34.7244, -86.6398),
                "t_seconds": 47.0,
            },
            "mq800": {
                "peer_name": "mq800",
                "world_uid": "compound-alpha",
                "label": "target-building",
                "confidence": 0.95,
                "crop_b64": "BBBB",
                "crop_size_px": (128, 96),
                "bbox_in_crop_px": (21, 16, 107, 80),
                "target_latlon": (34.7253, -86.6387),
                "t_seconds": 18.0,
            },
        },
        "detection_log_per_peer": {
            "rq86-1": [{
                "world_uid": "compound-alpha", "label": "tb",
                "confidence": 0.9, "crop_b64": "AAAA",
                "crop_size_px": (128, 96),
                "bbox_in_crop_px": (21, 16, 107, 80),
                "target_latlon": (34.7244, -86.6398),
                "t_seconds": 30.0,
            }],
        },
    }
    rq_sum = ls.detection_summary_for(state, "rq86-1")
    assert rq_sum.world_uid == "compound-alpha"
    assert abs(rq_sum.age_sec - 3.0) < 0.01
    mq_sum = ls.detection_summary_for(state, "mq800")
    assert abs(mq_sum.age_sec - 32.0) < 0.01  # stale (>30)

    log = ls.detection_log_for(state, "rq86-1")
    assert len(log) == 1
    assert abs(log[0].age_sec - 20.0) < 0.01

    m = AgencyMap(agency_colors={"Air-Support": "#D4AF37",
                                 "Unknown-Air": "#C68A3F"})
    m.add_peer(MapPeer(name="rq86-1", agency="Air-Support",
                       kind="recon-drone", lat=34.724, lon=-86.639))
    m.add_peer(MapPeer(name="mq800", agency="Unknown-Air",
                       kind="armed-drone", lat=34.715, lon=-86.580))
    ls.push_detections_to_agency_map(m, state)
    assert "rq86-1" in m._detections
    assert "mq800" in m._detections
    # Cache-evicted peer -> marker cleared
    state["detection_per_peer"].pop("mq800")
    ls.push_detections_to_agency_map(m, state)
    assert "mq800" not in m._detections


def test_render_peer_drawer_iframe_doc():
    """live_server._render_peer_drawer wraps PeerDetailPanel output in
    a self-contained HTML doc for Iframe srcDoc consumption."""
    pytest.importorskip("plotly")
    pytest.importorskip("dash")
    pytest.importorskip("dash_extensions")
    sys.path.insert(0, str(_DOD / "dashboard"))
    import live_server as ls

    state = {
        "t_seconds": 50.0,
        # jet-1 is a pre-established peer with no consensus reputation yet
        # (None) -- the Reputations list shows "forming…" for it.
        "reputations": {"mq800": 0.2, "rq86-1": 0.95, "jet-1": None},
        "tiers": {"mq800": 2, "rq86-1": 2, "jet-1": 0},
        "agencies": {"mq800": "Unknown-Air", "rq86-1": "Air-Support",
                     "jet-1": "Air-Support"},
        "kinds": {"mq800": "armed-drone", "rq86-1": "recon-drone",
                  "jet-1": "fighter"},
        "detection_per_peer": {
            "mq800": {
                "world_uid": "compound-alpha", "label": "target-building",
                "confidence": 0.95, "crop_b64": "BBBB",
                "crop_size_px": (128, 96),
                "bbox_in_crop_px": (21, 16, 107, 80),
                "target_latlon": (34.7253, -86.6387),
                "t_seconds": 47.0,
            },
        },
    }
    doc = ls._render_peer_drawer(state, "mq800")
    assert doc.startswith("<!DOCTYPE html>")
    # Header reflects compromised status (reputation 0.2 -> compromised)
    assert "COMPROMISED" in doc.upper()
    # Detection section emitted with our world_uid
    assert "compound-alpha" in doc
    # A forming peer (None score) must not crash float() and must read as
    # onboarding/forming -- matching the Reputations list -- never compromised.
    forming_doc = ls._render_peer_drawer(state, "jet-1")
    assert forming_doc.startswith("<!DOCTYPE html>")
    assert "forming…" in forming_doc
    assert "COMPROMISED" not in forming_doc.upper()
    # Empty peer -> placeholder document
    placeholder = ls._render_peer_drawer({}, "mq800")
    assert "<!DOCTYPE" in placeholder


def test_drawer_renders_detection_section():
    """PeerDetailPanel.to_html renders the SG2 detection section with
    bbox SVG, confidence + UID, and dims to STALE past 30s."""
    from autonomous_trust.inspector.dashboard.peer_detail import (
        DetectionSummary, PeerDetailPanel, PeerDetailState,
    )
    d = DetectionSummary(
        crop_b64="dGVzdA==", crop_size_px=(128, 96),
        bbox_in_crop_px=(21, 16, 107, 80),
        label="compound-alpha", world_uid="compound-alpha",
        confidence=0.87, age_sec=4.5,
    )
    html = PeerDetailPanel().to_html(PeerDetailState(
        name="rq86-1", agency="Air-Support", kind="recon-drone",
        detection=d, detection_log=[d, d]))
    assert "compound-alpha" in html
    assert "conf 0.87" in html
    assert '<rect x="21"' in html

    # Stale: opacity dim + STALE banner
    stale = DetectionSummary(**{**d.__dict__, "age_sec": 60.0})
    html_stale = PeerDetailPanel().to_html(PeerDetailState(
        name="rq86-1", agency="Air-Support", kind="recon-drone",
        detection=stale))
    assert "STALE" in html_stale
    assert 'opacity="0.4"' in html_stale

    # Active-no-contacts placeholder
    html_empty = PeerDetailPanel().to_html(PeerDetailState(
        name="rq86-1", agency="Air-Support", kind="recon-drone",
        detection=DetectionSummary()))
    assert "no contacts" in html_empty


def test_drawer_renders_obb_polygon_when_present():
    """When the detection carries an oriented box, the drawer draws a
    rotated <polygon> (not the axis-aligned <rect>)."""
    from autonomous_trust.inspector.dashboard.peer_detail import (
        DetectionSummary, PeerDetailPanel, PeerDetailState,
    )
    d = DetectionSummary(
        crop_b64="dGVzdA==", crop_size_px=(128, 96),
        bbox_in_crop_px=(21, 16, 107, 80),
        obb_in_crop_px=((30, 16), (107, 30), (98, 80), (21, 66)),
        label="compound-alpha", world_uid="compound-alpha",
        confidence=0.87, age_sec=4.5,
    )
    html = PeerDetailPanel().to_html(PeerDetailState(
        name="rq86-1", agency="Air-Support", kind="recon-drone",
        detection=d))
    assert "<polygon points=" in html
    assert "30,16" in html and "107,30" in html
    # OBB takes precedence over the axis-aligned rect.
    assert '<rect x="21"' not in html


def test_peer_detail_forming_reputation_matches_list():
    """A peer with no consensus reputation yet renders 'forming…' (the
    same wording the Reputations list shows for a None score), not a
    numeric score that would read as compromised at 0.00."""
    from autonomous_trust.inspector.dashboard.peer_detail import (
        PeerDetailPanel, PeerDetailState, ReputationSnapshot,
    )
    forming_html = PeerDetailPanel().to_html(PeerDetailState(
        name="jet-1", agency="Air", kind="fighter", status="onboarding",
        reputation=ReputationSnapshot(current_score=0.0, forming=True)))
    assert "forming…" in forming_html
    assert "awaiting consensus" in forming_html
    # A forming peer must NOT read as compromised in the drawer.
    assert "COMPROMISED" not in forming_html.upper()

    # The numeric (non-forming) path is unchanged: low score still shows
    # the score and a red/compromised treatment.
    numeric_html = PeerDetailPanel().to_html(PeerDetailState(
        name="mq800", agency="X", kind="drone", status="compromised",
        reputation=ReputationSnapshot(current_score=0.2)))
    assert "0.20" in numeric_html
    assert "forming" not in numeric_html


def test_validator_backward_compat_for_metadata_less_reading():
    v = CrossSourceValidator(data_type="temperature", threshold=5.0,
                             min_sources=2, window_sec=60.0)
    td = timedelta
    v.submit(Reading(td(seconds=0), "noaa-1", "temperature", 20.0, "C"))
    v.submit(Reading(td(seconds=1), "noaa-2", "temperature", 21.0, "C"))
    res = v.submit(Reading(td(seconds=2), "noaa-3", "temperature", 30.0, "C"))
    # metadata-less readings still bucket together and validate. Consensus is
    # the median of ALL sources {20, 21, 30} = 21, so the 30 C outlier
    # deviates by 9.0 (was 9.5 under the old median-of-others). Still anomalous.
    assert res.is_anomalous and abs(res.deviation - 9.0) < 0.01


class _FakeBundleForPickle:
    """Module-level so pickle can resolve it during the regression test
    below (closure-scoped classes aren't picklable)."""
    def __init__(self):
        self.target_x = 1.23
        self.electronic_noise = 0.05
    def tick(self, t):
        return [("x", t)]


class _FakeDSForPickle:
    def tick(self, t):
        return []


def test_detection_augmented_bundle_survives_pickle():
    """Regression: multiprocessing rehydration in a worker pool used to
    blow up with ``RecursionError: maximum recursion depth exceeded``
    because ``__getattr__`` accessed ``self._bundle`` before pickle had
    populated ``__dict__``. The unpickle-safe guard reads via
    ``self.__dict__.get('_bundle')`` so the not-yet-populated state
    raises ``AttributeError`` cleanly. See participant.py:120-129."""
    import pickle
    sys.path.insert(0, str(_DOD))
    from participant import _DetectionAugmentedBundle  # noqa: E402

    orig = _DetectionAugmentedBundle(_FakeBundleForPickle(), _FakeDSForPickle())
    back = pickle.loads(pickle.dumps(orig))
    # Delegated attribute access works after unpickling.
    assert back.target_x == 1.23
    assert back.electronic_noise == 0.05
    # tick() composes both producers — proves the wrapper isn't broken.
    assert back.tick(7) == [("x", 7)]


# --- Link-degradation model (§5.5) ------------------------------------

def _count_by_type(readings, data_type):
    return sum(1 for r in readings if r.data_type == data_type)


def test_degradation_tier_mapping():
    # Boundary checks against §5.5's four tiers.
    assert det._degradation_tier(0.95) == (det.DEGRADE_PASS, 0.95)
    assert det._degradation_tier(0.80) == (det.DEGRADE_PASS, 0.95)
    assert det._degradation_tier(0.79) == (det.DEGRADE_DOWNSAMPLE, 0.7)
    assert det._degradation_tier(0.50) == (det.DEGRADE_DOWNSAMPLE, 0.7)
    assert det._degradation_tier(0.49) == (det.DEGRADE_DROP, 0.4)
    assert det._degradation_tier(0.20) == (det.DEGRADE_DROP, 0.4)
    assert det._degradation_tier(0.19) == (det.DEGRADE_LOST, 0.1)
    assert det._degradation_tier(0.0) == (det.DEGRADE_LOST, 0.1)


def test_pass_through_full_quality(catalogue):
    src = det.DetectionSource("rq86-1", "recon-drone", catalogue=catalogue,
                              view_center_latlon=GROUND_MID_LL,
                              link_quality=0.95)
    assert src.degrade_tier == det.DEGRADE_PASS
    readings = src.tick(timedelta(seconds=10))
    dets = [r for r in readings if r.data_type == "detection"]
    assert dets and all(abs(r.quality - 0.95) < 1e-9 for r in dets)


def test_link_lost_suppresses_detections(catalogue):
    src = det.DetectionSource("rq86-1", "recon-drone", catalogue=catalogue,
                              view_center_latlon=GROUND_MID_LL,
                              link_quality=0.1)
    assert src.degrade_tier == det.DEGRADE_LOST
    readings = src.tick(timedelta(seconds=10))
    # Only a heartbeat fires, flagged link_lost; no detection events.
    assert _count_by_type(readings, "detection") == 0
    hbs = [r for r in readings if r.data_type == "detection_heartbeat"]
    assert len(hbs) == 1
    assert hbs[0].metadata["link_lost"] is True
    assert hbs[0].metadata["degradation"] == det.DEGRADE_LOST


def test_reading_quality_reflects_downsample_tier(catalogue):
    src = det.DetectionSource("rq86-1", "recon-drone", catalogue=catalogue,
                              view_center_latlon=GROUND_MID_LL,
                              link_quality=0.6)
    assert src.degrade_tier == det.DEGRADE_DOWNSAMPLE
    readings = src.tick(timedelta(seconds=10))
    dets = [r for r in readings if r.data_type == "detection"]
    assert dets and all(abs(r.quality - 0.7) < 1e-9 for r in dets)
    assert all(r.metadata["degradation"] == det.DEGRADE_DOWNSAMPLE
               for r in dets)
    assert all(abs(r.metadata["link_quality"] - 0.6) < 1e-9 for r in dets)


def test_degraded_link_drops_one_in_three(catalogue):
    # rq86 sees all three catalogue objects; the per-contact drop counter
    # advances 1,2,3 within the tick and drops the third (counter % 3 == 0).
    src = det.DetectionSource("rq86-1", "recon-drone", catalogue=catalogue,
                              view_center_latlon=GROUND_MID_LL,
                              link_quality=0.3)
    assert src.degrade_tier == det.DEGRADE_DROP
    readings = src.tick(timedelta(seconds=10))
    # 3 visible, 1 dropped → 2 detection events, each quality 0.4.
    assert _count_by_type(readings, "detection") == 2
    dets = [r for r in readings if r.data_type == "detection"]
    assert all(abs(r.quality - 0.4) < 1e-9 for r in dets)


def _real_crop_b64(w=128, h=96):
    """A real JPEG crop encoded as base64, for transform tests."""
    PIL = pytest.importorskip("PIL")
    from PIL import Image
    import base64 as _b64
    import io as _io
    img = Image.new("RGB", (w, h), (120, 160, 90))
    buf = _io.BytesIO()
    img.save(buf, format="JPEG")
    return _b64.b64encode(buf.getvalue()).decode("ascii"), (w, h)


def test_downsample_resizes_crop_bytes():
    pytest.importorskip("PIL")
    crop_b64, size = _real_crop_b64()
    obj = det.CatalogueObject(
        world_uid="compound-alpha", cls="building", confidence=0.9,
        crop="crops/alpha.jpg", crop_b64=crop_b64, crop_size_px=size,
        bbox_panorama_px=(0, 0, 10, 10), obb_panorama_px=(),
        center_utm=det._wgs84_to_utm(*GROUND_MID_LL),
        center_squad_xy=det._utm_to_squad_xy(*det._wgs84_to_utm(*GROUND_MID_LL)),
        center_latlon=GROUND_MID_LL, label="alpha", extra={})
    src = det.DetectionSource("rq86-1", "recon-drone", catalogue=[obj],
                              view_center_latlon=GROUND_MID_LL,
                              link_quality=0.6)
    dets = [r for r in src.tick(timedelta(seconds=10))
            if r.data_type == "detection"]
    assert len(dets) == 1
    assert dets[0].metadata["crop_size_px"] == [64, 48]
    assert dets[0].metadata["crop_b64"] != crop_b64  # actually transformed


# --- OBB (oriented box) in crop coords --------------------------------

def test_obb_in_crop_transform():
    # Axis-aligned OBB corners with a 1:1 crop scale map to the inner rect
    # left after the 20% bake-out margin.
    obb = ((100, 100), (200, 100), (200, 200), (100, 200))
    pts = det._obb_in_crop(obb, (100, 100, 200, 200), (140, 140))
    assert pts == [[20, 20], [120, 20], [120, 120], [20, 120]]
    # Unusable inputs degrade to [].
    assert det._obb_in_crop((), (0, 0, 10, 10), (128, 96)) == []
    assert det._obb_in_crop(obb, (100, 100, 200, 200), (0, 0)) == []


def test_emit_includes_obb_in_crop():
    obj = det.CatalogueObject(
        world_uid="compound-alpha", cls="building", confidence=0.9,
        crop="crops/a.jpg", crop_b64="", crop_size_px=(128, 96),
        bbox_panorama_px=(100, 100, 200, 200),
        obb_panorama_px=((110, 100), (200, 110), (190, 200), (100, 190)),
        center_utm=det._wgs84_to_utm(*GROUND_MID_LL),
        center_squad_xy=det._utm_to_squad_xy(*det._wgs84_to_utm(*GROUND_MID_LL)),
        center_latlon=GROUND_MID_LL, label="alpha", extra={})
    src = det.DetectionSource("rq86-1", "recon-drone", catalogue=[obj],
                              view_center_latlon=GROUND_MID_LL,
                              link_quality=0.95)
    dets = [r for r in src.tick(timedelta(seconds=10))
            if r.data_type == "detection"]
    assert len(dets) == 1
    obb_pts = dets[0].metadata["obb_in_crop_px"]
    assert len(obb_pts) == 4 and all(len(p) == 2 for p in obb_pts)
    # Rotated box is NOT an axis-aligned rectangle (corners differ in both x,y).
    xs = {p[0] for p in obb_pts}
    ys = {p[1] for p in obb_pts}
    assert len(xs) > 2 and len(ys) > 2


# --- Map click-to-select (dropdown alternative) -----------------------

def test_map_peer_markers_carry_customdata():
    """TargetPositionMapPanel tags each peer marker with customdata=[name]
    so a map click can resolve to a drawer selection."""
    pytest.importorskip("plotly")
    sys.path.insert(0, str(_DOD / "dashboard"))
    import target_position_map as tpm

    panel = tpm.TargetPositionMapPanel({"rq86-1": "#1FB8CD"})
    for dt, val in (("target_position_x", 120.0), ("target_position_y", 340.0)):
        panel.add_reading(Reading(
            timestamp=timedelta(seconds=10), peer_name="rq86-1",
            data_type=dt, value=val, unit="m", quality=0.95,
            metadata={"world_uid": "compound-alpha"}))
    fig = panel.figure()
    customs = []
    for tr in fig.data:
        cd = getattr(tr, "customdata", None)
        if cd is not None:
            customs.extend(list(cd))
    assert "rq86-1" in customs


def test_peer_from_map_click_resolves_customdata():
    """live_server._peer_from_map_click pulls the peer name out of a marker
    click and returns None for non-peer geometry."""
    pytest.importorskip("dash")
    pytest.importorskip("dash_extensions")
    sys.path.insert(0, str(_DOD / "dashboard"))
    import live_server as ls

    # Peer marker click → peer name.
    click = {"points": [{"customdata": ["mq800"], "lat": 34.7, "lon": -86.6}]}
    assert ls._peer_from_map_click(click) == "mq800"
    # Scalar customdata also accepted.
    assert ls._peer_from_map_click(
        {"points": [{"customdata": "rq86-1"}]}) == "rq86-1"
    # Non-peer geometry / empty / malformed → None (selection untouched).
    assert ls._peer_from_map_click({"points": [{"lat": 1.0}]}) is None
    assert ls._peer_from_map_click({"points": []}) is None
    assert ls._peer_from_map_click(None) is None


# --- Simulator-driven peer motion (pose provider) ----------------------

def test_update_pose_recomputes_visibility(catalogue):
    # A microdrone parked at the squad start can't see the compound 2km N.
    src = det.DetectionSource("microdrone-1", "microdrone",
                              catalogue=catalogue, view_center_latlon=SQUAD_LL)
    assert "compound-alpha" not in src.visible_uids
    # Advance it north to the objective — the compound enters its FOV.
    changed = src.update_pose(GROUND_MID_LL)
    assert changed is True
    assert "compound-alpha" in src.visible_uids
    # Re-applying the same pose is a no-op (no needless FOV recompute).
    assert src.update_pose(GROUND_MID_LL) is False


def test_pose_provider_drives_motion_in_tick(catalogue):
    # The pose provider feeds the live position each tick; once it places the
    # microdrone over the objective, it detects the compound.
    pose = {"ll": SQUAD_LL}
    src = det.DetectionSource(
        "microdrone-1", "microdrone", catalogue=catalogue,
        view_center_latlon=SQUAD_LL,
        pose_provider=lambda: (pose["ll"][0], pose["ll"][1]))
    # Still at the squad start: no compound detection.
    early = src.tick(timedelta(seconds=10))
    early_uids = {r.metadata.get("world_uid") for r in early
                  if r.data_type == "detection"}
    assert "compound-alpha" not in early_uids
    # Drone advances to the objective; next tick (past the time floor) sees it.
    pose["ll"] = GROUND_MID_LL
    late = src.tick(timedelta(seconds=20))
    late_uids = {r.metadata.get("world_uid") for r in late
                 if r.data_type == "detection"}
    assert "compound-alpha" in late_uids


def test_pose_provider_failure_keeps_last_pose(catalogue):
    # A flaky pose source must not crash the sensor loop.
    def _boom():
        raise RuntimeError("sim feed dropped")
    src = det.DetectionSource("rq86-1", "recon-drone", catalogue=catalogue,
                              view_center_latlon=GROUND_MID_LL,
                              pose_provider=_boom)
    out = src.tick(timedelta(seconds=10))  # must not raise
    assert any(r.data_type == "detection" for r in out)


def _haversine_m(ll_a, ll_b):
    import math
    (la1, lo1), (la2, lo2) = ll_a, ll_b
    la1, la2 = math.radians(la1), math.radians(la2)
    dla, dlo = la2 - la1, math.radians(lo2 - lo1)
    h = (math.sin(dla / 2) ** 2
         + math.cos(la1) * math.cos(la2) * math.sin(dlo / 2) ** 2)
    return 2 * 6371000.0 * math.asin(math.sqrt(h))


def _pose_stub(peer_name="microdrone-1"):
    """Minimal stand-in for a DoDMissionParticipant carrying just the
    attributes _detection_pose_provider reads, so we can exercise the wiring
    without the participant's full identity/worker startup."""
    from scenario import DoDMissionScenario

    class _Stub:
        pass
    stub = _Stub()
    stub.scenario = DoDMissionScenario()
    stub.peer_name = peer_name
    stub._t0_epoch = 0.0
    return stub


def test_microdrone_live_motion_wired_on_by_default():
    # The participant wires live microdrone motion on by default: the pose
    # provider replays this peer's scenario path, carrying it from the
    # insertion LZ (~km from the objective) to the objective hold (~tens of m)
    # as scenario time advances.
    import time as _time
    sys.path.insert(0, str(_DOD))
    from participant import DoDMissionParticipant
    from scenario import GROUND_MID  # the squad's actual objective (lat,lon,alt)

    objective_ll = (GROUND_MID[0], GROUND_MID[1])
    stub = _pose_stub()

    def _pose_at(scenario_secs):
        # The closure captures _t0_epoch; epoch = now - t lands the replay at t.
        stub._t0_epoch = _time.time() - scenario_secs
        prov = DoDMissionParticipant._detection_pose_provider(
            stub, "microdrone", SQUAD_LL)
        assert prov is not None
        return prov()

    lz = _pose_at(0.0)
    hold = _pose_at(210.0)
    assert lz is not None and hold is not None
    assert _haversine_m(lz, objective_ll) > 1000     # still at the LZ
    assert _haversine_m(hold, objective_ll) < 100     # converged on objective


def test_pose_provider_scoping_and_optout(monkeypatch):
    # Non-microdrone roles keep the stationary roster pose; an explicit
    # instance provider wins; AT_DETECTION_LIVE_MOTION=0 opts out.
    sys.path.insert(0, str(_DOD))
    from participant import DoDMissionParticipant

    stub = _pose_stub()
    assert DoDMissionParticipant._detection_pose_provider(
        stub, "recon-drone", GROUND_MID_LL) is None

    sentinel = lambda: (1.0, 2.0)  # noqa: E731
    stub._pose_provider = sentinel
    assert DoDMissionParticipant._detection_pose_provider(
        stub, "microdrone", SQUAD_LL) is sentinel

    stub2 = _pose_stub()
    monkeypatch.setenv("AT_DETECTION_LIVE_MOTION", "0")
    assert DoDMissionParticipant._detection_pose_provider(
        stub2, "microdrone", SQUAD_LL) is None
