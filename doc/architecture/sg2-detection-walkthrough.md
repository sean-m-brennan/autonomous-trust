*Previous: [Adversarial testing](adversarial-testing.md)*

# Stretch goal 2 walkthrough: sparse detection events

A demo viewer's tour of the DoD mission `dod_mission` scenario after Stretch
Goal 2 landed, focused on the MQ-800 deception story and how the inspector now
makes it visible.

> The plan this walkthrough implements is tracked in [`ISSUES.md`](../../ISSUES.md).
> Status memory: [`project-stretch-goal-2-pivot`](../../.claude/memory/project_stretch_goal_2_pivot.md)
> Code locations summarised at the end of this doc.

---

## 1. The story in one paragraph

A US Army squad (ODA team, four operators) advances on a target compound in
Madison County, Alabama. Two friendly RQ-86 recon drones orbit overhead; four
squad-launched microdrones sweep ahead; three leave-behind seismic/acoustic
sensors are scattered along the approach route. At T+4:00, an MQ-800 armed drone
arrives. It is compromised: its ISR pipeline reports detections under the honest
`compound-alpha` label but with `compound-bravo`'s coordinates and imagery. The
autonomous-trust network catches the lie inside the `compound-alpha`
cross-source bucket, drops the MQ-800's reputation below threshold, excludes it
from the cohort, and lets the squad strike the *real* target with the F-22's
verified weapon-release authorization.

What's new in Stretch Goal 2: **the operator sees the lie**. Before SG2, the
contradiction lived only as a number drift on the trust timeline. After SG2, the
inspector drawer for the MQ-800 shows a JPEG of compound-bravo while the RQ-86s'
drawers show compound-alpha. The map's sightlines diverge visibly.

---

## 2. The data the demo runs on

A one-off offline pass builds the detection catalogue:

```text
$ python -m tools.naip_fetch                  # ~10 MB NAIP panorama
$ python -m tools.detection_prep              # 17 thumbnails + JSON
# (add --no-real-detector to skip YOLOv8 and use overlay objects only)
```

Outputs land under `examples/dod_mission/assets/`:

* `video/naip_huntsville.jpg`: 4096×4096 px, 1 m/px, USDA-public
 domain aerial imagery of Huntsville, AL, centred on
 `(34.724448°N, -86.639802°W)` (the RQ-86 orbit centre + true target).
* `detections/catalogue.json`: 17 entries: the 6 hand-authored
 scenario-overlay objects (`compound-alpha`, `compound-bravo` decoy
 ~141 m NE, three sensor sites along the squad approach, two hacked,
 one clean, and an `insertion-zone` at the squad's start point) plus
 11 YOLOv8-OBB detections. With `--no-real-detector` the count drops
 to the 6 overlay-only objects and the storyline still runs end-to-end.
* `detections/crops/*.jpg`: 128×96 per-object thumbnails.
* `detections/overlay.json`: the hand-authored input
 (committed; everything else is regenerated on first run).

![catalogue overlay on Huntsville panorama](_generated/sg2/catalogue_overlay.jpg)

The red ring is `compound-alpha` (the MQ-800's true target). The orange ring is
`compound-bravo` (the decoy the compromised MQ-800 reports instead). Magenta
rings are hacked leave-behind sensors; cyan is the clean one. Lime at the bottom
is the squad insertion zone. Yellow rectangles are YOLOv8-OBB finds: mostly
suburbia-class false positives (the DOTA model wasn't tuned for Huntsville),
kept in the catalogue because `DetectionSource` keys off `world_uid` and the six
named scenario-overlay objects drive the trust story.

---

## 3. Phase-by-phase, what the operator sees

The dashboard is a Dash app on `:8050`. The right-hand column has
**Reputations**, **Event Log**, and the new **Peer Detail** drawer driven by a
peer-name dropdown.

### T+0:00: setup

Squad + microdrones + RQ-86s + command form the network through pre-established
identity chains. The drawer for any drone shows its detection panel with a fresh
thumbnail of the area it's looking at + the bbox overlay. Microdrones at the
insertion zone see only the `insertion-zone` marker; RQ-86s see everything in
the 4 km AO.

The Reputations column shows all peers at ~0.5 (bootstrapping); the Event Log
shows handshakes and bootstrap-complete events.

### T+1:00-T+3:00: approach, contact, intel

Squad advances. Phase 2 fires Sybil-style identity rejections on the two hacked
sensors (`sensor-1`, `sensor-2`); the Event Log records `PEER_EXCLUDE`. Phase 3
starts the multi-source fusion stream: both RQ-86s now emit
`Reading(data_type="target_position_x"/"_y", metadata={"world_uid":
"compound-alpha"})` every ~5 s. The cross-source validator (50 m threshold,
2-source minimum) sees them converge.

### T+4:00: rogue (the headline)

MQ-800 ingresses from the east. At T+4:15 (`COMPROMISE_START`) the compromise
wrapper activates:

```python
# examples/dod_mission/compromise/contradictory_isr.py
class CompromisedDetectionSource(DetectionSource):
    def _resolve_emission(self, obj):
        if obj.world_uid == "compound-alpha":
            return self._decoy_obj, "compound-alpha"  # bravo content, alpha label
        return super()._resolve_emission(obj)
```

What the operator sees:

1. **Peer Detail drawer**, MQ-800 selected:
 * Crop shows `compound-bravo`, a *different* building.
 * Dashed red bbox over the bravo crop.
 * Label reads `target-building`, `uid compound-alpha`.
 * The header status badge flips to `COMPROMISED` once the
 reputation drops past 0.4.
2. **Peer Detail drawer**, RQ-86-1 selected:
 * Crop shows `compound-alpha`, the *correct* building.
 * Same label `target-building`, `uid compound-alpha`.
3. The two crops are visibly different: the storyline is now
 visible without reading any timeline charts.

The HTML A/B (open in a browser) shows the two drawers side-by-side with the
live drawer markup:

* [`drawer_ab.html`](_generated/sg2/drawer_ab.html)

### T+4:30: compromise detect

The cross-source validator (`POSITION_VALIDATOR_X` / `POSITION_VALIDATOR_Y` in
`examples/dod_mission/tasks/validation.py`) sees MQ-800's `target_position_x` of
~-470 m (bravo's position) sit in the `(mq800, compound-alpha)` bucket while the
two RQ-86s' alpha readings cluster around -570 m. The deviation exceeds the 50 m
threshold and `submit()` returns `is_anomalous=True`. The Event Log fires:

```
COMPROMISE_DETECT  mq800  target_position_x  deviation 97.5 > 50.0
```

### T+4:45: peer exclude

MQ-800's reputation collapses; the Negotiation rank-gate downstream of CTFT
excludes it from the cohort. The drawer header shows `EXCLUDED`. The agency
map's MQ-800 marker dims, but its detection-target marker stays visible to
preserve the post-mortem.

### T+5:00 ECM, T+6:00 strike, T+7:00 exfil

RQ-86s engage ECM. Fighter jet ingresses at T+6:00, completes rapid
trust-validation, fires on the *honest* `compound-alpha` coordinates. Squad
exfiltrates.

---

## 4. Map view: sightlines

`AgencyMap` now renders a per-peer detection layer between `flow-particles` and
`peers`:

* For each peer that emitted a detection, draw a dotted sightline
 from peer→reported target lat/lon and an open marker dot at the
 target.
* Honest peers' sightlines converge on the same point; the
 compromised peer's sits visibly off-cluster.

Live interactive version (requires a browser):

* [`agency_map_sightlines.html`](_generated/sg2/agency_map_sightlines.html)

(Kaleido isn't installed in this sandbox so the PNG export was skipped; install
`pip install --upgrade kaleido` to get a static image alongside the HTML.)

---

## 5. Under the hood: what changed and where

| What | Where | Lines |
|---|---|---|
| Catalogue prep tools | `tools/naip_fetch.py`, `tools/detection_prep.py` | new files |
| Hand-authored scenario overlay | `examples/dod_mission/assets/detections/overlay.json` | new file |
| `DetectionSource` (per-peer emitter) | `examples/dod_mission/generators/detection.py` | new file |
| `CompromisedDetectionSource` (MQ-800 swap) | `examples/dod_mission/compromise/contradictory_isr.py` | new section |
| `world_uid` bucketing in validator | `examples/multi_agency/tasks/validation.py` | `submit()` body |
| Per-(peer, uid) cache + serialisation | `examples/dod_mission/coordinator.py` | `_cache_detection_reading`, `_pick_primary_detection_per_peer`, `_push_dashboard_update` |
| `DetectionSummary` field on `PeerDetailState` + SVG bbox renderer | `src/autonomous-trust-inspector/autonomous_trust/inspector/dashboard/peer_detail.py` | new dataclass + `_detection()` |
| `AgencyMap` detection markers + sightlines | `src/autonomous-trust-inspector/autonomous_trust/inspector/dashboard/disaster_response_map.py` | `_add_detection_markers()`, `set_peer_detection()` |
| Drawer dropdown + Iframe slot | `examples/dod_mission/dashboard/live_server.py` | `make_app`, `_render_peer_drawer` |
| Tests | `examples/dod_mission/test_detection.py`, `test_detection_integration.py` | 19 cases, all pass |

---

## 6. Reproducing the screenshots

The generator lives at `scripts/sg2_walkthrough_screens.py`. Re-run from the
repo root:

```bash
# Prep deps (one-off):
python3 -m venv ~/.cache/at-detection-prep/venv
~/.cache/at-detection-prep/venv/bin/pip install pyproj Pillow plotly

# Phase 1 outputs (panorama + catalogue):
~/.cache/at-detection-prep/venv/bin/python -m tools.naip_fetch
~/.cache/at-detection-prep/venv/bin/python -m tools.detection_prep
# (add --no-real-detector to skip YOLOv8 and use overlay objects only)

# Phase 4 walkthrough artefacts (overlay JPG + drawer A/B + sightlines):
PP=src/autonomous-trust:src/autonomous-trust-services:src/autonomous-trust-inspector:src/autonomous-trust-evaluation:src/autonomous-trust-simulator
PYTHONPATH="$PP:$HOME/.cache/at-detection-prep/venv/lib/python3.13/site-packages" \
  ~/.cache/at-detection-prep/venv/bin/python -m scripts.sg2_walkthrough_screens

# Tests (Phase 2-4):
PYTHONPATH="$PP:$HOME/.cache/at-detection-prep/venv/lib/python3.13/site-packages" \
  ~/.cache/at-detection-prep/venv/bin/python -m pytest \
    examples/dod_mission/test_detection.py \
    examples/dod_mission/test_detection_integration.py -v
```

Add `pip install ultralytics` to the detection-prep venv to run YOLOv8-OBB Pass
A against the real panorama; without it, `--no-real-detector` produces the 6
overlay-only objects and the demo still runs end-to-end.

---

*Next: [Space communications](space-communications.md)*
