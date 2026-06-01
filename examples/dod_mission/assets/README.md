# DoD demo assets

Large media for the demo. Per the SG2 plan, these are **not committed** — they
are produced on first run and `.gitignore`d:

| Path | Producer | Size |
|---|---|---|
| `video/naip_huntsville.jpg` + `.geo.json` | `python -m tools.naip_fetch` | ~10 MB |
| `detections/catalogue.json` | `python -m tools.detection_prep` | ~50 KB |
| `detections/crops/*.jpg` | `python -m tools.detection_prep` | ~10-25 MB |

Hand-authored sources **are** committed:

- `detections/overlay.json` — scenario-critical synthetic objects
  (compound-alpha, compound-bravo decoy, hacked sensors, leave-behind
  sensors) keyed by `world_uid` for the runtime `DetectionSource`.
- `detections/attribution.txt` — NAIP public-domain + YOLOv8 Apache-2.0
  provenance.

See `STRETCH_GOAL_2_DETECTION_PLAN.md` §4 for the full prep pipeline.
