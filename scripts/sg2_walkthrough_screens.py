"""Regenerate the SG2 walkthrough's _generated/sg2/ artefacts.

Re-run from the repo root, with the ``autonomous_trust`` conda env active,
after `tools/naip_fetch.py` and `tools/detection_prep.py` have written
their outputs (the conda env supplies ultralytics/Pillow/pyproj/numpy):

    conda activate autonomous_trust
    PYTHONPATH=src/autonomous-trust:src/autonomous-trust-services:\
src/autonomous-trust-inspector:src/autonomous-trust-evaluation:\
src/autonomous-trust-simulator \
        python -m scripts.sg2_walkthrough_screens

Produces:
* doc/architecture/_generated/sg2/catalogue_overlay.jpg
* doc/architecture/_generated/sg2/drawer_ab.html
* doc/architecture/_generated/sg2/agency_map_sightlines.html
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "examples" / "dod_mission"))

OUT_DIR = REPO_ROOT / "doc" / "architecture" / "_generated" / "sg2"
ASSETS = REPO_ROOT / "examples" / "dod_mission" / "assets"
PANORAMA = ASSETS / "video" / "naip_huntsville.jpg"
CATALOGUE = ASSETS / "detections" / "catalogue.json"

# Colours match doc/architecture/sg2-detection-walkthrough.md section 2.
OVERLAY_COLOURS = {
    "compound-alpha":  (255,  64,  64),  # red
    "compound-bravo":  (255, 165,   0),  # orange
    "sensor-1-site":   (255,   0, 255),  # magenta (hacked)
    "sensor-2-site":   (255,   0, 255),  # magenta (hacked)
    "sensor-3-site":   (  0, 255, 255),  # cyan (clean)
    "insertion-zone":  ( 50, 255,  50),  # lime
}
YOLO_COLOUR = (255, 255, 0)  # pale yellow for the YOLO finds


def _catalogue_overlay() -> None:
    from PIL import Image, ImageDraw

    im = Image.open(PANORAMA).convert("RGB")
    cat = json.loads(CATALOGUE.read_text())
    draw = ImageDraw.Draw(im)

    # Markers are drawn into the 4096px panorama, then the image is
    # cropped + downscaled to ~460x676 (portrait). Use big radii + thick
    # strokes so the rings survive the ~6× downsample.
    for obj in cat["objects"]:
        uid = obj["world_uid"]
        bbox = obj.get("bbox_panorama_px") or obj.get("bbox_px")
        if not bbox:
            continue
        x0, y0, x1, y1 = bbox
        if obj.get("source") == "scenario-overlay":
            colour = OVERLAY_COLOURS.get(uid, (255, 255, 255))
            cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
            r = 40
            draw.ellipse((cx - r, cy - r, cx + r, cy + r),
                         outline=colour, width=14)
        else:
            # YOLO finds: thicker rectangle to be visible post-downsample.
            draw.rectangle((x0 - 6, y0 - 6, x1 + 6, y1 + 6),
                           outline=YOLO_COLOUR, width=8)

    # Crop to the squad-approach corridor (~1200..2900 wide × full height),
    # matching the framing of the previous _generated JPG.
    cropped = im.crop((1200, 0, 2900, 4096))
    target_w, target_h = 460, int(round(460 * 4096 / 1700))  # ≈ 1108
    # Keep it portrait but not absurdly tall — cap at 676 (the prior shape).
    target_h = 676
    out = cropped.resize((target_w, target_h), Image.LANCZOS)
    target = OUT_DIR / "catalogue_overlay.jpg"
    out.save(target, "JPEG", quality=86, optimize=True)
    print(f"wrote {target.relative_to(REPO_ROOT)} ({target.stat().st_size:,} bytes)")


def _drawer_ab() -> None:
    from dashboard import live_server as ls  # type: ignore

    cat = json.loads(CATALOGUE.read_text())
    alpha = next(o for o in cat["objects"] if o["world_uid"] == "compound-alpha")
    bravo = next(o for o in cat["objects"] if o["world_uid"] == "compound-bravo")
    alpha_b64 = base64.b64encode(
        (ASSETS / "detections" / alpha["crop"]).read_bytes()).decode()
    bravo_b64 = base64.b64encode(
        (ASSETS / "detections" / bravo["crop"]).read_bytes()).decode()

    common = {
        "world_uid": "compound-alpha",
        "label": "target-building",
        "confidence": 0.91,
        "crop_size_px": [128, 96],
        "bbox_in_crop_px": [12, 14, 110, 78],
        "t_seconds": 270.0,
    }
    state = {
        "t_seconds": 285.0,
        "reputations": {"mq800-armed-1": 0.22, "rq86-recon-1": 0.91},
        "tiers":       {"mq800-armed-1": 1,    "rq86-recon-1": 3},
        "agencies":    {"mq800-armed-1": "USAF","rq86-recon-1": "USA"},
        "kinds":       {"mq800-armed-1": "armed-drone",
                        "rq86-recon-1": "recon-drone"},
        "detection_per_peer": {
            "mq800-armed-1": dict(common, crop_b64=bravo_b64,
                                  target_latlon=[bravo["center_lat"],
                                                 bravo["center_lon"]]),
            "rq86-recon-1": dict(common, crop_b64=alpha_b64,
                                 target_latlon=[alpha["center_lat"],
                                                alpha["center_lon"]]),
        },
        "detection_log_per_peer": {"mq800-armed-1": [], "rq86-recon-1": []},
    }
    mq = ls._render_peer_drawer(state, "mq800-armed-1")
    rq = ls._render_peer_drawer(state, "rq86-recon-1")

    page = (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<title>SG2 drawer A/B</title>'
        '<style>'
        'body{margin:0;background:#0B1220;color:#E2E8F0;'
        'font-family:Inter,system-ui,sans-serif}'
        '.row{display:flex;gap:18px;padding:18px;align-items:flex-start}'
        '.col{flex:1 1 0;min-width:0;'
        'border:1px solid #1e293b;border-radius:8px;background:#0F172A}'
        '.col>h2{margin:0;padding:10px 14px;font-size:13px;'
        'background:#1e293b;border-radius:8px 8px 0 0}'
        '.col>iframe{width:100%;height:720px;border:0;'
        'border-radius:0 0 8px 8px;background:#0F172A}'
        '</style></head><body>'
        '<div class="row">'
        '<div class="col"><h2>MQ-800 armed (compromised)</h2>'
        f'<iframe srcdoc="{_srcdoc(mq)}"></iframe></div>'
        '<div class="col"><h2>RQ-86 recon (honest)</h2>'
        f'<iframe srcdoc="{_srcdoc(rq)}"></iframe></div>'
        '</div></body></html>'
    )
    target = OUT_DIR / "drawer_ab.html"
    target.write_text(page)
    print(f"wrote {target.relative_to(REPO_ROOT)} ({target.stat().st_size:,} bytes)")


def _srcdoc(html: str) -> str:
    return html.replace("&", "&amp;").replace('"', "&quot;")


def _agency_map_sightlines() -> None:
    from autonomous_trust.inspector.dashboard.disaster_response_map import (
        AgencyMap, MapPeer,
    )

    cat = json.loads(CATALOGUE.read_text())
    alpha = next(o for o in cat["objects"] if o["world_uid"] == "compound-alpha")
    bravo = next(o for o in cat["objects"] if o["world_uid"] == "compound-bravo")

    am = AgencyMap()
    # RQ-86s orbit overhead the AO; MQ-800 ingresses from the east.
    am.add_peer(MapPeer(name="rq86-recon-1", lat=34.7244, lon=-86.6420,
                        agency="USA", kind="recon-drone"))
    am.add_peer(MapPeer(name="rq86-recon-2", lat=34.7244, lon=-86.6376,
                        agency="USA", kind="recon-drone"))
    am.add_peer(MapPeer(name="mq800-armed-1", lat=34.7240, lon=-86.6300,
                        agency="USAF", kind="armed-drone"))

    am.set_peer_detection("rq86-recon-1", alpha["center_lat"], alpha["center_lon"],
                          world_uid="compound-alpha", label="target-building",
                          confidence=0.93)
    am.set_peer_detection("rq86-recon-2", alpha["center_lat"], alpha["center_lon"],
                          world_uid="compound-alpha", label="target-building",
                          confidence=0.90)
    am.set_peer_detection("mq800-armed-1", bravo["center_lat"], bravo["center_lon"],
                          world_uid="compound-alpha", label="target-building",
                          confidence=0.88)

    fig = am.figure()
    target = OUT_DIR / "agency_map_sightlines.html"
    fig.write_html(str(target), include_plotlyjs="cdn", full_html=True)
    print(f"wrote {target.relative_to(REPO_ROOT)} ({target.stat().st_size:,} bytes)")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not PANORAMA.exists():
        raise SystemExit(f"missing {PANORAMA}; run tools/naip_fetch.py first")
    if not CATALOGUE.exists():
        raise SystemExit(f"missing {CATALOGUE}; run tools/detection_prep.py first")
    _catalogue_overlay()
    _drawer_ab()
    _agency_map_sightlines()


if __name__ == "__main__":
    main()
