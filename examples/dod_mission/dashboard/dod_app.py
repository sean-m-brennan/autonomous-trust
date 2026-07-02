# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""DoD-mission dashboard component bundle.

Counterpart to examples/multi_agency/dashboard/multi_agency_app.py.
Instantiates the reusable dashboard components from
`autonomous_trust.inspector.dashboard` with DoD-specific configuration:

  * per-peer colors come from PeerRole.color in scenario.py (role-keyed,
    not agency-keyed)
  * sensor comparison chart is on `target_position_x` instead of
    `temperature` — that's the metric the MQ-800 falsifies
  * trust timeline carries the 8 DoD phase markers
  * narration is the DoD storyline (see narration_script.py)
  * role legend replaces agency badges (squad / microdrone / RQ-86 /
    MQ-800 / sensor / jet / command)

Known minor deltas this file does NOT fix (issues live in the shared
inspector layout):

  * `disaster_response_layout._grid()` hardcodes panel titles like
    "Agency Map" / "Trust Network" — for DoD presentation, these should
    read "Tactical Map" / "Trust Network".  Override at the layout level
    when the inspector layout is generalized; this module's
    `PANEL_TITLES` dict declares the DoD overrides so the renderer can
    pick them up once the layout is parameterized.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Path-mounted sibling import for the scenario module (dashed package).
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
from scenario import (  # noqa: E402
    DoDMissionScenario,
    SQUAD_GREEN, MICRODRONE_CYAN, RQ86_GOLD, MQ800_AMBER,
    SENSOR_GREY, JET_SILVER, COMMAND_BLUE,
)


# Map config — Madison County, AL.  Generic civilian terrain that matches
# the UTM positions translated from examples/mission/simulator/scenario.yaml.
MAP_CONFIG = {
    "center": {"lat": 34.715, "lon": -86.640},
    "zoom": 13,
    "style": "satellite-streets",  # Mapbox style
    "role_layers": {
        "soldier":       {"color": SQUAD_GREEN,     "icon": "person",    "label": "Squad"},
        "microdrone":    {"color": MICRODRONE_CYAN, "icon": "triangle",  "label": "Microdrone"},
        "recon-drone":   {"color": RQ86_GOLD,       "icon": "diamond",   "label": "RQ-86 Recon"},
        "armed-drone":   {"color": MQ800_AMBER,     "icon": "x",         "label": "MQ-800"},
        "ground-sensor": {"color": SENSOR_GREY,     "icon": "circle",    "label": "Sensor"},
        "fighter-jet":   {"color": JET_SILVER,      "icon": "star",      "label": "Jet"},
        "command-node":  {"color": COMMAND_BLUE,    "icon": "pentagon",  "label": "Command"},
    },
}

# Legend entries shown in the title bar of the presentation layout.
# (label, color) pairs — order matters; squad first as the focal cohort.
ROLE_LEGEND = [
    ("Squad",       SQUAD_GREEN),
    ("Microdrone",  MICRODRONE_CYAN),
    ("RQ-86",       RQ86_GOLD),
    ("MQ-800",      MQ800_AMBER),
    ("Sensor",      SENSOR_GREY),
    ("Jet",         JET_SILVER),
    ("Command",     COMMAND_BLUE),
]

# DoD-specific panel title overrides.  See module docstring for the
# known-gap note: the shared layout currently hardcodes its own titles,
# so these are advisory until that gets parameterized.
PANEL_TITLES = {
    "map":      ("Tactical Map", "Madison County, AL"),
    "graph":    ("Trust Network", "Bilateral trust (edge = weight)"),
    "log":      ("Event Log", "Newest first"),
    "time":     ("Trust Dynamics", "Per-peer reputation"),
    "streams":  ("Active Tasks", "ISR + recon + ECM"),
    "detail":   ("Peer Detail", "Click a node on the map or graph"),
}


def build_peer_colors(scenario: DoDMissionScenario) -> dict[str, str]:
    """Extract per-peer color map from scenario PeerRole.color."""
    return {name: role.color for name, role in scenario.peers.items()}


def build_dashboard(scenario: DoDMissionScenario) -> dict:
    """Instantiate the configured dashboard component set.

    Returns a dict of name -> component, ready to be wired by the
    inspector's callback layer.  The keys are stable and used by the
    presentation layout module.
    """
    from autonomous_trust.inspector.dashboard.trust_timeline import TrustTimeline
    from autonomous_trust.inspector.dashboard.event_log import EventLogPanel
    from autonomous_trust.inspector.dashboard.sensor_chart import SensorComparisonChart
    from autonomous_trust.inspector.dashboard.data_streams import DataStreamsPanel
    from autonomous_trust.inspector.dashboard.peer_detail import PeerDetailPanel

    colors = build_peer_colors(scenario)

    # Trust dynamics: same threshold (0.5) as multi-agency.  Phase markers
    # come from scenario.phases — 8 of them for DoD.
    timeline = TrustTimeline(
        peer_colors=colors,
        threshold=0.5,
        title="Trust Dynamics — DoD Squad Infiltration",
    )
    for phase in scenario.phases:
        timeline.add_phase_marker(
            t_seconds=phase.start.total_seconds(),
            label=phase.name,
        )

    # Target-position map: each overhead-ISR peer reports a target
    # location as parallel (target_position_x, target_position_y)
    # readings; this panel pairs them, converts squad-frame metres to
    # WGS84, and shows a per-peer marker on a map. The MQ-800
    # compromise beat (compromise/contradictory_isr.py) used to surface
    # as an X-coordinate divergence on a time-series line chart; the
    # map makes the contradiction visible as a peer pointing at a
    # *different building*. Replaces the previous SensorComparisonChart
    # on data_type=target_position_x.
    from .target_position_map import TargetPositionMapPanel
    target_x_chart = TargetPositionMapPanel(
        # Start from the full scenario color map so EVERY peer that reports a
        # target (microdrones included) gets its own colour + legend entry —
        # previously only rq86/mq800 were listed, so a microdrone's reported
        # target rendered grey (#888): near-invisible on the dark map and
        # unlabelled. Keep the curated overhead-ISR golds/amber as overrides.
        peer_colors={
            **colors,
            "rq86-1": RQ86_GOLD,
            "rq86-2": "#E6C656",   # lighter gold to differentiate from rq86-1
            "mq800":  MQ800_AMBER,
        },
        window_sec=120.0,
        title="Asset Positions / Target Position via Overhead ISR",
    )

    # Secondary: electronic noise floor — RQ-86s see the noise spike when
    # MQ-800 arrives; MQ-800 under-reports it (see contradictory_isr.py).
    noise_chart = SensorComparisonChart(
        data_type="electronic_noise_db",
        unit="dB",
        peer_colors={
            "rq86-1": RQ86_GOLD,
            "rq86-2": "#E6C656",
            "mq800":  MQ800_AMBER,
        },
        window_sec=120.0,
        title="Electronic Noise Floor — Overhead ISR",
    )

    event_log = EventLogPanel(capacity=200)
    streams = DataStreamsPanel(peer_colors=colors)
    detail = PeerDetailPanel()

    return {
        "trust_timeline": timeline,
        "target_x_chart": target_x_chart,
        "noise_chart": noise_chart,
        "event_log": event_log,
        "data_streams": streams,
        "peer_detail": detail,
    }
