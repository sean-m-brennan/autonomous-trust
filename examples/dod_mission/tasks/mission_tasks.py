# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""DoD mission task type definitions.

Each task is a `TaskDefinition` (reused from the multi-agency demo)
that the AT negotiation layer will route between peers based on
advertised capabilities and reputation.  Producers register the task's
required_capabilities; consumers register the consumer_capabilities and
issue requests.  The body of the task — what actually happens at
execution — is implementation detail handled in the participant runner
(Phase 3) and matters less than the negotiation flow being visible in
the dashboard.

Task → role mapping (see ../scenario.py for the role inventory):

  recon_sweep:    squad-* (consumers)   → microdrone-* (producers)
  target_track:   rq86-*  (producers)   → squad-*, command (consumers)
  sensor_fusion:  any (producers)       → fema-fusion-style aggregator
                                          (here: squad-intel or command)
  ecm_engage:     rq86-1   (consumer)   → rq86-2 (producer)  (and vice versa)
  triangulate:    squad-intel (consumer)→ microdrone-* (producers, ≥3)
  fire_mission:   command (consumer)    → jet-1   (producer)
  exfil_cover:    squad-captain         → surviving microdrone-* (producers)

`min_reputation` rises with the consequence of failure: data sharing
sits at 0.5, target tracking at 0.6, fire missions at 0.85.
"""

from __future__ import annotations

# Reuse the TaskDefinition dataclass from multi-agency rather than
# duplicating it.  If the two demos diverge later, we can promote it to
# autonomous_trust.evaluation.tasks.
from examples.multi_agency.tasks.data_sharing import TaskDefinition


# --- Reconnaissance --------------------------------------------------

RECON_SWEEP = TaskDefinition(
    task_type="recon_sweep",
    description="Microdrone swarm sweeps a designated area; returns "
                "video imagery and motion-detection hits.",
    required_capabilities=["recon_sweep", "video_stream"],
    consumer_capabilities=["sensor_fusion", "tactical_comms"],
    min_reputation=0.5,
    data_types=["video_frame", "motion_intensity", "audio_level"],
    cadence_sec=2.0,
    priority=2,
    metadata={"producer_role": "microdrone", "consumer_role": "soldier"},
)

TRIANGULATE = TaskDefinition(
    task_type="triangulate",
    description="Three-drone subswarm produces an aggregated GPS fix "
                "on a designated target.  Requires bearing reports from "
                "at least three independent positions.",
    required_capabilities=["gps", "imu", "tof_sensor"],
    consumer_capabilities=["sensor_fusion"],
    min_reputation=0.6,
    data_types=["target_fix_lat", "target_fix_lon"],
    cadence_sec=3.0,
    priority=3,
    metadata={"producer_role": "microdrone", "consumer_role": "soldier",
              "min_producers": 3},
)


# --- Overhead ISR ----------------------------------------------------

TARGET_TRACK = TaskDefinition(
    task_type="target_track",
    description="Overhead recon platform continuously reports target "
                "vehicle ID, position, and heading.  Used for both "
                "cross-source corroboration and fire-mission targeting.",
    required_capabilities=["electro_optical", "mti_radar", "target_track"],
    consumer_capabilities=["sensor_fusion", "tactical_comms"],
    min_reputation=0.6,
    data_types=["target_position_x", "target_position_y", "target_bearing_deg",
                "vehicle_class"],
    cadence_sec=1.0,
    priority=3,
    metadata={"producer_role": "recon-drone", "consumer_role": "soldier"},
)

SENSOR_FUSION = TaskDefinition(
    task_type="sensor_fusion",
    description="Merge multi-source sensor readings (target position, "
                "bearing, ground sensors) into a unified situational "
                "picture.  Higher reputation required — output is "
                "consumed for targeting decisions.",
    required_capabilities=["sensor_fusion"],
    consumer_capabilities=[],  # anyone can consume the fused picture
    min_reputation=0.7,
    data_types=["fused_target_lat", "fused_target_lon", "confidence"],
    cadence_sec=2.0,
    priority=4,
    metadata={"producer_role": "soldier"},
)


# --- Combat ----------------------------------------------------------

ECM_ENGAGE = TaskDefinition(
    task_type="ecm_engage",
    description="RQ-86 emits electronic countermeasures against a "
                "designated rogue platform.  Paired RQ-86s coordinate "
                "to keep the target neutralized (CTFT pattern).",
    required_capabilities=["ecm"],
    consumer_capabilities=["ecm"],
    min_reputation=0.6,
    data_types=["ecm_status", "target_uuid"],
    cadence_sec=5.0,
    priority=4,
    metadata={"producer_role": "recon-drone", "consumer_role": "recon-drone"},
)

FIRE_MISSION = TaskDefinition(
    task_type="fire_mission",
    description="Authoritative strike request.  Carries target "
                "coordinates and a confirmation handshake.  Highest "
                "min_reputation — a forged identity must never satisfy "
                "this task.",
    required_capabilities=["weapon_release", "fire_mission"],
    consumer_capabilities=["fire_mission_relay"],
    min_reputation=0.85,
    data_types=["strike_lat", "strike_lon", "confirmation_code"],
    cadence_sec=0.0,    # event-driven, not periodic
    priority=10,
    metadata={"producer_role": "fighter-jet", "consumer_role": "command-node"},
)

EXFIL_COVER = TaskDefinition(
    task_type="exfil_cover",
    description="Surviving microdrones provide forward / rear watch as "
                "the squad withdraws.  Lower-cadence task — the squad "
                "is primarily relying on ground-level awareness.",
    required_capabilities=["recon_sweep", "video_stream"],
    consumer_capabilities=["tactical_comms"],
    min_reputation=0.4,    # accept any surviving asset
    data_types=["watch_sector", "threat_detected"],
    cadence_sec=4.0,
    priority=2,
    metadata={"producer_role": "microdrone", "consumer_role": "soldier"},
)


ALL_TASKS = [
    RECON_SWEEP, TARGET_TRACK, SENSOR_FUSION, ECM_ENGAGE,
    TRIANGULATE, FIRE_MISSION, EXFIL_COVER,
]
