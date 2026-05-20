# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
"""DoD Squad Infiltration Scenario — HighTrust whitepaper §1.3.1.

Sourced from doc/tekfive/whitepaper/out/HighTrust_DOD.md and the role
breakdown in examples/mission/simulator/scenario.md.  Initial positions
were translated from examples/mission/simulator/scenario.yaml (UTM zone
16N → WGS84 lat/lon).  Movement paths are intentionally NOT carried in
this file — the simulator-side YAML, generated separately, drives peer
motion, and AT peers learn current position through the metadata
service.  See examples/multi_agency/ for the pattern this mirrors.

Peers (baseline, 14 total — scalable via constructor knobs):
  Squad (ODA)             4 specialists (Captain, Warrant, Intel, Ops)
  Microdrones             4 vanguard reconnaissance
  RQ-86 recon             2 overhead, peer leaders
  MQ-800                  1 joins at phase 4, sends contradictory data
  Leave-behind sensors    3 some hacked, present unknown identities
  Fighter jet             1 joins at phase 6 for strike
  Command                 1 remote coordination node

Timeline (8 phases, ~8 minutes total):
  T+0:00  Setup     — Network forms (squad + microdrones + RQ-86s + command)
  T+1:00  Approach  — Squad moves toward target, swarms sweep ahead
  T+2:00  Contact   — Leave-behind sensors contacted (some hacked, rejected)
  T+3:00  Intel     — Clean sensor + overhead data fused, target located
  T+4:00  Rogue     — MQ-800 arrives, feeds contradictory data, excluded
  T+5:00  ECM       — RQ-86s engage rogue with countermeasures (CTFT)
  T+6:00  Strike    — Fighter jet validates in <1s, fires
  T+7:00  Exfil     — Squad exfiltrates with minimal drone cover
"""

from datetime import timedelta

from autonomous_trust.evaluation.scenarios.scenario import (
    GeoPosition,
    Scenario, Phase, PeerRole,
    ScenarioEvent, PhaseEvent,
)

# Landmarks (UTM 16N from the original mission YAML → WGS84 via utm.to_latlon).
# Madison County, AL — generic civilian terrain.
GROUND_START   = (34.706505, -86.633657, 197.0)   # Squad insertion
GROUND_MID     = (34.724448, -86.639802, 195.0)   # Target area
RQ86_ORBIT     = (34.724448, -86.639802, 5000.0)  # Overhead orbit center
MQ800_INGRESS  = (34.715000, -86.580000, 600.0)   # MQ-800 enters from the east
JET_INGRESS    = (34.724448, -86.453789, 400.0)   # ~17 km east of target
COMMAND_REMOTE = (33.518600, -86.810400, 200.0)   # ~135 km south (Birmingham AL)

# Role colors (CSS).  Identifies role only; trust state is rendered
# separately by the dashboard (edge color, node glow, etc.).
SQUAD_GREEN     = "#5B6E1F"
MICRODRONE_CYAN = "#1FB8CD"
RQ86_GOLD       = "#D4AF37"
MQ800_AMBER     = "#C68A3F"
SENSOR_GREY     = "#888888"
JET_SILVER      = "#C0C0C0"
COMMAND_BLUE    = "#1E3A8A"

# Squad specialist roster (HighTrust §1.3.1 / simulator/scenario.md).
# Baseline = first N entries; additional generic "squad-N" peers fill out
# larger squads (squad_size > len(SQUAD_ROSTER)).
SQUAD_ROSTER = [
    ("squad-captain",  "Captain",        "Commander"),
    ("squad-warrant",  "1stLt-Novosel",  "Warrant Officer"),
    ("squad-intel",    "SGM-Payne",      "Intel Specialist"),
    ("squad-ops",      "Ops-1",          "Ops Specialist"),
    ("squad-comms",    "Comms-1",        "Comms Specialist"),
    ("squad-weapons",  "Wpns-1",         "Weapons Specialist"),
    ("squad-medic",    "Med-1",          "Medic"),
    ("squad-engineer", "Eng-1",          "Demolition"),
]

# Microdrone storyline nicknames; generic "microdrone-N" beyond the list.
MICRODRONE_NICKNAMES = ["Boss", "Scorch", "Sev", "Fixer"]


def _pos(landmark, *, lat_jitter=0.0, lon_jitter=0.0, alt=None):
    """Build a GeoPosition from a landmark tuple with optional jitter."""
    lat, lon, default_alt = landmark
    return GeoPosition(lat + lat_jitter, lon + lon_jitter,
                       alt if alt is not None else default_alt)


class DoDMissionScenario(Scenario):
    """Squad infiltration with mixed ground / air / overhead assets.

    Constructor knobs scale peer count from the 9-peer storyline baseline
    up toward ~100 nodes for scale testing.  All knobs preserve the
    scenario's narrative beats (compromise, detection, exclusion, strike).
    """

    def __init__(self,
                 squad_size: int = 4,
                 swarm_size: int = 4,
                 rq86_count: int = 2,
                 sensor_count: int = 3,
                 hacked_sensors: int = 2,
                 include_mq800: bool = True,
                 include_jet: bool = True,
                 include_command: bool = True):
        if hacked_sensors > sensor_count:
            raise ValueError(
                f"hacked_sensors ({hacked_sensors}) cannot exceed "
                f"sensor_count ({sensor_count})"
            )
        if squad_size < 1:
            raise ValueError("squad_size must be at least 1 (need a leader)")
        self._squad_size = squad_size
        self._swarm_size = swarm_size
        self._rq86_count = rq86_count
        self._sensor_count = sensor_count
        self._hacked_sensors = hacked_sensors
        self._include_mq800 = include_mq800
        self._include_jet = include_jet
        self._include_command = include_command
        super().__init__()

    # --- abstract property impls --------------------------------------

    @property
    def name(self) -> str:
        return "dod-mission"

    @property
    def description(self) -> str:
        n = len(self._peers) if self._peers else "..."
        return (
            f"DoD squad infiltration scenario from the HighTrust whitepaper "
            f"§1.3.1.  {n} peers (squad, microdrone swarm, RQ-86 recon, "
            f"MQ-800 rogue, leave-behind sensors, fighter jet, command) "
            f"autonomously form a trust network, detect a rogue drone via "
            f"reputation collapse, neutralize it via ECM, and complete a "
            f"strike with rapid trust validation of a new asset — all "
            f"without human-in-the-loop trust decisions."
        )

    def define(self):
        self._define_peers()
        self._define_phases()

    # --- peers ---------------------------------------------------------

    def _define_peers(self):
        self._define_squad()
        self._define_microdrones()
        self._define_rq86s()
        if self._include_mq800:
            self._define_mq800()
        self._define_sensors()
        if self._include_jet:
            self._define_jet()
        if self._include_command:
            self._define_command()

    def _define_squad(self):
        # Squad members are pre-established peers, all at the insertion point.
        # Spread laterally so they're not coincident on the map.
        for i in range(self._squad_size):
            if i < len(SQUAD_ROSTER):
                name, nickname, specialty = SQUAD_ROSTER[i]
            else:
                name, nickname, specialty = f"squad-{i+1}", f"Soldier-{i+1}", "Specialist"
            self.add_peer(PeerRole(
                name=name,
                agency="ODA",
                kind="soldier",
                position=_pos(GROUND_START,
                              lat_jitter=0.00002 * i,
                              lon_jitter=0.00002 * (i % 2 - 0.5)),
                color=SQUAD_GREEN,
                join_phase=0,
                capabilities=["heads_up_display", "sensor_fusion",
                              "tactical_comms"],
                metadata={"nickname": nickname, "specialty": specialty},
            ))

    def _define_microdrones(self):
        # Microdrones (vanguard) are pre-established, launched with the squad.
        for i in range(self._swarm_size):
            nickname = (MICRODRONE_NICKNAMES[i]
                        if i < len(MICRODRONE_NICKNAMES)
                        else f"Drone-{i+1}")
            self.add_peer(PeerRole(
                name=f"microdrone-{i+1}",
                agency="ODA",
                kind="microdrone",
                # Launched from squad position; will move ahead in simulator path.
                position=_pos(GROUND_START,
                              lat_jitter=0.00005 * (i + 1),
                              lon_jitter=0.00005 * ((i + 1) % 3 - 1),
                              alt=200.0),
                color=MICRODRONE_CYAN,
                join_phase=0,
                capabilities=["video_stream", "audio_sensor", "tof_sensor",
                              "imu", "gps", "recon_sweep"],
                metadata={"nickname": nickname},
            ))

    def _define_rq86s(self):
        # RQ-86s are peer leaders, orbit at altitude.
        for i in range(self._rq86_count):
            angle_offset = (i / max(self._rq86_count, 1)) * 360.0
            self.add_peer(PeerRole(
                name=f"rq86-{i+1}",
                agency="Air-Support",
                kind="recon-drone",
                position=_pos(RQ86_ORBIT,
                              lat_jitter=0.005 * (i % 2 * 2 - 1),
                              lon_jitter=0.005 * ((i + 1) % 2 * 2 - 1)),
                color=RQ86_GOLD,
                join_phase=0,
                capabilities=["electro_optical", "infrared", "sar", "mti_radar",
                              "sigint", "ecm", "comm_relay", "target_track"],
                metadata={"orbit_radius_m": 1500,
                          "orbit_angle_deg": angle_offset},
            ))

    def _define_mq800(self):
        # MQ-800 is the rogue.  Joins at phase 4 ("Rogue").  Initial position
        # is its ingress waypoint; the simulator drives its arrival path.
        # It is NOT marked compromised in metadata — the network must discover
        # that via reputation, not via configuration.
        self.add_peer(PeerRole(
            name="mq800",
            agency="Unknown-Air",
            kind="armed-drone",
            position=_pos(MQ800_INGRESS),
            color=MQ800_AMBER,
            join_phase=4,
            capabilities=["electro_optical", "infrared", "weapon_release",
                          "long_range_comms"],
            metadata={"rogue": True},  # used by compromise module, NOT dashboard
        ))

    def _define_sensors(self):
        # Leave-behind sensors scatter along the approach path between
        # insertion and target.  Some present Sybil / forged identities.
        clean_indices = set(range(self._hacked_sensors, self._sensor_count))
        for i in range(self._sensor_count):
            # Interpolate along the squad's approach: 0 → target.
            t = (i + 1) / (self._sensor_count + 1)
            lat = GROUND_START[0] + t * (GROUND_MID[0] - GROUND_START[0])
            lon = GROUND_START[1] + t * (GROUND_MID[1] - GROUND_START[1])
            is_clean = i in clean_indices
            self.add_peer(PeerRole(
                name=f"sensor-{i+1}",
                agency="Leave-Behind",
                kind="ground-sensor",
                position=GeoPosition(lat, lon, 195.0),
                color=SENSOR_GREY,
                join_phase=2,  # discovered during "Contact" phase
                capabilities=["seismic", "acoustic", "perimeter"],
                metadata={"forged_identity": not is_clean},
            ))

    def _define_jet(self):
        # Fighter jet joins at phase 6 ("Strike") — exercises rapid trust
        # validation of a new asset under <5s.
        self.add_peer(PeerRole(
            name="jet-1",
            agency="Air-Support",
            kind="fighter-jet",
            position=_pos(JET_INGRESS),
            color=JET_SILVER,
            join_phase=6,
            capabilities=["weapon_release", "high_speed_recon",
                          "long_range_comms", "fire_mission"],
            metadata={"callsign": "ColJones"},
        ))

    def _define_command(self):
        self.add_peer(PeerRole(
            name="command",
            agency="Command",
            kind="command-node",
            position=_pos(COMMAND_REMOTE),
            color=COMMAND_BLUE,
            join_phase=0,
            capabilities=["coordination", "asset_authorization",
                          "fire_mission_relay"],
            metadata={"location": "Remote HQ"},
        ))

    # --- phases --------------------------------------------------------

    def _define_phases(self):
        # Phase 0: Setup — pre-established peers form the network.
        self.add_phase(Phase(
            name="Setup",
            start=timedelta(0),
            description="Squad, microdrones, RQ-86 recon, and command form "
                        "the network through pre-established identity chains.",
        ))

        # Phase 1: Approach.
        self.add_phase(Phase(
            name="Approach",
            start=timedelta(minutes=1),
            description="Squad advances toward the target; microdrone swarm "
                        "sweeps ahead extending the squad's detection envelope.",
        ))

        # Phase 2: Contact — leave-behind sensors discovered.  Hacked ones
        # present unknown identities and are rejected via Sybil defense.
        contact = Phase(
            name="Contact",
            start=timedelta(minutes=2),
            description="Leave-behind sensors discovered along the approach. "
                        "Identity verification rejects forged credentials; "
                        "verified sensors integrate into the trust graph.",
        )
        for i in range(self._hacked_sensors):
            contact.events.append(ScenarioEvent(
                timestamp=timedelta(minutes=2, seconds=15 + 5 * i),
                event_type=PhaseEvent.COMPROMISE_START,
                peer_name=f"sensor-{i+1}",
                description=f"sensor-{i+1} presents an unverifiable identity "
                            f"(Sybil); behavior diverges from clean sensors.",
                data={"mode": "sybil"},
            ))
            contact.events.append(ScenarioEvent(
                timestamp=timedelta(minutes=2, seconds=30 + 5 * i),
                event_type=PhaseEvent.COMPROMISE_DETECT,
                peer_name=f"sensor-{i+1}",
                description=f"Network rejects sensor-{i+1}: identity does not "
                            f"validate against the leave-behind roster.",
            ))
            contact.events.append(ScenarioEvent(
                timestamp=timedelta(minutes=2, seconds=45 + 5 * i),
                event_type=PhaseEvent.PEER_EXCLUDE,
                peer_name=f"sensor-{i+1}",
                description=f"sensor-{i+1} excluded from the trust graph.",
            ))
        self.add_phase(contact)

        # Phase 3: Intel — clean sensors + overhead data fused to locate target.
        intel = Phase(
            name="Intel",
            start=timedelta(minutes=3),
            description="Verified sensor data is fused with RQ-86 overhead "
                        "imagery and SIGINT.  Target location is corroborated "
                        "across multiple independent sources.",
        )
        intel.events.append(ScenarioEvent(
            timestamp=timedelta(minutes=3, seconds=10),
            event_type=PhaseEvent.DATA_STREAM_START,
            description="Multi-source fusion stream activated.",
        ))
        self.add_phase(intel)

        # Phase 4: Rogue — MQ-800 arrives, exposed via reputation collapse.
        # MQ-800 auto-joins via join_phase=4 at T+4:00.  Compromise begins
        # ~15s later (giving the network a moment to see it as a peer first),
        # detection lands within another 15s, exclusion shortly after.
        if self._include_mq800:
            rogue = Phase(
                name="Rogue",
                start=timedelta(minutes=4),
                description="MQ-800 armed drone arrives.  After brief peer-leader "
                            "ingest from the RQ-86s, it begins broadcasting data "
                            "that contradicts every other sensor in the cohort.  "
                            "Gossip-driven reputation collapse follows.",
            )
            rogue.events.append(ScenarioEvent(
                timestamp=timedelta(minutes=4, seconds=15),
                event_type=PhaseEvent.COMPROMISE_START,
                peer_name="mq800",
                description="MQ-800 begins emitting contradictory sensor data.",
                data={"mode": "contradictory_data"},
            ))
            rogue.events.append(ScenarioEvent(
                timestamp=timedelta(minutes=4, seconds=30),
                event_type=PhaseEvent.COMPROMISE_DETECT,
                peer_name="mq800",
                description="Ground units and RQ-86s independently detect "
                            "MQ-800's data divergence; reputation drops.",
            ))
            rogue.events.append(ScenarioEvent(
                timestamp=timedelta(minutes=4, seconds=45),
                event_type=PhaseEvent.PEER_EXCLUDE,
                peer_name="mq800",
                description="MQ-800 reputation collapses below threshold; "
                            "cohort cuts off inbound messages.",
            ))
            self.add_phase(rogue)
        else:
            # Keep phase numbering stable for scale tests that omit MQ-800.
            self.add_phase(Phase(
                name="Rogue",
                start=timedelta(minutes=4),
                description="(MQ-800 disabled in this run — no rogue arrival.)",
            ))

        # Phase 5: ECM — RQ-86s engage the (now-excluded) MQ-800 with active
        # countermeasures, draining their cooperation budget but keeping the
        # rogue neutralized.  Squad operates in degraded overhead-coverage mode.
        ecm = Phase(
            name="ECM",
            start=timedelta(minutes=5),
            description="RQ-86 pair engages the rogue MQ-800 with electronic "
                        "countermeasures (CTFT strategy: keep it neutralized "
                        "but defer escalation).  Squad continues autonomously "
                        "under reduced overhead coverage.",
        )
        self.add_phase(ecm)

        # Phase 6: Strike — fighter jet arrives, validates trust in <1s, fires.
        if self._include_jet:
            strike = Phase(
                name="Strike",
                start=timedelta(minutes=6),
                description="Fighter jet ingresses, announces itself, completes "
                            "rapid identity + reputation validation with the "
                            "squad / swarm cohort in under one second, acquires "
                            "targeting data, and engages.",
            )
            strike.events.append(ScenarioEvent(
                timestamp=timedelta(minutes=6, seconds=5),
                event_type=PhaseEvent.ANNOTATION,
                description="Jet validates trust + acquires targeting data "
                            "in a single high-speed pass.",
            ))
            self.add_phase(strike)
        else:
            self.add_phase(Phase(
                name="Strike",
                start=timedelta(minutes=6),
                description="(Fighter jet disabled in this run.)",
            ))

        # Phase 7: Exfil — squad withdraws with whatever overhead remains.
        self.add_phase(Phase(
            name="Exfil",
            start=timedelta(minutes=7),
            description="Squad exfiltrates with the surviving microdrones "
                        "providing forward-watch and rear-watch overhead.",
        ))


# Module-level CLI for quick inspection: `python -m examples.dod_mission.scenario`
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--squad-size", type=int, default=4)
    parser.add_argument("--swarm-size", type=int, default=4)
    parser.add_argument("--sensor-count", type=int, default=3)
    parser.add_argument("--hacked-sensors", type=int, default=2)
    parser.add_argument("--no-mq800", action="store_true")
    parser.add_argument("--no-jet", action="store_true")
    parser.add_argument("--no-command", action="store_true")
    args = parser.parse_args()

    sc = DoDMissionScenario(
        squad_size=args.squad_size,
        swarm_size=args.swarm_size,
        sensor_count=args.sensor_count,
        hacked_sensors=args.hacked_sensors,
        include_mq800=not args.no_mq800,
        include_jet=not args.no_jet,
        include_command=not args.no_command,
    )
    print(f"# {sc.name}")
    print(sc.description)
    print()
    print(f"## Peers ({len(sc.peers)})")
    by_kind: dict[str, list[str]] = {}
    for name, role in sc.peers.items():
        by_kind.setdefault(role.kind, []).append(name)
    for kind, names in sorted(by_kind.items()):
        print(f"  {kind:15s} × {len(names):3d}  ({', '.join(names[:4])}"
              f"{'...' if len(names) > 4 else ''})")
    print()
    print(f"## Phases ({len(sc.phases)})")
    for i, ph in enumerate(sc.phases):
        events = f"  ({len(ph.events)} events)" if ph.events else ""
        print(f"  {i}. T+{ph.start}  {ph.name}{events}")
