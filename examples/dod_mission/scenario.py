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

import math
import random
from datetime import timedelta

from autonomous_trust.evaluation.scenarios.scenario import (
    GeoPosition,
    Scenario, Phase, PeerRole,
    ScenarioEvent, PhaseEvent,
)

# Landmarks (UTM 16N from the original mission YAML → WGS84 via utm.to_latlon).
# Madison County, AL — generic civilian terrain.
GROUND_START   = (34.706505, -86.633657, 197.0)   # Squad insertion
GROUND_MID     = (34.72352, -86.63792, 195.0)     # Target area (target building)
RQ86_ORBIT     = (34.724448, -86.639802, 5000.0)  # Overhead orbit center
MQ800_INGRESS  = (34.715000, -86.580000, 600.0)   # MQ-800 enters from the east
JET_INGRESS    = (34.724448, -86.453789, 400.0)   # ~17 km east of target
JET_EGRESS     = (34.724448, -86.825815, 400.0)   # mirror of ingress, ~17 km west
COMMAND_REMOTE = (33.518600, -86.810400, 200.0)   # ~135 km south (Birmingham AL)
GROUND_EXFIL   = (34.699600, -86.668604, 198.0)   # Extraction point (SW of objective)

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


# --- Squad infil / exfil movement ---------------------------------------
# The squad stages at the insertion LZ through Setup, infiltrates to the
# objective during Approach/Contact, holds there through the Rogue/ECM/
# Strike beats, then exfiltrates to a *separate* extraction point during
# Exfil. Positions are recomputed every advance_to() tick from scenario
# time -- mirroring isr.py's moving-target path, so the converging squad
# and the (also moving) target share one timeline. Microdrones stay
# co-located with the squad as vanguard recon (see _microdrone_offset).
#
# Rather than a straight LZ->objective->extraction line, the infil and
# exfil legs *meander* through a string of randomly-perturbed waypoints
# (>=10 total) so the track reads like a real dismounted advance rather
# than a ruler line. The four narrative anchors are fixed -- staged at
# the LZ (T+0:00/T+1:00), objective reached (T+3:00), held (T+7:00),
# extracted (T+8:00) -- and the wander waypoints are inserted between
# them. A per-scenario seed keeps the path reproducible for playback and
# tests while still being randomly generated.
_SQUAD_WANDER_SEED = 0xD0D5EED   # default; override via constructor seed=
_APPROACH_LEGS = 6               # wander waypoints on the LZ->objective leg
_EXFIL_LEGS = 3                  # wander waypoints on the objective->exfil leg
_WANDER_DEG = 0.0024             # ~265 m max lateral wander per waypoint
                                 # (wide enough to read as a real meander,
                                 # not a near-straight line)

_DEG_PER_M = 1.0 / 111320.0   # latitude degrees per metre (small-angle)


def _lerp3(a, b, f):
    """Linear interpolation between two (lat, lon, alt) tuples."""
    return (a[0] + f * (b[0] - a[0]),
            a[1] + f * (b[1] - a[1]),
            a[2] + f * (b[2] - a[2]))


def _build_squad_waypoints(seed=_SQUAD_WANDER_SEED):
    """Time-keyed squad path with random wander between fixed anchors.

    Returns a list of ``(t_seconds, (lat, lon, alt))`` waypoints (>=10).
    The anchors at T+0:00, T+1:00 (LZ), T+3:00 / T+7:00 (objective) and
    T+8:00 (extraction) are exact; intermediate waypoints meander up to
    ``_WANDER_DEG`` either side of the straight leg. Deterministic for a
    given ``seed`` so recordings and tests stay reproducible."""
    rng = random.Random(seed)

    def _wander(base):
        return (base[0] + rng.uniform(-1.0, 1.0) * _WANDER_DEG,
                base[1] + rng.uniform(-1.0, 1.0) * _WANDER_DEG,
                base[2])

    wps = [(0.0, GROUND_START),    # T+0:00  staged at the insertion LZ
           (60.0, GROUND_START)]   # T+1:00  hold through Setup
    # Approach leg: meander from the LZ to the objective (T+1:00..T+3:00).
    for k in range(1, _APPROACH_LEGS + 1):
        f = k / (_APPROACH_LEGS + 1)
        t = 60.0 + f * (180.0 - 60.0)
        wps.append((t, _wander(_lerp3(GROUND_START, GROUND_MID, f))))
    wps.append((180.0, GROUND_MID))   # T+3:00  infiltrated to the objective
    wps.append((420.0, GROUND_MID))   # T+7:00  hold at the objective
    # Exfil leg: meander from the objective to the extraction point.
    for k in range(1, _EXFIL_LEGS + 1):
        f = k / (_EXFIL_LEGS + 1)
        t = 420.0 + f * (480.0 - 420.0)
        wps.append((t, _wander(_lerp3(GROUND_MID, GROUND_EXFIL, f))))
    wps.append((480.0, GROUND_EXFIL))  # T+8:00  exfiltrated to extraction
    return wps


def _interp_path(secs, waypoints):
    """Piecewise-linear (lat, lon, alt) along a time-keyed waypoint list.

    Clamps to the first/last waypoint outside the path's time span."""
    if secs <= waypoints[0][0]:
        return waypoints[0][1]
    if secs >= waypoints[-1][0]:
        return waypoints[-1][1]
    for (t0, p0), (t1, p1) in zip(waypoints, waypoints[1:]):
        if t0 <= secs <= t1:
            f = (secs - t0) / (t1 - t0) if t1 > t0 else 0.0
            return (p0[0] + f * (p1[0] - p0[0]),
                    p0[1] + f * (p1[1] - p0[1]),
                    p0[2] + f * (p1[2] - p0[2]))
    return waypoints[-1][1]


def _offset_latlon(lat, lon, east_m, north_m):
    """Shift (lat, lon) by metre offsets (small-angle approximation)."""
    dlat = north_m * _DEG_PER_M
    dlon = east_m * _DEG_PER_M / max(math.cos(math.radians(lat)), 1e-6)
    return lat + dlat, lon + dlon


def _microdrone_offset(i, swarm_size):
    """Co-location offset (east_m, north_m, alt_m) for microdrone ``i``.

    Vanguard recon hovers close to the squad: a loose ring at ~15-25 m
    horizontal radius (well inside the 200 m envelope, ~20 m average)
    and 12-20 m altitude (200 m is the platform ceiling, not the
    cruising height)."""
    bearing = (i / max(swarm_size, 1)) * 2.0 * math.pi
    radius_m = 15.0 + 5.0 * (i % 3)          # 15 / 20 / 25 m
    alt_m = 12.0 + 4.0 * (i % 3)             # 12 / 16 / 20 m
    return radius_m * math.sin(bearing), radius_m * math.cos(bearing), alt_m


# --- Air-asset orbits ---------------------------------------------------
# The RQ-86 recon pair and the MQ-800 fly broad circular orbits over the
# objective, recomputed every advance_to() tick like the squad path. The
# orbits are deliberately wide (km-scale) so the flight tracks read as
# sweeping overhead coverage rather than a static dot near the compound.
# The MQ-800 ingresses from the east and only begins its orbit once it
# arrives (phase 4), holding at its ingress point until then.
RQ86_ORBIT_RADIUS_M = 3000.0     # broad recon orbit (was 1500 m roster)
RQ86_ORBIT_PERIOD_S = 240.0      # one revolution every 4 min
MQ800_ORBIT_RADIUS_M = 2500.0    # broad rogue orbit around the objective
MQ800_ORBIT_PERIOD_S = 200.0
MQ800_JOIN_SEC = 240.0           # phase 4 ("Rogue") start — see join_phase=4


def _orbit_position(center, radius_m, period_s, base_angle_deg, secs):
    """(lat, lon, alt) on a circular orbit around ``center`` at ``secs``.

    ``center`` is a (lat, lon, alt) landmark; altitude is held constant.
    ``base_angle_deg`` offsets the starting bearing so co-orbiting assets
    stay spread around the ring."""
    theta = (math.radians(base_angle_deg)
             + 2.0 * math.pi * secs / period_s)
    east_m = radius_m * math.cos(theta)
    north_m = radius_m * math.sin(theta)
    lat, lon = _offset_latlon(center[0], center[1], east_m, north_m)
    return lat, lon, center[2]


# Fighter-jet ingress/egress. The jet holds off-map to the east until it
# joins at phase 6 (T+6:00), then makes a high-speed pass over the
# objective (~T+6:30) and egresses to the west. Tracked like the squad
# path via _interp_path, so before T+6:00 it clamps to the ingress hold
# point (well off the map) and only enters view during the Strike beat.
JET_JOIN_SEC = 360.0    # phase 6 ("Strike") start — jet joins the net (T+6:00)
JET_LAUNCH_SEC = 290.0  # T+4:50 — scrambled as the MQ-800 is excluded
JET_STRIKE_SEC = 375.0  # T+6:15 — authored high-speed pass over the objective
JET_EGRESS_SEC = 480.0  # T+8:00 — clears to the west
# The jet's strike is GATED on the MQ-800 rogue actually being exposed
# (its reputation collapsing) so the narrative always reads as "threat
# detected -> jet responds", never the jet overflying before the anomaly.
# It holds off-map until `gate_jet_on_anomaly` fires, then strikes no
# sooner than this many seconds later (and never before its authored time).
JET_ANOMALY_HOLD_SEC = 10.0
# Safety net: in a degenerate run where the rogue never produces a
# detectable collapse, release the jet once the clock passes this so the
# demo still completes instead of holding the strike forever.
JET_HOLD_CEILING_SEC = 540.0
# Authored waypoints, used only when there is no rogue to gate on
# (`include_mq800=False`); the gated path is built by
# DoDMissionScenario._jet_waypoints anchored to the actual strike time.
_JET_WAYPOINTS = [
    (0.0,            JET_INGRESS),  # parked off-map east
    (JET_LAUNCH_SEC, JET_INGRESS),  # launch — begins the ingress run
    # Timed so the jet crosses into the map view (~3 km out) right at the
    # T+6:00 narration "arrives" beat and overflies the objective at the
    # strike, matching the narration / strike annotation instead of
    # trailing ~25 s behind them.
    (JET_STRIKE_SEC, GROUND_MID),   # high-speed pass over the objective
    (JET_EGRESS_SEC, JET_EGRESS),   # egresses to the west
]
# Ingress-run / egress-run durations, preserved when the gated strike
# time slides later than the authored one.
_JET_INGRESS_RUN_SEC = JET_STRIKE_SEC - JET_LAUNCH_SEC   # 85s lead-in
_JET_EGRESS_RUN_SEC = JET_EGRESS_SEC - JET_STRIKE_SEC    # 105s trail-off

# The rogue peer whose exposure releases the jet.
ROGUE_PEER_NAME = "mq800"


# Phase 6 #2 rank-gate: minimum fraction of admitted peers that must
# have completed AT-core bootstrap (peer._tier >= 1) before the
# scenario consents to leave Setup. 0.9 mirrors the architecture-doc
# value; override at runtime via DoDMissionScenario instance attribute
# `_approach_gate_threshold` if a test needs to drive a different point.
APPROACH_TIER_THRESHOLD = 1
APPROACH_FRACTION_REQUIRED = 0.9


def _bootstrap_gate(scenario) -> bool:
    """Phase gate for the Approach transition.

    Consults the scenario's ``_tier_view_provider`` (a callable
    returning ``{peer_name: tier_int}``) which the live coordinator
    attaches at init time. Returns True (gate open) when:
      - no provider is attached (playback mode without a live coord,
        or a test that doesn't care about bootstrap), OR
      - ≥ APPROACH_FRACTION_REQUIRED of admitted peers have
        ``tier >= APPROACH_TIER_THRESHOLD``.

    A provider that returns an empty dict is treated as "no peers
    formed yet" → gate stays closed. This keeps the Setup phase
    visibly held until bootstrap actually starts.
    """
    provider = getattr(scenario, "_tier_view_provider", None)
    if provider is None:
        return True
    try:
        tiers = provider() or {}
    except Exception:
        # Provider error: don't deadlock the scenario — log via the
        # advance_to handler (it catches our return) and default open.
        return True
    if not tiers:
        return False
    threshold = getattr(scenario, "_approach_gate_threshold",
                        APPROACH_TIER_THRESHOLD)
    fraction = getattr(scenario, "_approach_gate_fraction",
                       APPROACH_FRACTION_REQUIRED)
    at_or_above = sum(1 for t in tiers.values() if int(t) >= threshold)
    return at_or_above >= fraction * len(tiers)


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
                 include_command: bool = True,
                 seed: int = _SQUAD_WANDER_SEED):
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
        # Movement bookkeeping (populated by _define_squad / _define_
        # microdrones, consumed by _update_positions). Initialised before
        # super().__init__() because that calls self.define().
        self._squad_offsets: dict[str, tuple[float, float]] = {}
        self._microdrone_index: dict[str, int] = {}
        # RQ-86 orbit phase offsets (name -> base bearing deg), populated
        # by _define_rq86s and consumed by _update_positions.
        self._rq86_orbits: dict[str, float] = {}
        # Scenario-seconds at which the MQ-800 rogue's reputation collapsed
        # (set by gate_jet_on_anomaly from the live coordinator or replayed
        # in playback). None = not yet exposed -> the jet holds off-map.
        self._jet_anomaly_sec = None
        # Randomly-wandering infil/exfil path (>=10 waypoints), seeded so
        # it is reproducible across playback/tests. See _build_squad_waypoints.
        self._squad_waypoints = _build_squad_waypoints(seed)
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

    # --- movement ------------------------------------------------------

    def advance_to(self, scenario_time: timedelta):
        """Advance phases/events, then move the squad + microdrones.

        Movement is layered on top of the base phase/event logic so the
        live coordinator and the playback engine -- both of which call
        ``advance_to`` every tick -- animate the infil/exfil without any
        extra plumbing. See _build_squad_waypoints."""
        super().advance_to(scenario_time)
        self._update_positions(scenario_time)

    def _update_positions(self, scenario_time: timedelta):
        secs = scenario_time.total_seconds()
        c_lat, c_lon, c_alt = _interp_path(secs, self._squad_waypoints)
        # Squad members keep their rigid lateral spread around the centroid.
        for name, (d_lat, d_lon) in self._squad_offsets.items():
            role = self._peers.get(name)
            if role is not None:
                role.position = GeoPosition(c_lat + d_lat, c_lon + d_lon,
                                            c_alt)
        # Microdrones track the squad as a co-located vanguard ring.
        for name, i in self._microdrone_index.items():
            role = self._peers.get(name)
            if role is None:
                continue
            east_m, north_m, alt_m = _microdrone_offset(i, self._swarm_size)
            m_lat, m_lon = _offset_latlon(c_lat, c_lon, east_m, north_m)
            role.position = GeoPosition(m_lat, m_lon, alt_m)
        # RQ-86 recon pair fly broad circular orbits over the objective.
        for name, base_ang in self._rq86_orbits.items():
            role = self._peers.get(name)
            if role is None:
                continue
            o_lat, o_lon, o_alt = _orbit_position(
                RQ86_ORBIT, RQ86_ORBIT_RADIUS_M, RQ86_ORBIT_PERIOD_S,
                base_ang, secs)
            role.position = GeoPosition(o_lat, o_lon, o_alt)
        # MQ-800 flies a broad orbit around the objective once it has
        # ingressed (phase 4); it holds at its eastern ingress point until
        # then so the arrival reads as a distinct beat.
        if self._include_mq800 and secs >= MQ800_JOIN_SEC:
            role = self._peers.get("mq800")
            if role is not None:
                o_lat, o_lon, o_alt = _orbit_position(
                    GROUND_MID, MQ800_ORBIT_RADIUS_M, MQ800_ORBIT_PERIOD_S,
                    0.0, secs - MQ800_JOIN_SEC)
                role.position = GeoPosition(o_lat, o_lon, MQ800_INGRESS[2])
        # Fighter jet: high-speed ingress pass over the objective during
        # the Strike phase, then egress. Holds off-map east until the rogue
        # is exposed (see _jet_strike_time / gate_jet_on_anomaly) so it never
        # overflies before the MQ-800 anomaly the narrative depends on.
        if self._include_jet:
            role = self._peers.get("jet-1")
            if role is not None:
                launch_sec = self._jet_launch_time(secs)
                if launch_sec is None:
                    # Rogue not yet exposed — park at the off-map ingress hold.
                    j_lat, j_lon, j_alt = JET_INGRESS
                else:
                    j_lat, j_lon, j_alt = _interp_path(
                        secs, self._jet_waypoints(launch_sec))
                role.position = GeoPosition(j_lat, j_lon, j_alt)
        # Leave-behind sensors are emplaced and stationary — their roster
        # positions are already correct, so no per-tick update is needed;
        # they are surfaced as tracked assets by the coordinator's
        # platform feed.

    # --- jet strike gating ---------------------------------------------

    def gate_jet_on_anomaly(self, peer_name, secs) -> None:
        """Release the fighter jet once the MQ-800 rogue is exposed.

        Called for every successful reputation slash (live coordinator) or
        every replayed slash marker (canned playback). Only the rogue's
        collapse counts, and only the first one — later slashes/re-detections
        can't push the strike around. No-op when the jet or rogue is disabled
        for this run, leaving the authored timing untouched.
        """
        if peer_name != ROGUE_PEER_NAME:
            return
        if not (self._include_jet and self._include_mq800):
            return
        if self._jet_anomaly_sec is None:
            self._jet_anomaly_sec = float(secs)

    def _jet_launch_time(self, secs):
        """Scenario-seconds at which the jet *begins its ingress run* (leaves
        the off-map hold), or ``None`` while it must keep holding.

        With no rogue to gate on the jet keeps its authored launch. With the
        rogue, it holds off-map until the collapse (`gate_jet_on_anomaly`)
        plus a short beat, never earlier than its authored launch — then
        flies the full authored ingress run in, so the pass always reads as
        "threat exposed -> jet scrambles -> strike" with no teleport. A
        ceiling releases a never-exposed rogue's run so the demo can't hang.

        Anchoring to launch (not the strike) is deliberate: the ingress run
        is ~85s, so a strike pinned to anomaly+10s would force the jet to
        have "launched" before the anomaly and snap forward when released.
        """
        if not self._include_mq800:
            return JET_LAUNCH_SEC
        if self._jet_anomaly_sec is None:
            if secs >= JET_HOLD_CEILING_SEC:
                self._jet_anomaly_sec = secs - JET_ANOMALY_HOLD_SEC
            else:
                return None
        return max(JET_LAUNCH_SEC,
                   self._jet_anomaly_sec + JET_ANOMALY_HOLD_SEC)

    def _jet_waypoints(self, launch_sec):
        """Ingress→strike→egress waypoints anchored to ``launch_sec``,
        preserving the authored ingress-run and egress-run durations so a
        delayed launch still flies the same visual pass, just later (strike
        = launch + ingress run)."""
        strike_sec = launch_sec + _JET_INGRESS_RUN_SEC
        return [
            (0.0, JET_INGRESS),                          # parked off-map
            (launch_sec, JET_INGRESS),                   # launch — begin ingress
            (strike_sec, GROUND_MID),                    # pass over objective
            (strike_sec + _JET_EGRESS_RUN_SEC, JET_EGRESS),  # egress west
        ]

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
            # Lateral spread (degrees) preserved as a rigid offset from the
            # squad centroid so members keep formation as the squad moves.
            lat_off, lon_off = 0.00002 * i, 0.00002 * (i % 2 - 0.5)
            self._squad_offsets[name] = (lat_off, lon_off)
            self.add_peer(PeerRole(
                name=name,
                agency="ODA",
                kind="soldier",
                position=_pos(GROUND_START,
                              lat_jitter=lat_off,
                              lon_jitter=lon_off),
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
            self._microdrone_index[f"microdrone-{i+1}"] = i
            self.add_peer(PeerRole(
                name=f"microdrone-{i+1}",
                agency="ODA",
                kind="microdrone",
                # Co-located with the squad: vanguard recon hovering close
                # by (<=200 m in any direction), not racing ahead. Initial
                # horizontal offset averages ~15 m; hover altitude averages
                # 10-20 m (200 m is the platform ceiling, not the norm).
                # Once squad movement is driven, drones track the squad's
                # current position under the same co-location envelope.
                position=_pos(GROUND_START,
                              lat_jitter=0.00005 * (i + 1),
                              lon_jitter=0.00005 * ((i + 1) % 3 - 1),
                              alt=12.0 + 4.0 * (i % 3)),
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
            self._rq86_orbits[f"rq86-{i+1}"] = angle_offset
            # Seed the roster position on the orbit ring (at t=0) so the
            # peer's home location already sits on its broad flight path.
            o_lat, o_lon, _ = _orbit_position(
                RQ86_ORBIT, RQ86_ORBIT_RADIUS_M, RQ86_ORBIT_PERIOD_S,
                angle_offset, 0.0)
            self.add_peer(PeerRole(
                name=f"rq86-{i+1}",
                agency="Air-Support",
                kind="recon-drone",
                position=GeoPosition(o_lat, o_lon, RQ86_ORBIT[2]),
                color=RQ86_GOLD,
                join_phase=0,
                capabilities=["electro_optical", "infrared", "sar", "mti_radar",
                              "sigint", "ecm", "comm_relay", "target_track"],
                metadata={"orbit_radius_m": RQ86_ORBIT_RADIUS_M,
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
        # Gated on bootstrap completion (Phase 6 #2). Holds the scene
        # at Setup until ≥90% of admitted peers have reached
        # `peer._tier >= 1`. Belt-and-suspenders for the AT-core
        # BootstrapWorker — if the bootstrap corpus stalls, the
        # demo waits visibly instead of launching the squad over an
        # un-formed network. Coordinator attaches the live tier view
        # via scenario._tier_view_provider after construction; if no
        # provider is wired (playback mode without live coord), the
        # gate defaults to OPEN so existing recordings replay as-is.
        self.add_phase(Phase(
            name="Approach",
            start=timedelta(minutes=1),
            description="Squad advances toward the target; microdrone swarm "
                        "sweeps ahead extending the squad's detection envelope.",
            gate=_bootstrap_gate,
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
                # Aligned with the jet's visual pass over the objective
                # (JET_STRIKE_SEC = T+6:15) so the event log, the map, and
                # the narration tell the same beat at the same moment.
                timestamp=timedelta(minutes=6, seconds=15),
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
    parser.add_argument("--seed", type=lambda s: int(s, 0),
                        default=_SQUAD_WANDER_SEED,
                        help="seed for the random squad infil/exfil wander")
    args = parser.parse_args()

    sc = DoDMissionScenario(
        squad_size=args.squad_size,
        swarm_size=args.swarm_size,
        sensor_count=args.sensor_count,
        hacked_sensors=args.hacked_sensors,
        include_mq800=not args.no_mq800,
        include_jet=not args.no_jet,
        include_command=not args.no_command,
        seed=args.seed,
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
