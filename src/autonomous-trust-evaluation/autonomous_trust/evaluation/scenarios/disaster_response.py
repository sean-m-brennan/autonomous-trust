# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

"""Multi-agency disaster-response scenario.

Implements the HighTrust whitepaper's multi-agency (NOAA / USGS / FEMA /
EPA) federal data-sharing demo. 10 peers run across Minikube; one NOAA
weather sensor has valid ZTA credentials but goes rogue at T+4:00. The
AT reputation system is expected to detect the divergence via corroboration
against honest sources and autonomously exclude the compromised peer.

Phase timeline (matches demo-implementation-plan.md §Scenario Phases):

    T+0:00  Formation     -- peers discover each other / identity exchange
    T+0:30  Bootstrap     -- cautious small data exchanges
    T+1:30  Negotiation   -- FEMA requests weather + seismic streams
    T+2:30  Sharing       -- full data flows, reputation converges
    T+4:00  Compromise    -- noaa-3 begins emitting falsified readings
    T+4:30  Detection     -- peers score noaa-3 low via gossip consensus
    T+5:00  Exclusion     -- network cuts off noaa-3
    T+6:00  Onboarding    -- EPA joins with zero AT reputation
    T+7:00  Integration   -- EPA earns trust, full sharing
"""

from __future__ import annotations

from datetime import timedelta

try:
    from autonomous_trust.services.peer.position import GeoPosition
except ImportError:
    # Minimal fallback for environments without the full AT package
    # (e.g. unit tests, scenario export for canned playback). The engine
    # only reads lat/lon/alt off GeoPosition.
    class GeoPosition:  # type: ignore[no-redef]
        def __init__(self, lat: float, lon: float, alt: float | None = None):
            self.lat = float(lat)
            self.lon = float(lon)
            self.alt = None if alt is None else float(alt)

from .scenario import (
    Phase,
    PhaseEvent,
    PeerRole,
    Scenario,
    ScenarioEvent,
)


# Agency color palette (federal-appropriate, matches dashboard CSS).
AGENCY_COLORS = {
    "NOAA": "#1f77b4",  # blue
    "USGS": "#8c564b",  # brown
    "FEMA": "#d62728",  # red
    "EPA":  "#2ca02c",  # green
}

# Data-type capability strings advertised by each role.
CAP_WEATHER_STREAM   = "weather_stream"
CAP_SEISMIC_STREAM   = "seismic_stream"
CAP_AIRQUALITY_STREAM = "airquality_stream"
CAP_DATA_FUSION      = "data_fusion"
CAP_SITUATION_REPORT = "situation_report"
CAP_SENSOR_VALIDATE  = "sensor_validation"

# Scenario region: Pacific Northwest / Cascadia -- plausible combined
# weather + seismic disaster context. Positions are plausible; any decent
# map projection will show them as a coherent deployment.
_PNW_CENTER_LAT = 46.75
_PNW_CENTER_LON = -122.50


class DisasterResponseScenario(Scenario):
    """HighTrust multi-agency demo: disaster response.

    Ten peers across four federal agencies discover each other, exchange
    environmental data through the AT negotiation protocol, and autonomously
    exclude a compromised NOAA sensor. EPA joins mid-crisis and earns trust
    through demonstrated behavior.
    """

    @property
    def name(self) -> str:
        return "Disaster Response"

    @property
    def description(self) -> str:
        return (
            "Multi-agency federal data sharing during a Pacific Northwest "
            "disaster. NOAA weather, USGS seismic, FEMA ops, and EPA air "
            "quality peers negotiate data exchange machine-to-machine. "
            "A compromised NOAA sensor with valid ZTA credentials is "
            "detected and excluded autonomously."
        )

    # ------------------------------------------------------------------

    def define(self):
        self._define_peers()
        self._define_phases()
        self._define_compromise_timeline()

    # ------------------------------------------------------------------
    # Peer roster
    # ------------------------------------------------------------------

    def _define_peers(self):
        # Three honest NOAA weather stations spread across the region.
        self.add_peer(PeerRole(
            name="noaa-1",
            agency="NOAA",
            kind="weather-sensor",
            position=GeoPosition(_PNW_CENTER_LAT + 0.35, _PNW_CENTER_LON - 0.40),
            color=AGENCY_COLORS["NOAA"],
            join_phase=0,
            capabilities=[CAP_WEATHER_STREAM, CAP_SENSOR_VALIDATE],
            metadata={"station_id": "KPDX-AUX-1", "altitude_m": 12},
        ))
        self.add_peer(PeerRole(
            name="noaa-2",
            agency="NOAA",
            kind="weather-sensor",
            position=GeoPosition(_PNW_CENTER_LAT - 0.25, _PNW_CENTER_LON + 0.15),
            color=AGENCY_COLORS["NOAA"],
            join_phase=0,
            capabilities=[CAP_WEATHER_STREAM, CAP_SENSOR_VALIDATE],
            metadata={"station_id": "KOLM-AUX-1", "altitude_m": 60},
        ))
        # noaa-3 is the rogue station (has valid ZTA credentials -- AT must
        # catch it through behavior, not identity). metadata.compromised
        # is consulted by the data service at runtime; the reputation
        # system has no knowledge of this flag.
        self.add_peer(PeerRole(
            name="noaa-3",
            agency="NOAA",
            kind="weather-sensor",
            position=GeoPosition(_PNW_CENTER_LAT + 0.05, _PNW_CENTER_LON - 0.10),
            color=AGENCY_COLORS["NOAA"],
            join_phase=0,
            capabilities=[CAP_WEATHER_STREAM, CAP_SENSOR_VALIDATE],
            metadata={
                "station_id": "KSEA-AUX-X",
                "altitude_m": 130,
                "compromised": True,
                "compromise_onset_sec": 240.0,  # T+4:00
                "compromise_modes": [
                    "temperature_drift",
                    "wind_spikes",
                    "pressure_flatline",
                    "precipitation_invert",
                ],
            },
        ))

        # Fourth honest NOAA station -- rounds the roster to 10 peers per
        # the plan's total. noaa-3 is still the rogue; noaa-4 corroborates.
        self.add_peer(PeerRole(
            name="noaa-4",
            agency="NOAA",
            kind="weather-sensor",
            position=GeoPosition(_PNW_CENTER_LAT - 0.10, _PNW_CENTER_LON - 0.30),
            color=AGENCY_COLORS["NOAA"],
            join_phase=0,
            capabilities=[CAP_WEATHER_STREAM, CAP_SENSOR_VALIDATE],
            metadata={"station_id": "KHQM-AUX-1", "altitude_m": 5},
        ))

        # USGS seismic monitors.
        self.add_peer(PeerRole(
            name="usgs-1",
            agency="USGS",
            kind="seismic-monitor",
            position=GeoPosition(_PNW_CENTER_LAT - 0.45, _PNW_CENTER_LON - 0.55),
            color=AGENCY_COLORS["USGS"],
            join_phase=0,
            capabilities=[CAP_SEISMIC_STREAM, CAP_SENSOR_VALIDATE],
            metadata={"station_id": "CC.LON", "altitude_m": 260},
        ))
        self.add_peer(PeerRole(
            name="usgs-2",
            agency="USGS",
            kind="seismic-monitor",
            position=GeoPosition(_PNW_CENTER_LAT + 0.15, _PNW_CENTER_LON + 0.40),
            color=AGENCY_COLORS["USGS"],
            join_phase=0,
            capabilities=[CAP_SEISMIC_STREAM, CAP_SENSOR_VALIDATE],
            metadata={"station_id": "UW.OLGA", "altitude_m": 180},
        ))

        # FEMA operations.
        self.add_peer(PeerRole(
            name="fema-field-1",
            agency="FEMA",
            kind="field-station",
            position=GeoPosition(_PNW_CENTER_LAT - 0.05, _PNW_CENTER_LON - 0.20),
            color=AGENCY_COLORS["FEMA"],
            join_phase=0,
            capabilities=[CAP_SITUATION_REPORT],
            metadata={"unit": "FEMA-R10-FS1", "mobile": True},
        ))
        self.add_peer(PeerRole(
            name="fema-field-2",
            agency="FEMA",
            kind="field-station",
            position=GeoPosition(_PNW_CENTER_LAT + 0.20, _PNW_CENTER_LON + 0.10),
            color=AGENCY_COLORS["FEMA"],
            join_phase=0,
            capabilities=[CAP_SITUATION_REPORT],
            metadata={"unit": "FEMA-R10-FS2", "mobile": True},
        ))
        self.add_peer(PeerRole(
            name="fema-fusion",
            agency="FEMA",
            kind="fusion-node",
            position=GeoPosition(_PNW_CENTER_LAT, _PNW_CENTER_LON),
            color=AGENCY_COLORS["FEMA"],
            join_phase=0,
            capabilities=[CAP_DATA_FUSION, CAP_SITUATION_REPORT],
            metadata={"unit": "FEMA-R10-HQ"},
        ))

        # EPA -- late joiner, arrives at Phase 7 (T+6:00).
        self.add_peer(PeerRole(
            name="epa-1",
            agency="EPA",
            kind="air-quality-monitor",
            position=GeoPosition(_PNW_CENTER_LAT - 0.10, _PNW_CENTER_LON + 0.05),
            color=AGENCY_COLORS["EPA"],
            join_phase=7,
            capabilities=[CAP_AIRQUALITY_STREAM, CAP_SENSOR_VALIDATE],
            metadata={"station_id": "EPA-AQS-PNW-1", "altitude_m": 80},
        ))

    # ------------------------------------------------------------------
    # Phase timeline
    # ------------------------------------------------------------------

    def _define_phases(self):
        self.add_phase(Phase(
            name="Formation",
            start=timedelta(seconds=0),
            description=(
                "NOAA, USGS, and FEMA nodes discover each other. "
                "Identity exchange and ZTA verification."
            ),
        ))
        self.add_phase(Phase(
            name="Bootstrap",
            start=timedelta(seconds=30),
            description=(
                "Cautious small data exchanges. Reputation ramp-up via "
                "contrite tit-for-tat."
            ),
        ))
        self.add_phase(Phase(
            name="Negotiation",
            start=timedelta(seconds=90),
            description=(
                "FEMA-fusion negotiates weather_stream and seismic_stream "
                "subscriptions via the AT task protocol."
            ),
        ))
        self.add_phase(Phase(
            name="Sharing",
            start=timedelta(seconds=150),
            description=(
                "Full data flows established. Bilateral trust scores "
                "stabilize as peers corroborate readings."
            ),
        ))
        self.add_phase(Phase(
            name="Compromise",
            start=timedelta(seconds=240),
            description=(
                "noaa-3 has been compromised. It has valid credentials and "
                "passes all ZTA checks, but its readings begin to drift "
                "from the other NOAA sensors and USGS corroboration."
            ),
        ))
        self.add_phase(Phase(
            name="Detection",
            start=timedelta(seconds=270),
            description=(
                "Peers independently observe divergence from corroborating "
                "sources. Gossip consensus propagates low scores for noaa-3."
            ),
        ))
        self.add_phase(Phase(
            name="Exclusion",
            start=timedelta(seconds=300),
            description=(
                "noaa-3 reputation has collapsed below the sharing threshold. "
                "The network autonomously stops listening to it."
            ),
        ))
        self.add_phase(Phase(
            name="Onboarding",
            start=timedelta(seconds=360),
            description=(
                "EPA-1 arrives mid-crisis with valid ZTA credentials. AT "
                "starts it at zero reputation -- identity is not trust."
            ),
        ))
        self.add_phase(Phase(
            name="Integration",
            start=timedelta(seconds=420),
            description=(
                "EPA-1 has earned sufficient reputation through consistent "
                "behavior. Full data sharing established."
            ),
        ))

    # ------------------------------------------------------------------
    # Compromise timeline events
    # ------------------------------------------------------------------

    def _define_compromise_timeline(self):
        """Register explicit events for the compromise narrative.

        Detection and exclusion events are scheduled optimistically -- if
        the live AT reputation system doesn't actually catch the compromise,
        these events are still emitted on the timeline (for the event log
        and canned playback) but the real cutoff in a live run must come
        from the reputation system itself. The UI should distinguish
        'scheduled' vs 'observed' via event metadata.data["source"].
        """
        self.add_event("Compromise", ScenarioEvent(
            timestamp=timedelta(seconds=240),
            event_type=PhaseEvent.COMPROMISE_START,
            peer_name="noaa-3",
            description=(
                "noaa-3 begins emitting falsified readings (gradual +5F "
                "temperature drift, wind spikes, pressure flatline, "
                "inverted precipitation). Credentials remain valid."
            ),
            data={"source": "scenario", "modes": [
                "temperature_drift", "wind_spikes",
                "pressure_flatline", "precipitation_invert",
            ]},
        ))
        self.add_event("Detection", ScenarioEvent(
            timestamp=timedelta(seconds=270),
            event_type=PhaseEvent.COMPROMISE_DETECT,
            peer_name="noaa-3",
            description=(
                "noaa-3 readings diverge from noaa-1 and noaa-2 by more "
                "than two standard deviations. Peers independently lower "
                "their bilateral scores; gossip consensus converges."
            ),
            data={"source": "scenario"},
        ))
        self.add_event("Exclusion", ScenarioEvent(
            timestamp=timedelta(seconds=300),
            event_type=PhaseEvent.PEER_EXCLUDE,
            peer_name="noaa-3",
            description=(
                "noaa-3 reputation below sharing threshold. Network cuts "
                "off data channels; honest NOAA stations continue sharing."
            ),
            data={"source": "scenario"},
        ))

        # Narration callouts for presentation mode. These are informational
        # only -- they appear in the event log and the narration overlay.
        self.add_event("Compromise", ScenarioEvent(
            timestamp=timedelta(seconds=241),
            event_type=PhaseEvent.ANNOTATION,
            description=(
                "A valid ZTA-authenticated peer has gone rogue. Zero Trust "
                "cannot detect this -- the credentials are still good. "
                "Watch the reputation traces."
            ),
            data={"source": "narration"},
        ))
        self.add_event("Detection", ScenarioEvent(
            timestamp=timedelta(seconds=271),
            event_type=PhaseEvent.ANNOTATION,
            description=(
                "The network decided. No human operator flagged noaa-3 -- "
                "each peer reached the same conclusion independently from "
                "cross-source corroboration."
            ),
            data={"source": "narration"},
        ))
        self.add_event("Onboarding", ScenarioEvent(
            timestamp=timedelta(seconds=361),
            event_type=PhaseEvent.ANNOTATION,
            description=(
                "EPA-1 arrives with valid ZTA credentials and zero AT "
                "reputation. Identity is not trust; trust must be earned."
            ),
            data={"source": "narration"},
        ))
        self.add_event("Integration", ScenarioEvent(
            timestamp=timedelta(seconds=421),
            event_type=PhaseEvent.ANNOTATION,
            description=(
                "EPA-1 has earned trust through demonstrated data quality. "
                "Full data sharing, no human coordination required."
            ),
            data={"source": "narration"},
        ))
