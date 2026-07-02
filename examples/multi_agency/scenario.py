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

"""
Multi-Agency Federal Data Sharing Scenario — Disaster Response.

10 peers from 4 federal agencies responding to Hurricane Helene making
landfall near Wilmington, NC.  Demonstrates AutonomousTrust's ability to
autonomously form cross-agency data-sharing networks and detect/exclude
a compromised sensor sending falsified weather data.

Peers:
  NOAA  (blue):   3 weather sensors along the coast
  USGS  (green):  2 seismic/ground-motion monitors inland
  FEMA  (orange): 2 field stations + 1 fusion center
  EPA   (purple): 1 air quality monitor (joins late)

Timeline (8 phases, ~8 minutes):
  T+0:00  Formation     — NOAA, USGS, FEMA peers discover each other
  T+1:00  Bootstrap     — Trust graph stabilizes, reputation reaches 0.7+
  T+2:00  Negotiation   — Peers negotiate data-sharing agreements
  T+2:30  Data Sharing  — Weather/seismic streams begin flowing
  T+4:00  Compromise    — NOAA-Sensor-3 begins sending falsified temp data
  T+4:30  Detection     — Network detects anomaly via cross-source validation
  T+5:00  Exclusion     — Compromised sensor's reputation collapses, excluded
  T+6:00  EPA Onboard   — EPA monitor joins post-exclusion
  T+7:00  Integration   — EPA fully integrated, data sharing resumes at full
  T+8:00  End

Geography: Coastal North Carolina
  NOAA sensors: Wrightsville Beach, Carolina Beach, Topsail Beach
  USGS monitors: Castle Hayne, Burgaw (inland)
  FEMA stations: Wilmington Convention Center, Leland
  FEMA fusion:  Raleigh
  EPA monitor:  Wilmington downtown
"""

from datetime import timedelta

from autonomous_trust.evaluation.scenarios.scenario import (
    GeoPosition,
    Scenario, Phase, PeerRole, PeerState,
    ScenarioEvent, PhaseEvent,
)

# Agency colors (CSS)
NOAA_BLUE = "#1E90FF"
USGS_GREEN = "#2E8B57"
FEMA_ORANGE = "#FF8C00"
EPA_PURPLE = "#8B5CF6"


class DisasterResponseScenario(Scenario):
    """Multi-agency disaster response scenario for the demo."""

    @property
    def name(self) -> str:
        return "disaster-response"

    @property
    def description(self) -> str:
        return (
            "Multi-agency federal data sharing during Hurricane Helene response. "
            "10 peers from NOAA, USGS, FEMA, and EPA autonomously form a trust "
            "network, share environmental data, detect a compromised weather "
            "sensor, and exclude it — all without human intervention."
        )

    def define(self):
        self._define_peers()
        self._define_phases()

    def _define_peers(self):
        # --- NOAA Weather Sensors (coastal NC) ---
        self.add_peer(PeerRole(
            name="noaa-sensor-1",
            agency="NOAA",
            kind="weather-station",
            position=GeoPosition(34.2088, -77.7964),  # Wrightsville Beach
            color=NOAA_BLUE,
            join_phase=0,
            capabilities=["weather_stream", "temperature", "wind", "pressure",
                          "precipitation"],
            metadata={"station_id": "NOAA-WXS-041", "location": "Wrightsville Beach"},
        ))
        self.add_peer(PeerRole(
            name="noaa-sensor-2",
            agency="NOAA",
            kind="weather-station",
            position=GeoPosition(34.0493, -77.8932),  # Carolina Beach
            color=NOAA_BLUE,
            join_phase=0,
            capabilities=["weather_stream", "temperature", "wind", "pressure",
                          "precipitation"],
            metadata={"station_id": "NOAA-WXS-042", "location": "Carolina Beach"},
        ))
        self.add_peer(PeerRole(
            name="noaa-sensor-3",
            agency="NOAA",
            kind="weather-station",
            position=GeoPosition(34.3543, -77.6360),  # Topsail Beach
            color=NOAA_BLUE,
            join_phase=0,
            capabilities=["weather_stream", "temperature", "wind", "pressure",
                          "precipitation"],
            metadata={
                "station_id": "NOAA-WXS-043",
                "location": "Topsail Beach",
                "compromised": True,  # This sensor will be compromised
            },
        ))

        # --- USGS Seismic Monitors (inland) ---
        self.add_peer(PeerRole(
            name="usgs-monitor-1",
            agency="USGS",
            kind="seismic-monitor",
            position=GeoPosition(34.3521, -77.9016),  # Castle Hayne
            color=USGS_GREEN,
            join_phase=0,
            capabilities=["seismic_stream", "ground_motion", "magnitude"],
            metadata={"station_id": "USGS-SEI-017", "location": "Castle Hayne"},
        ))
        self.add_peer(PeerRole(
            name="usgs-monitor-2",
            agency="USGS",
            kind="seismic-monitor",
            position=GeoPosition(34.5519, -77.9261),  # Burgaw
            color=USGS_GREEN,
            join_phase=0,
            capabilities=["seismic_stream", "ground_motion", "magnitude"],
            metadata={"station_id": "USGS-SEI-018", "location": "Burgaw"},
        ))

        # --- FEMA Field Stations + Fusion Center ---
        self.add_peer(PeerRole(
            name="fema-field-1",
            agency="FEMA",
            kind="field-station",
            position=GeoPosition(34.2358, -77.9448),  # Wilmington Conv Ctr
            color=FEMA_ORANGE,
            join_phase=0,
            capabilities=["data_fusion", "validation", "coordination"],
            metadata={"station_id": "FEMA-FS-201", "location": "Wilmington"},
        ))
        self.add_peer(PeerRole(
            name="fema-field-2",
            agency="FEMA",
            kind="field-station",
            position=GeoPosition(34.2168, -78.0456),  # Leland
            color=FEMA_ORANGE,
            join_phase=0,
            capabilities=["data_fusion", "validation"],
            metadata={"station_id": "FEMA-FS-202", "location": "Leland"},
        ))
        self.add_peer(PeerRole(
            name="fema-fusion",
            agency="FEMA",
            kind="fusion-center",
            position=GeoPosition(35.7796, -78.6382),  # Raleigh
            color=FEMA_ORANGE,
            join_phase=0,
            capabilities=["data_fusion", "validation", "coordination",
                          "situation_report"],
            metadata={"station_id": "FEMA-FC-100", "location": "Raleigh"},
        ))

        # --- EPA Air Quality Monitor (joins late) ---
        self.add_peer(PeerRole(
            name="epa-monitor-1",
            agency="EPA",
            kind="air-quality-monitor",
            position=GeoPosition(34.2257, -77.9447),  # Wilmington downtown
            color=EPA_PURPLE,
            join_phase=7,  # Joins during "EPA Onboard" phase (index 7)
            capabilities=["airquality_stream", "aqi", "pm25", "ozone"],
            metadata={"station_id": "EPA-AQM-301", "location": "Wilmington"},
        ))

    def _define_phases(self):
        # Phase 0: Formation (T+0:00)
        self.add_phase(Phase(
            name="Formation",
            start=timedelta(0),
            description="NOAA, USGS, and FEMA peers discover each other and "
                        "begin identity verification.",
        ))

        # Phase 1: Bootstrap (T+1:00)
        self.add_phase(Phase(
            name="Bootstrap",
            start=timedelta(minutes=1),
            description="Trust graph stabilizes. Peers reach initial reputation "
                        "of 0.7+ through successful identity exchange.",
        ))

        # Phase 2: Negotiation (T+2:00)
        self.add_phase(Phase(
            name="Negotiation",
            start=timedelta(minutes=2),
            description="Peers negotiate data-sharing agreements based on "
                        "capabilities and trust levels.",
        ))

        # Phase 3: Data Sharing (T+2:30)
        p3 = Phase(
            name="Data Sharing",
            start=timedelta(minutes=2, seconds=30),
            description="Environmental data streams begin flowing. Weather, "
                        "seismic, and situational data shared across agencies.",
        )
        p3.events.append(ScenarioEvent(
            timestamp=timedelta(minutes=2, seconds=30),
            event_type=PhaseEvent.DATA_STREAM_START,
            description="Weather and seismic data streams activated",
        ))
        self.add_phase(p3)

        # Phase 4: Compromise (T+4:00)
        p4 = Phase(
            name="Compromise",
            start=timedelta(minutes=4),
            description="NOAA-Sensor-3 at Topsail Beach begins sending "
                        "falsified temperature readings.",
        )
        p4.events.append(ScenarioEvent(
            timestamp=timedelta(minutes=4),
            event_type=PhaseEvent.COMPROMISE_START,
            peer_name="noaa-sensor-3",
            description="noaa-sensor-3 compromised: falsified temperature data",
            data={"mode": "configurable"},  # GradualDrift or AbruptDeviation
        ))
        self.add_phase(p4)

        # Phase 5: Detection (T+4:30)
        p5 = Phase(
            name="Detection",
            start=timedelta(minutes=4, seconds=30),
            description="Cross-source validation detects anomalous readings "
                        "from noaa-sensor-3. Reputation begins declining.",
        )
        p5.events.append(ScenarioEvent(
            timestamp=timedelta(minutes=4, seconds=30),
            event_type=PhaseEvent.COMPROMISE_DETECT,
            peer_name="noaa-sensor-3",
            description="Anomaly detected: noaa-sensor-3 temperature diverges "
                        "from noaa-sensor-1 and noaa-sensor-2",
        ))
        self.add_phase(p5)

        # Phase 6: Exclusion (T+5:00)
        p6 = Phase(
            name="Exclusion",
            start=timedelta(minutes=5),
            description="noaa-sensor-3 reputation falls below threshold. "
                        "Network autonomously excludes it.",
        )
        p6.events.append(ScenarioEvent(
            timestamp=timedelta(minutes=5),
            event_type=PhaseEvent.PEER_EXCLUDE,
            peer_name="noaa-sensor-3",
            description="noaa-sensor-3 excluded: reputation collapsed below threshold",
        ))
        self.add_phase(p6)

        # Phase 7: EPA Onboarding (T+6:00)
        # EPA auto-joins via join_phase=7; no explicit event needed.
        self.add_phase(Phase(
            name="EPA Onboard",
            start=timedelta(minutes=6),
            description="EPA air quality monitor joins the network. Trust "
                        "established through existing peer vouching.",
        ))

        # Phase 8: Integration (T+7:00)
        self.add_phase(Phase(
            name="Integration",
            start=timedelta(minutes=7),
            description="EPA fully integrated. Data sharing resumes at full "
                        "capacity with 9 trusted peers.",
        ))
