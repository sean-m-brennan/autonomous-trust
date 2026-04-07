"""
Narration script for the civilian disaster response demo.

Each block appears as a semi-transparent overlay at the bottom of the
dashboard during presentation mode.  All trust decisions are attributed
to the autonomous network — never to a human operator.
"""

from autonomous_trust.inspector.dashboard.narration import NarrationBlock


CIVILIAN_NARRATION = [
    # Phase 0: Formation (T+0:00 - T+1:00)
    NarrationBlock(
        t_start=0,
        t_end=15,
        text="Hurricane Helene approaches the North Carolina coast.",
        subtext="Nine federal sensors from NOAA, USGS, and FEMA are powering up "
                "in the Wilmington area.  They have never communicated before.",
        style="info",
    ),
    NarrationBlock(
        t_start=15,
        t_end=60,
        text="The sensors discover each other and begin exchanging identities.",
        subtext="No central authority coordinates this.  Each peer independently "
                "verifies the others' cryptographic identities.",
        style="default",
    ),

    # Phase 1: Bootstrap (T+1:00 - T+2:00)
    NarrationBlock(
        t_start=60,
        t_end=90,
        text="Trust is forming.  Watch the reputation scores climb.",
        subtext="Peers earn reputation through consistent, honest behavior — "
                "responding to pings, delivering promised data, confirming "
                "each other's identity claims.",
        style="default",
    ),
    NarrationBlock(
        t_start=90,
        t_end=120,
        text="Reputation stabilizes above 0.7 for all nine peers.",
        subtext="This is the threshold for data-sharing negotiations.  The "
                "network has autonomously decided these peers are trustworthy.",
        style="success",
    ),

    # Phase 2-3: Negotiation + Data Sharing (T+2:00 - T+4:00)
    NarrationBlock(
        t_start=120,
        t_end=150,
        text="Peers negotiate data-sharing agreements.",
        subtext="NOAA sensors offer weather streams.  USGS offers seismic data.  "
                "FEMA field stations request both.  The negotiation protocol "
                "ensures fair exchange based on capabilities and trust.",
        style="default",
    ),
    NarrationBlock(
        t_start=150,
        t_end=210,
        text="Data is flowing.  The sensor comparison chart shows three "
                "NOAA stations tracking together.",
        subtext="Temperature, wind speed, pressure, and precipitation data "
                "stream continuously.  FEMA's fusion center aggregates it all.",
        style="success",
    ),
    NarrationBlock(
        t_start=210,
        t_end=240,
        text="The hurricane intensifies.  Wind speeds climbing, pressure dropping.",
        subtext="All three NOAA sensors agree — the readings are consistent "
                "across stations 20 km apart.  This consensus is key to what "
                "happens next.",
        style="info",
    ),

    # Phase 4: Compromise (T+4:00)
    NarrationBlock(
        t_start=240,
        t_end=260,
        text="Something is wrong with NOAA-Sensor-3 at Topsail Beach.",
        subtext="An attacker has compromised the sensor.  It begins reporting "
                "falsified temperature readings.  Watch the sensor comparison "
                "chart — the red line is about to diverge.",
        style="alert",
    ),
    NarrationBlock(
        t_start=260,
        t_end=270,
        text="The compromised sensor's readings diverge from the other two.",
        subtext="No human flagged this.  The autonomous cross-source validation "
                "running on FEMA's fusion node detects the statistical anomaly.",
        style="alert",
    ),

    # Phase 5: Detection (T+4:30)
    NarrationBlock(
        t_start=270,
        t_end=290,
        text="Anomaly detected.  The network lowers its trust in NOAA-Sensor-3.",
        subtext="Transaction scores for noaa-sensor-3 drop.  Its reputation "
                "begins declining on the trust timeline.  Other peers "
                "independently confirm the anomaly.",
        style="alert",
    ),

    # Phase 6: Exclusion (T+5:00)
    NarrationBlock(
        t_start=300,
        t_end=330,
        text="NOAA-Sensor-3 excluded.  The network made this decision autonomously.",
        subtext="Reputation fell below 0.5 — the exclusion threshold.  No human "
                "pressed a button.  The trust graph shows the edge turning red "
                "and disappearing.  Data sharing continues with the remaining "
                "eight peers.",
        style="alert",
    ),

    # Phase 7: EPA Onboarding (T+6:00)
    NarrationBlock(
        t_start=360,
        t_end=390,
        text="A new peer arrives.  EPA deploys an air quality monitor.",
        subtext="The network onboards it the same way it onboarded the original "
                "nine — identity verification, reputation bootstrap, capability "
                "negotiation.  No special provisioning needed.",
        style="info",
    ),

    # Phase 8: Integration (T+7:00)
    NarrationBlock(
        t_start=420,
        t_end=480,
        text="Nine trusted peers sharing weather, seismic, and air quality data.",
        subtext="The network formed, detected a compromise, excluded the bad "
                "actor, and integrated a new peer — all without centralized "
                "command or human intervention.  This is AutonomousTrust.",
        style="success",
    ),
]
