# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Narration script for the DoD squad infiltration demo.

Each block appears as a semi-transparent overlay at the bottom of the
dashboard during presentation mode.  All trust decisions are attributed
to the autonomous network — never to a human operator, never to "the
system was configured to."  This matches the plan's "Observe, Don't
Command" critical design constraint (dod-demo-implementation-plan.md).

Severity / style is consumed by inspector.dashboard.narration:

  "info"     neutral context
  "default"  normal narrative beat
  "alert"    threat or anomaly visible
  "success"  successful autonomous action
"""

from autonomous_trust.inspector.dashboard.narration import (
    NarrationBlock, NarrationAnchor,
)


# The trust/threat beats below carry ``anchor`` cues so that, during canned
# playback, examples.dod_mission.__main__ re-times them to when the events
# *actually* happened in the recording (reputation crossing 0.7, the MQ-800
# being detected and collapsing, the jet checking in) instead of the
# idealised ``t_start`` schedule. The ``t_start`` values remain the live-mode
# fallback (and the fallback if a cue never fires in a given recording).
# The "cohort_above" cohort (the pre-established peers) is injected at
# runtime from the scenario roster — see __main__.

DOD_NARRATION: list[NarrationBlock] = [
    # ----- Phase 0: Setup (T+0:00 - T+1:00) ----------------------------
    NarrationBlock(
        t_start=0,
        t_end=15,
        text="A 12-man squad inserts behind enemy lines on a mobile-target "
             "mission.  They are two kilometers out.",
        subtext="The squad has pre-established trust with their microdrones, "
             "two RQ-86 recon drones overhead, and a remote command node.  "
             "Pre-mission identity chains are loaded.  Nothing else is "
             "trusted yet.",
        style="info",
    ),
    NarrationBlock(
        t_start=15,
        t_end=60,
        text="The cohort forms.  Squad, drones, and overhead recon exchange "
             "identities and bootstrap reputation.",
        subtext="There is no central authority confirming who's who.  Each "
             "peer cryptographically verifies the others against the "
             "pre-mission roster — and every successful exchange feeds the "
             "reputation ledger.",
        style="default",
    ),

    # ----- Phase 1: Approach (T+1:00 - T+2:00) -------------------------
    NarrationBlock(
        t_start=60,
        t_end=100,
        text="The squad advances.  Microdrones sweep ahead, just above the "
             "treetops, extending the squad's detection envelope.",
        subtext="The map shows the swarm moving forward of the squad line.  "
             "RQ-86s loiter at 5,000 m, providing wide-area ISR and acting "
             "as peer leaders for the swarm.",
        style="default",
    ),
    NarrationBlock(
        t_start=100,
        t_end=120,
        text="Reputation has stabilized above 0.7 for every pre-established "
             "peer.",
        subtext="That's the threshold for inter-peer data-sharing "
             "negotiations.  Watch the trust dynamics chart — the curves "
             "have leveled.  The network has autonomously decided these "
             "peers are trustworthy.",
        style="success",
        # Fires when the LAST pre-established peer first crosses 0.7.
        anchor=NarrationAnchor(kind="cohort_above", op="above",
                               threshold=0.7),
    ),

    # ----- Phase 2: Contact (T+2:00 - T+3:00) --------------------------
    NarrationBlock(
        t_start=120,
        t_end=150,
        text="Leave-behind sensors come into range.  Some are friendly, "
             "pre-positioned; some have been hacked by the adversary.",
        subtext="Friendly sensors present credentials chained to the "
             "pre-mission roster.  Hacked ones present forged identities — "
             "self-signed or claiming a roster slot they don't own.",
        style="info",
    ),
    NarrationBlock(
        t_start=150,
        t_end=180,
        text="The hacked sensors are rejected.  Their identity chains don't "
             "validate.",
        subtext="No human flagged them.  The peer-to-peer identity layer "
             "refuses the credential before any data ever reaches the trust "
             "graph.  See the event log: sensor-1 and sensor-2 excluded; "
             "sensor-3 admitted.",
        style="success",
    ),

    # ----- Phase 3: Intel (T+3:00 - T+4:00) ----------------------------
    NarrationBlock(
        t_start=180,
        t_end=220,
        text="Multi-source fusion locates the target.  Verified sensors, "
             "RQ-86 SAR, and microdrone video all corroborate.",
        subtext="The fusion node weights each source by reputation.  When "
             "three independent ISR streams agree within the position "
             "validator's tolerance, the squad receives a high-confidence "
             "target fix.",
        style="default",
    ),

    # ----- Phase 4: Rogue (T+4:00 - T+5:00) ----------------------------
    NarrationBlock(
        t_start=240,
        t_end=255,
        text="An MQ-800 armed drone arrives.  It has not been pre-cleared by "
             "this squad.",
        subtext="The RQ-86s and squad provisionally extend trust — the "
             "MQ-800 carries a valid identity from a friendly air component, "
             "just not on this squad's roster.  Watch what the network does "
             "in the next 30 seconds.",
        style="info",
        # Fires when the MQ-800 first appears in the trust timeline.
        anchor=NarrationAnchor(kind="peer_sample", peer="mq800", op="first"),
    ),
    NarrationBlock(
        t_start=255,
        t_end=270,
        text="MQ-800 starts feeding target-position data that disagrees with "
             "everyone else's.",
        subtext="The cross-source position validator is running on the "
             "fusion node.  RQ-86-1, RQ-86-2, and the microdrones agree "
             "within a few meters; the MQ-800 designates a different "
             "building the better part of a kilometer away — far beyond "
             "any plausible sensor error, so it cannot be written off as a "
             "statistical anomaly.  On the Target Position map its marker "
             "visibly splits from the cluster in real time.",
        style="alert",
        # Fires on the first cross-source position anomaly against the MQ-800.
        anchor=NarrationAnchor(kind="event", event_type="COMPROMISE_DETECT",
                               peer="mq800"),
    ),
    NarrationBlock(
        t_start=270,
        t_end=285,
        text="Reputation collapse.  Independent peers reach the same "
             "conclusion through gossip.",
        subtext="Each peer's transaction scoring drops MQ-800 below the "
             "trust threshold.  No central node issued an order — the squad "
             "processors, the RQ-86s, and the microdrones converged "
             "independently.",
        style="alert",
        # Fires when the MQ-800's reputation first drops below the 0.5 line.
        anchor=NarrationAnchor(kind="peer_sample", peer="mq800", op="below",
                               threshold=0.5),
    ),
    NarrationBlock(
        t_start=285,
        t_end=305,
        text="MQ-800 excluded.  Its messages are dropped at the protocol "
             "layer across the cohort.",
        subtext="The trust-graph edge to MQ-800 has turned red and "
             "disappeared.  The dashboard timestamp annotation reads "
             "\"Network excluded MQ-800 (autonomous).\"  This was not a "
             "human decision.",
        style="alert",
        # Fires when the MQ-800 hits the untrusted floor (excluded).
        anchor=NarrationAnchor(kind="peer_sample", peer="mq800", op="below",
                               threshold=0.2),
    ),

    # ----- Phase 5: ECM (T+5:00 - T+6:00) ------------------------------
    NarrationBlock(
        t_start=305,
        t_end=345,
        text="The RQ-86 pair engages the rogue with electronic counter-"
             "measures.  CTFT pattern — they keep it neutralized but do "
             "not escalate.",
        subtext="With overhead coverage consumed by the e-battle, the squad "
             "is running on swarm ISR alone.  Operational coherence "
             "survives the loss of the peer leaders — the network does not "
             "depend on any single node.",
        style="default",
    ),

    # ----- Phase 6: Strike (T+6:00 - T+7:00) ---------------------------
    NarrationBlock(
        t_start=360,
        # No fixed t_end: hold this "jet arrives / validating" beat until the
        # strike-confirmed block below opens its gate (the jet actually
        # reaching the objective). Otherwise, because the strike beat is gated
        # and the jet's pass floats later than its authored time, the overlay
        # would go blank between this beat ending and the gate firing.
        t_end=None,
        text="A fighter jet was already on patrol nearby.  The moment the "
             "MQ-800 was exposed as rogue, Command vectored it in.  It "
             "arrives now, announces itself, and the cohort validates it.",
        subtext="The jet presents a fresh identity chained to Command's "
             "root.  Squad processors verify it against the pre-mission "
             "trust anchor and admit it to the cohort.  Elapsed time, "
             "identity to operational trust: under one second.",
        style="success",
        # Fires when the fighter jet checks in (first appears in the timeline).
        anchor=NarrationAnchor(kind="peer_sample", peer="jet-1", op="first"),
    ),
    NarrationBlock(
        t_start=380,
        t_end=420,
        text="Strike confirmed.  Targeting data was acquired, verified, and "
             "actioned in a single high-speed pass.",
        subtext="The swarm provides bomb-damage assessment.  All within "
             "six seconds of the jet's ingress — orders of magnitude faster "
             "than any human-mediated trust process.",
        style="success",
        # Held until the jet is actually over the objective. The launch is
        # gated on the MQ-800 collapse so the strike time floats; t_start is
        # only the earliest it may show (coordinator publishes the gate; see
        # scenario.jet_over_objective / coordinator._push_dashboard_update).
        gate="jet_over_target",
    ),

    # ----- Phase 7: Exfil (T+7:00 - T+8:00) ----------------------------
    NarrationBlock(
        t_start=420,
        t_end=480,
        text="The squad exfiltrates.  Two microdrones survive — one "
             "forward, one rear.",
        subtext="A rogue armed drone arrived, was detected, was excluded, "
             "and a strike was completed — none of it commanded by an "
             "operator.  You are watching the network's own decision-"
             "making process.  The dashboard is a window, not a cockpit.",
        style="success",
    ),
]
