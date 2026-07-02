# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Narration script for the multi-agency disaster-response demo.

Each block is a NarrationBlock (from inspector.dashboard.narration) keyed
to a scenario-second timestamp. The dashboard shows at most one block
at a time, automatically advancing with the clock.

Language discipline: every line credits the decision to the network --
"the network detected," "peers converged," "AT excluded." Never "we
detected" or "the operator flagged." That framing is a core design
principle (see demo-implementation-plan.md §Critical Design Constraint).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Keep the import lazy-style: the evaluation package shouldn't hard-depend
# on the inspector for unit-test import paths.
if TYPE_CHECKING:
    from autonomous_trust.inspector.dashboard.narration import NarrationBlock


def build_narration_script():
    """Return the full narration script as a list of NarrationBlock."""
    from autonomous_trust.inspector.dashboard.narration import NarrationBlock

    return [
        NarrationBlock(
            t_start=0, t_end=25,
            text=("Federal peers come online: NOAA weather, USGS seismic, "
                  "and FEMA ops. Each agency runs its own infrastructure."),
            subtext=("You are watching autonomous peer discovery. "
                     "No central broker. No pre-negotiated trust."),
            style="info",
        ),
        NarrationBlock(
            t_start=30, t_end=85,
            text=("Bootstrap phase. Peers start with zero reputation "
                  "toward one another and build trust by exchanging "
                  "small data samples."),
            subtext=("Contrite tit-for-tat -- a cooperative peer that "
                     "forgives occasional anomalies."),
            style="info",
        ),
        NarrationBlock(
            t_start=90, t_end=145,
            text=("FEMA's fusion node negotiates weather and seismic "
                  "subscriptions from NOAA and USGS. Machine-to-machine; "
                  "no human in the approval loop."),
            style="info",
        ),
        NarrationBlock(
            t_start=150, t_end=235,
            text=("Full data sharing. Trust scores stabilize as peers "
                  "corroborate readings across agencies."),
            subtext=("Each agency's sensitivity policy stays local. "
                     "AT handles only the behavioral trust layer."),
            style="info",
        ),
        NarrationBlock(
            t_start=240, t_end=265,
            text=("NOAA sensor #3 has been compromised. Its ZTA "
                  "credentials are still valid -- identity says it is "
                  "NOAA. But its data has started to drift."),
            subtext=("This is the attack ZTA cannot catch: a legitimate "
                     "peer producing illegitimate data."),
            style="alert",
        ),
        NarrationBlock(
            t_start=270, t_end=295,
            text=("The network is detecting the divergence. Each honest "
                  "peer independently observes noaa-3 out of agreement "
                  "with noaa-1, noaa-2, noaa-4 by more than two sigma."),
            subtext=("Gossip consensus propagates the low scores. Same "
                     "conclusion, reached independently."),
            style="alert",
        ),
        NarrationBlock(
            t_start=300, t_end=355,
            text=("noaa-3 has been excluded from the data-sharing mesh. "
                  "The remaining network continues sharing data normally."),
            subtext=("No human operator flagged this peer. No analyst "
                     "approved the exclusion. The network decided."),
            style="success",
        ),
        NarrationBlock(
            t_start=360, t_end=415,
            text=("EPA arrives mid-crisis with valid ZTA credentials. "
                  "Identity: verified. AT reputation: zero."),
            subtext=("Trust must be earned through behavior. "
                     "Identity is not trust."),
            style="info",
        ),
        NarrationBlock(
            t_start=420, t_end=480,
            text=("EPA-1 has earned sufficient trust through consistent, "
                  "accurate air-quality data. Fully integrated."),
            subtext=("Onboarding happened autonomously. "
                     "No agency had to pre-negotiate terms."),
            style="success",
        ),
    ]
