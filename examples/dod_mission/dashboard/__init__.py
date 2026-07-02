# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""DoD-mission dashboard configuration.

Wires the reusable dashboard components in
`autonomous_trust.inspector.dashboard` to DoD-specific config (role
colors, target-position sensor chart, mission phase markers,
squad-storyline narration).

Public surface:

  build_dashboard(scenario)        — returns the configured component bundle
  DOD_NARRATION                    — list[NarrationBlock] for the overlay
  MAP_CONFIG                       — center/zoom/style for the tactical map
  ROLE_LEGEND                      — (label, color) pairs for the role legend
  PresentationLayout               — full-page render wrapper
"""

from .dod_app import (  # noqa: F401
    build_dashboard, build_peer_colors, MAP_CONFIG, ROLE_LEGEND,
)
from .narration_script import DOD_NARRATION  # noqa: F401
from .presentation import PresentationLayout  # noqa: F401
