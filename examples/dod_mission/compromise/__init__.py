# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Compromise behaviors for the DoD scenario.

Two compromise categories:

* `contradictory_isr` — the MQ-800 emits offset target-position and
  under-reported electronic-noise readings.  Caught by cross-source
  validators in ../tasks/validation.py.  Wraps an honest generator and
  flips its output after the scenario's "Rogue" phase begins.

* `forged_identity` — leave-behind sensors that the squad doesn't
  recognize.  Their data may be perfectly honest; the rejection
  happens at the AT identity verification layer, not via data
  validation.  This module is a thin marker class + factory that
  signals to the runtime "this peer's identity should not validate."
"""

from .contradictory_isr import (  # noqa: F401
    create_compromised_mq800_position_x,
    create_compromised_mq800_position_y,
    create_compromised_mq800_electronic_noise,
    create_all_mq800_compromised_generators,
)
from .forged_identity import (  # noqa: F401
    ForgedIdentitySensor,
    create_forged_identity_sensor,
)
