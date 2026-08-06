# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Data generators for the DoD scenario peers.

ISR generators (target position, electronic noise, motion) belong to
overhead and vanguard drones.  Ground-sensor generators (seismic,
acoustic, perimeter trip) belong to leave-behind sensors along the
approach path.  Squad members and command consume but don't produce —
they have no generators here.
"""

from .isr import (  # noqa: F401
    TargetPositionXGenerator, TargetPositionYGenerator,
    TargetBearingGenerator, ElectronicNoiseGenerator,
    MotionIntensityGenerator, AudioLevelGenerator,
    OverheadISRGenerators, MicrodroneGenerators,
)
from .ground_sensor import (  # noqa: F401
    SeismicGenerator, AcousticGenerator, PerimeterTripGenerator,
    GroundSensorGenerators,
)
