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
"""Physical consistency as a pre-statistical falsification layer (R+D.md §12.2).

Build-order step 1 of doc/verification_oracle.md: check a peer's claim against
conservation, dimensional coherence and kinematic feasibility BEFORE any
reputation math runs. The verdict is a hard falsification rather than a
statistic, which is why it has its own evidence channel
(``TX_CHANNEL_PHYSICAL``, R+D.md §12.8) and its own weight.

See doc/architecture/physical-consistency.md for the design, and the C twin at
``src/c/autonomous_trust/physics/``.
"""

from .checker import (IMPLICATED_SCORE, REFUTED_SCORE,  # noqa: F401
                      PhysicsCheckError, PhysicsChecker)
from .diagnose import (CLEARED, IMPLICATED, REFUTED,  # noqa: F401
                       diagnose, minimal_hitting_sets)
from .model import (EMPTY_MODEL, PHYSICS_ENV,  # noqa: F401
                    PhysicsDeclarationError, PhysicsModel, Quantity, Relation,
                    load_physics, parse_physics)
from .units import (BASE_UNITS, DIMENSIONLESS, UNITS,  # noqa: F401
                    Dimension, UnitError, parse_unit, same_dimension)
