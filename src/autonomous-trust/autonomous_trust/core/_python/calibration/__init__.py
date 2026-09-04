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
"""Conformal coverage audit (R+D.md §12.4).

Build-order step 3 of doc/verification_oracle.md: audit whether a peer's
prediction sets cover as often as it claims, with finite-sample validity and no
distributional assumptions. Catches the peer that is usually right and
systematically overconfident --- the one an averaged reputation score cannot
see coming.

Its own evidence channel (``TX_CHANNEL_CALIBRATION``, R+D.md §12.8) at the
baseline weight, so it demotes gradually where a physical refutation demotes
decisively.

See doc/architecture/calibration-audit.md for the design, and the C twin at
``src/c/autonomous_trust/calibration/``.
"""

from .audit import (ABSENT_SCORE, OVERCONFIDENT_SCORE,  # noqa: F401
                    CalibrationAuditor, Prediction)
from .conformal import binomial_tail_log, covers, overconfident  # noqa: F401
from .model import (CALIBRATION_ENV, EMPTY_MODEL,  # noqa: F401
                    CalibrationDeclarationError, CalibrationModel, Predictive,
                    load_calibration, parse_calibration)
