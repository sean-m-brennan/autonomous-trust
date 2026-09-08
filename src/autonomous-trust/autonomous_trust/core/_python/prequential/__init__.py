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
"""Prequential competence with per-region weighting (R+D.md §12.5).

Build-order step 4 of doc/verification_oracle.md: score peers on their
sequential record of forecasts against outcomes (Dawid, 1984) with a proper
scoring rule, and let that record WEIGHT the peer's evidence rather than
become evidence itself.

Unlike the three layers before it, this one produces no ``TransactionScore``
and has no evidence channel. Poor competence is not a defection, and R+D.md
§12.8's channel set is closed and pre-declared; what §12.5 asks for is the
authored per-capability ``transaction_weight``, learned rather than declared,
which is what :meth:`~.competence.PrequentialEstimator.competence` returns --
bounded to a band around the operator's number.

The sleeping-experts restriction (Freund, Schapire, Singer and Warmuth, 1997)
makes the competence regional with nobody declaring the regions, and drives
the Hedge weights behind
:meth:`~.competence.PrequentialEstimator.combine`, whose aggregate forecast is
the claimant for the O(sqrt(T log N)) regret bound against arbitrary
adversarial peers -- the one guarantee reputation averaging cannot supply at
any sample size.

See doc/architecture/prequential-competence.md for the design, and the C twin
at ``src/c/autonomous_trust/prequential/``.
"""

from .competence import (NEUTRAL_COMPETENCE, Forecast,  # noqa: F401
                         LossRing, PrequentialEstimator)
from .model import (DEFAULT_ALPHA, EMPTY_MODEL,  # noqa: F401
                    PREQUENTIAL_ENV, Forecasting, PrequentialDeclarationError,
                    PrequentialModel, load_prequential, parse_prequential)
from .scoring import (MAX_LOSS, band_multiplier, hedge_bound,  # noqa: F401
                      hedge_weights, interval_score, normalized_loss,
                      weight_round)
