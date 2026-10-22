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
"""Selective assignment and off-policy scoring (R+D.md §12.7;
RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md).

A requestor with N willing peers assigns a task to k of them through a
stochastic, propensity-logged draw, so the outcomes it never asked for can
still be estimated. In order: :mod:`.model` (the ``selection.json``
declaration), :mod:`.draw` (the subset and its exact inclusion
probabilities), :mod:`.chain` (the committed seed chain that makes a draw
auditable), :mod:`.selector` (the requestor's chain and decision log),
:mod:`.hooks` (the negotiation hooks and audit verbs), and :mod:`.estimate`
(the doubly robust estimator over the log). The C twin is
``src/c/extensions/selection/``.
"""

from .model import (DEFAULT_FLOOR, DEFAULT_LOG_RECORDS,  # noqa: F401
                    EMPTY_MODEL, SELECTION_ENV, Policy,
                    SelectionDeclarationError, SelectionModel,
                    load_selection, load_selection_env, parse_selection)
from .draw import Draw, draw, propensities, seed_of  # noqa: F401
from .chain import (LENGTH, SeedChain, verify_link,  # noqa: F401
                    verify_rotation)
from .estimate import estimate, reward_model  # noqa: F401

# Declares this layer to the core's oracle registry (..oracles).
from . import oracle  # noqa: F401,E402
