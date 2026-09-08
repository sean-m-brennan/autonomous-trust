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
"""Sampled replication with bisection dispute resolution (R+D.md §12.6).

Build-order step 6 of doc/verification_oracle.md: for work that resists
certification, replicate a random fraction of tasks rather than all of them,
scale the fraction to consequence, and resolve a disagreement by bisecting a
hash-chained trace to the first divergent step rather than re-running the whole
computation. The outcome lands on the ``replication`` evidence channel like any
other finding (R+D.md §12.8) -- a falsification procedure, not an adjudication
of standing.

This package is the three affordances in order: :mod:`.sampling` (which tasks
to replicate), and -- as the layer is built out -- adjudication of a replica's
result and the bisection game for expensive disputes. See
doc/architecture/replication.md for the design and the C twin at
``src/c/autonomous_trust/replication/``.
"""

from .model import (DEFAULT_PROB, EMPTY_MODEL,  # noqa: F401
                    REPLICATION_ENV, ReplicationDeclarationError,
                    ReplicationModel, load_replication, load_replication_env,
                    parse_replication)
from .sampling import (clamp_prob, should_replicate,  # noqa: F401
                       uniform_unit)
from .adjudication import (CORROBORATED, CORROBORATED_SCORE,  # noqa: F401
                          DISPUTE, OUTVOTED, OUTVOTED_SCORE, SINGLE,
                          adjudicate, verify)
from .bisection import (bisect_adjudicate, commit_root,  # noqa: F401
                       first_divergence, hash_chain)
