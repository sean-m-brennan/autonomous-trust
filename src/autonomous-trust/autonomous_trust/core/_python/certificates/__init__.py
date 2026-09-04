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
"""Certificate-carrying task interfaces (R+D.md §12.3).

Build-order step 2 of doc/verification_oracle.md. For a large fraction of
computational work, checking is asymptotically cheaper than producing;
requiring every answer to arrive with a witness converts peer judgement into
running a checker, which makes the oracle exact rather than statistical.

See doc/architecture/certificate-interfaces.md for the design, and the C twin
at ``src/c/autonomous_trust/certificates/``.
"""

from .checkers import (CHECKERS, INDETERMINATE, INVALID,  # noqa: F401
                       VALID, MAX_DIM, MAX_ELEMENTS)
from .drat import DratError, check_refutation, is_rat, is_rup  # noqa: F401
from .inventory import (CERTIFIED, OPTIONAL, UNCERTIFIABLE,  # noqa: F401
                        UNEXAMINED, InventoryRow, build_inventory,
                        format_inventory, summarise)
from .model import (CERTIFICATES_ENV, CHECKER_KINDS,  # noqa: F401
                    DEFAULT_TOLERANCE, EMPTY_MODEL,
                    CertificateDeclarationError, CertificateModel,
                    CertifiedCapability, load_certificates, parse_certificates)
from .rng import SplitMix64  # noqa: F401
from .verify import (ABSENT_SCORE, INVALID_SCORE, VALID_SCORE,  # noqa: F401
                     Certified, CertificateVerifier, default_seed,
                     split_certified)
