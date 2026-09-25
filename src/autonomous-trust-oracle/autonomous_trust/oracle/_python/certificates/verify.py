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
"""Turning a checker's verdict into evidence (R+D.md §12.3).

:class:`CertificateVerifier` is the requestor-side entry point: it resolves the
capability's declaration, runs the checker, and returns ``(score, channel)`` or
``None``. Unlike the physics layer, this one CAN return a good score --- and
the difference is not an inconsistency but the whole point of a certificate. A
claim that survives a physical feasibility test is merely not-refuted; a claim
whose witness checks out has been *proved right*, and refusing to say so would
throw away the strongest positive evidence AT is able to obtain.

The scores, and why they sit where they do:

``0.9`` valid
    The same number a correct known-answer probe earns, because it is the same
    kind of fact: we know the answer is right, we did not merely fail to catch
    it being wrong.
``0.1`` invalid
    The same number a tampered probe earns. An invalid witness is not a
    disappointing result, it is a demonstrated one.
``0.3`` required but absent
    Suspicious rather than proved wrong, matching the existing
    ZKP-available-but-no-proof arm. The peer did not do what its capability
    declared it would; that is a fact about the peer, but it is not a wrong
    answer.

``None`` covers everything else: no declaration, a capability declared
uncertifiable, an optional witness that was not supplied, and --- importantly
--- INDETERMINATE, where our own retained inputs were missing or malformed. A
peer must never be scored for our inability to check.

**The inputs come from our own record.** ``requested_kwargs`` is stamped by the
requestor's negotiation process from the task it retained, never read off the
reply (see ``TaskResult.attach_requested_parameters``). A checker fed the
peer's own account of the problem would be verifying that the peer can solve a
problem of its choosing.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from autonomous_trust.core.reputation import TX_CHANNEL_CERTIFICATE
# The certified-result wire helpers are negotiation wire format and live in the
# core (FEATURE_SPLIT_PLAN Phase 3, as neg_certified does in C); re-exported
# here, where this layer's callers and tests have always found them.
from autonomous_trust.core.negotiation.certified import (  # noqa: F401
    Certified, default_seed, split_certified)
from .checkers import CHECKERS, INDETERMINATE, INVALID, VALID
from .model import (EMPTY_MODEL, CertificateModel, CertifiedCapability,
                    load_certificates)

logger = logging.getLogger(__name__)

#: A witness that checks out: the answer is proved right.
VALID_SCORE = 0.9

#: A witness that does not check out: the answer is proved wrong.
INVALID_SCORE = 0.1

#: Declared to certify, and nothing was presented.
ABSENT_SCORE = 0.3


class CertificateVerifier:
    """Requestor-side certificate checking for one node.

    Stateless apart from the declaration --- unlike the physics checker, no
    observation window is needed, because a certificate is self-contained by
    construction. That is exactly the property that makes this layer cheap: the
    verdict depends only on the inputs we already held and the witness in hand,
    so it needs no history and cannot be affected by what other peers said.
    """

    def __init__(self, model: Optional[CertificateModel] = None, logger_=None):
        self.model = model if model is not None else EMPTY_MODEL
        self.logger = logger_ or logger

    @classmethod
    def from_env(cls, path=None, logger_=None) -> 'CertificateVerifier':
        return cls(load_certificates(path), logger_=logger_)

    @property
    def enabled(self) -> bool:
        return not self.model.empty

    def verify(self, capability: Optional[str], result: Any,
               certificate: Any = None,
               requested_kwargs: Optional[Mapping] = None,
               seed: int = 0) -> Optional[tuple[float, str]]:
        """Check one returned result against its declared certificate.

        ``seed`` is the verifier's own randomness for the one probabilistic
        checker (Freivalds). It must come from this node at check time and must
        not be derivable from the problem, or the peer can grind an answer that
        passes; see :mod:`.rng`. It is a parameter rather than a draw so a
        replay reproduces the verdict.
        """
        verdict, _reason = self.evaluate(capability, result, certificate,
                                         requested_kwargs, seed)
        if verdict == VALID:
            return VALID_SCORE, TX_CHANNEL_CERTIFICATE
        if verdict == INVALID:
            return INVALID_SCORE, TX_CHANNEL_CERTIFICATE
        if verdict == 'absent':
            return ABSENT_SCORE, TX_CHANNEL_CERTIFICATE
        return None

    def evaluate(self, capability: Optional[str], result: Any,
                 certificate: Any = None,
                 requested_kwargs: Optional[Mapping] = None,
                 seed: int = 0) -> tuple[str, str]:
        """The verdict and its reason, without the reputation policy.

        Returns one of ``valid`` / ``invalid`` / ``absent`` / ``indeterminate``
        / ``none``. Split out from :meth:`verify` so the conformance corpus can
        pin the finding itself rather than the number it happens to map to.
        """
        if self.model.empty:
            return 'none', 'no declaration is configured'
        decl = self.model.for_capability(capability)
        if decl is None:
            return 'none', f'{capability!r} is not declared'
        if not decl.certifiable:
            # An acknowledged expensive case. Deliberately not a verdict: the
            # declaration records that nobody can check this, which is what
            # the inventory reports, and the completion arms score it as
            # before.
            return 'none', (f'{capability!r} is declared uncertifiable'
                            + (f' ({decl.note})' if decl.note else ''))

        has_certificate = certificate is not None and certificate != {}
        checker = CHECKERS.get(decl.checker)
        if checker is None:                     # unreachable via the loader
            return 'indeterminate', f'no checker for kind {decl.checker!r}'

        if not has_certificate and not _self_certifying(decl.checker):
            if decl.required:
                self.logger.warning(
                    'certificates: %s declared a %s witness and returned none',
                    capability, decl.checker)
                return 'absent', (f'{capability!r} declares a {decl.checker} '
                                  f'witness and none was presented')
            return 'none', 'no witness presented, and none is required'

        inputs = dict(requested_kwargs or {})
        verdict, reason = checker(inputs, result,
                                  certificate if isinstance(certificate, Mapping)
                                  else {}, decl, seed)
        if verdict == INVALID:
            self.logger.warning('certificates: %s FAILED its %s check: %s',
                                capability, decl.checker, reason)
        elif verdict == INDETERMINATE:
            # Our own record, not the peer's fault. Logged at info because an
            # operator chasing "why is nothing being certified" needs to see
            # it, but it never reaches a score.
            self.logger.info(
                'certificates: cannot check %s (%s); the peer is not scored '
                'for this', capability, reason)
            return 'indeterminate', reason
        return verdict, reason


def _self_certifying(kind: str) -> bool:
    """True for checkers whose witness is not the peer's to supply.

    ``matrix_product`` is verified against the requestor's own randomness and
    ``linear_solve`` against a residual computed from the answer itself, so
    "no certificate attached" is the normal case for both and must not be read
    as a peer withholding one. ``state_estimation`` reads its sequence out of
    the answer for the same reason.
    """
    return kind in ('matrix_product', 'linear_solve', 'state_estimation')
