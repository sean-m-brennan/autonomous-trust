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
"""Certificate-carrying interfaces (R+D.md §12.3) as a scorer arm
(``..oracles``). The Python twin of ``certificates_oracle.c``. Until
FEATURE_SPLIT_PLAN Phase 3 this lived in ``automate``.
"""
from __future__ import annotations

import logging
import traceback
from typing import Optional

from autonomous_trust.core import oracles
from autonomous_trust.core.negotiation.certified import default_seed
from .inventory import build_inventory, format_inventory
from .model import CertificateDeclarationError
from .verify import CertificateVerifier

#: Process-wide certificate verifier, built lazily from ``$AT_CERTIFICATES``.
#: Stateless apart from the declaration -- a certificate is self-contained, so
#: unlike the physics checker there is no window to carry -- but built once
#: anyway so the declaration is read and the inventory reported a single time
#: rather than per task result.
_CERTIFICATES: 'CertificateVerifier | None' = None


def certificate_verifier(registered=None) -> CertificateVerifier:
    """The process-wide verifier, built on first call.

    Emits the certificate inventory once, at build time. That report is the
    other half of what R+D.md §12.3 asks for: a node that silently falls
    through to completion scoring for everything it cannot check looks, from
    outside, exactly like a node that is checking everything, and the expensive
    case is only "recognized" if somebody can see it.
    """
    global _CERTIFICATES
    if _CERTIFICATES is None:
        log = logging.getLogger(__name__)
        try:
            _CERTIFICATES = CertificateVerifier.from_env()
        except CertificateDeclarationError:
            log.error('certificates: declaration rejected, layer stays OFF: %s',
                      traceback.format_exc())
            _CERTIFICATES = CertificateVerifier()
        if _CERTIFICATES.enabled:
            log.info('%s', format_inventory(
                build_inventory(_CERTIFICATES.model, registered)))
    return _CERTIFICATES


def _check(inp: oracles.ScoreInput) -> Optional[tuple[float, str]]:
    """After physics and before the ZKP arms. After physics because a witness
    proves the answer satisfies the problem AS STATED, which says nothing about
    whether the statement was physically coherent. Before the ZKP arms because
    those ask only whether the bytes were altered -- an exact check of the
    ANSWER outranks an attestation about its transport.

    This is the one layer that can return a GOOD score, and that is not an
    inconsistency with the physics layer above it. Surviving a feasibility test
    means "not refuted"; a witness that checks out means "proved right", and
    declining to say so would discard the strongest positive evidence this
    node can obtain."""
    verifier = certificate_verifier()
    if not verifier.enabled:
        return None
    verdict = verifier.verify(
        inp.cap, inp.task.result, getattr(inp.task, 'certificate', None),
        getattr(inp.task, 'requested_kwargs', None),
        inp.seed if inp.seed is not None else default_seed())
    if verdict is not None and inp.logger is not None:
        score, channel = verdict
        inp.logger.info('%s: task %s scored %.2f on the %s channel by its '
                        '%s witness', inp.name, inp.task.uuid, score, channel,
                        inp.cap)
    return verdict


def _reset() -> None:
    global _CERTIFICATES
    _CERTIFICATES = None


oracles.declare('certificates', _reset)
oracles.register_arm(oracles.Arm('certificates.check', 300, score=_check))
