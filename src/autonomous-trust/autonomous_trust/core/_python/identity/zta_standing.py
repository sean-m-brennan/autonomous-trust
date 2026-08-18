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

"""IPC carrier for what ZTA proved (or failed to prove) about a peer.

See doc/architecture/zta-integration.md. The ZTA verdict is discovered by IdentityProcess -- it owns
admission and the verifier -- but the thing it must bound, reputation, lives in
another process. This is that hand-off, fanned out exactly like
:class:`ChildGroupSet` via ``ProcessTracker.update`` and consumed in
``Protocol.run_message_handlers``.

Why a *ceiling* and not a score: a ZTA verdict is an authority finding about
whether an identity is who it claims, not the outcome of an interaction with
it. AT's reputation scale is [0, 1] with no negatives (doc/architecture/reputation.md), so a "penalty"
has no representation on it at all, and the earlier attempt to send one as
``score = -0.8`` was rejected at the boundary twice over -- see
``zta_process.c::_send_reputation_penalty``. A bound on how far an unproved
peer may rise says exactly what ZTA knows and nothing it does not.
"""

from typing import Optional

#: ZTA proved this peer: a credential verified against a configured anchor AND
#: bound to this identity. No ceiling; anchors the unwind (`verified_at`).
STANDING_PROVED = 'proved'

#: Admitted, but ZTA did not prove it -- the DDIL/deferred fallback, or (under
#: `binding_mode: prefer`) a credential that chained but carried no binding.
#: Carries the ceiling such a peer may not rise above.
STANDING_CAPPED = 'capped'

#: An affirmative post-admission failure: REVOKED, EXPIRED or REJECTED at
#: re-verification. Distinct from `capped` because "we could not check" and
#: "we checked and it is bad" warrant different responses -- the first bounds a
#: peer, the second unwinds and demotes it.
STANDING_FAILED = 'failed'

#: Deliberately NOT the six-valued `ZtaStatus`. These three are the distinctions
#: reputation can act on; the verifier's own status rides along in `reason` for
#: the operator log. Keeping the acted-on vocabulary small is the same argument
#: doc/architecture/reputation.md makes about evidence channels, applied in the
#: small: a consumer
#: should be handed the distinction it needs, not a wider enum it must re-derive.
STANDINGS = (STANDING_PROVED, STANDING_CAPPED, STANDING_FAILED)


class ZtaStanding(object):
    """One peer's ZTA standing, as IdentityProcess currently understands it.

    Plain picklable object (no protobuf) -- like ``ChildGroupSet`` it only ever
    travels the local inter-process queues, never the network. Nothing here is
    peer-supplied: it is this node's own finding about a peer, so a remote
    party cannot forge itself a ceiling of 1.0 by claiming one.

    :param peer_uuid:   the peer this finding is about (str or UUID)
    :param status:      one of :data:`STANDINGS`
    :param ceiling:     highest reputation this peer may hold while its
                        credential is unproved, or None for "no bound"
    :param verified_at: epoch seconds of the most recent PROVED verification,
                        or None if this peer has never verified. This is the
                        anchor the retroactive unwind reaches back to (doc/architecture/zta-integration.md):
                        standing earned after the last point ZTA actually
                        proved something is what a later failure calls into
                        question, and standing earned before it is not.
    :param reason:      verifier-supplied detail, for the operator-facing log
    """

    def __init__(self, peer_uuid, status: str, ceiling: Optional[float] = None,
                 verified_at: Optional[float] = None, reason: str = ''):
        self.peer_uuid = str(peer_uuid)
        self.status = str(status)
        self.ceiling = None if ceiling is None else float(ceiling)
        self.verified_at = None if verified_at is None else float(verified_at)
        self.reason = str(reason or '')

    def __repr__(self):
        return ('ZtaStanding(%s, %s, ceiling=%s, verified_at=%s)'
                % (self.peer_uuid[:8], self.status, self.ceiling,
                   self.verified_at))
