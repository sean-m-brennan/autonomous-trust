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
"""What a node does with another member's ZTA finding about a peer
(doc/architecture/zta-integration.md, "Delegated verification").

Two findings travel between members. A *vouch* (``zta_verified``) says the
sender's verifier proved the peer's credential; enough of them, from members
above the reputation bar, lift the ceiling on a peer this node could not verify
itself. An *alert* (``zta_revoked``) says the sender found the credential
revoked. It is never taken on the sender's word: this node checks the
credential itself first and acts on its own answer. Only when its own verifier
cannot answer (DDIL) are alerts counted, and a quorum of them puts the peer
under the DDIL ceiling until this node's own check settles it.

Pure: membership, the recorded credential, reputation, this node's own check
and where a standing goes are all asked of the context, so the decisions are
the same in the identity process, its tests and the conformance adapter. Twin
of C zta_delegation.{h,c}; the verdict strings are what the corpus pins. Uuids
are lower-case strings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from autonomous_trust.core.identity.peer_standing import (
    STANDING_CAPPED, STANDING_FAILED, STANDING_PROVED)

from .zta_verifier import ZtaStatus

#: The wire verbs, sent to process ``zta_verify`` (C's process; Python's
#: network delivers it to identity through the extension's process alias).
ZTA_PROTO_VERIFICATION = 'zta_verified'
ZTA_PROTO_REVOCATION_ALERT = 'zta_revoked'
ZTA_PROCESS = 'zta_verify'

VOUCH = 'vouch'
ALERT = 'alert'

MAX_PEERS = 256
MAX_SENDERS = 16

NOT_MEMBER = 'not_member'          # the sender is not in our group
NO_RECORD = 'no_record'            # we hold no credential for the peer
HASH_MISMATCH = 'hash_mismatch'    # about a credential other than the one we hold
WRONG_STATUS = 'wrong_status'      # a vouch not VERIFIED, an alert not REVOKED
NOT_UNVERIFIED = 'not_unverified'  # a vouch for a peer we are not waiting on
OWN_VERIFIED = 'own_verified'      # an alert our own check contradicts
OWN_FAILED = 'own_failed'          # an alert our own check confirms: FAILED published
SETTLED = 'settled'                # the quorum was already met for this peer
PENDING = 'pending'                # the sender's reputation is not known yet
BELOW_BAR = 'below_bar'            # the sender's reputation is under the bar
DUPLICATE = 'duplicate'            # this sender was already counted
COUNTED = 'counted'                # counted, quorum not yet met
QUORUM = 'quorum'                  # counted, and the quorum is met: standing published
FULL = 'full'                      # no room to track it

_WAITING = (ZtaStatus.UNAVAILABLE, ZtaStatus.DEFERRED)
_FAILED = (ZtaStatus.REVOKED, ZtaStatus.EXPIRED, ZtaStatus.REJECTED)


@dataclass
class DelegationContext:
    """What the decisions ask of the node. Every callable is required.

    ``reputation`` returns the sender's score, or None when it is not known yet
    (the caller asks for it and offers the finding again once it is).
    ``standing(peer, status, ceiling, reason)`` publishes a ZTA standing
    (ceiling None: none)."""
    is_member: Callable[[str], bool]
    recorded_hash: Callable[[str], Optional[bytes]]
    reputation: Callable[[str], Optional[float]]
    own_check: Callable[[str], ZtaStatus]
    standing: Callable[[str, str, Optional[float], str], None]
    min_reputation: float
    quorum: int
    ddil_cap: float
    revocation_penalty: float


@dataclass
class _Peer:
    unverified: bool = False   # our own last check could not answer
    lifted: bool = False       # vouch quorum met since
    bounded: bool = False      # alert quorum met since
    vouchers: list = field(default_factory=list)
    alerters: list = field(default_factory=list)


def failed_ceiling(status: ZtaStatus, revocation_penalty: float) -> float:
    """The FAILED ceiling for one of our own failures: revoked and rejected cost
    the whole penalty, expired half (a lapse, not a lie)."""
    penalty = revocation_penalty
    if status is ZtaStatus.EXPIRED:
        penalty *= 0.5
    return min(1.0, max(0.0, 1.0 - penalty))


class ZtaDelegation(object):
    """Per-peer record of what members told us. Plain data, so it pickles
    across the process fork."""

    def __init__(self):
        self.peers: dict[str, _Peer] = {}

    def _find(self, peer: str, create: bool) -> Optional[_Peer]:
        p = self.peers.get(peer)
        if p is None and create and len(self.peers) < MAX_PEERS:
            p = self.peers[peer] = _Peer()
        return p

    def own_result(self, peer: str, status: ZtaStatus) -> None:
        """This node's own check of ``peer`` answered ``status`` (the
        re-verification sweep, or an alert's re-check). UNAVAILABLE/DEFERRED
        marks the peer as one we are waiting on; any other answer settles it
        and clears what was counted."""
        waiting = status in _WAITING
        p = self._find(peer, waiting)
        if p is None:
            return
        if waiting:
            p.unverified = True
            return
        # Our own answer settles it: whatever others said is moot.
        self.peers[peer] = _Peer()

    @staticmethod
    def _count(senders: list, sender: str) -> str:
        if sender in senders:
            return DUPLICATE
        if len(senders) >= MAX_SENDERS:
            return FULL
        senders.append(sender)
        return COUNTED

    @staticmethod
    def _bar(ctx: DelegationContext, sender: str) -> Optional[str]:
        score = ctx.reputation(sender)
        if score is None:
            return PENDING
        if score < ctx.min_reputation:
            return BELOW_BAR
        return None

    def event(self, ctx: DelegationContext, kind: str, sender: str, peer: str,
              cred_hash: bytes, status: ZtaStatus) -> str:
        """One finding from member ``sender`` about ``peer``, credential
        ``cred_hash``, with the sender's ``status``. Any standing it leads to
        goes through ``ctx``. Returns the verdict string."""
        # Who said it: only a member's finding is heard (the transport names
        # the sender, so this is not the payload's claim).
        if not ctx.is_member(sender):
            return NOT_MEMBER
        # About what: the credential we hold for the peer, and no other.
        recorded = ctx.recorded_hash(peer)
        if not recorded:
            return NO_RECORD
        if bytes(recorded) != bytes(cred_hash):
            return HASH_MISMATCH
        quorum = ctx.quorum if ctx.quorum > 0 else 1

        if kind == VOUCH:
            if status is not ZtaStatus.VERIFIED:
                return WRONG_STATUS
            p = self._find(peer, False)
            if p is None or not p.unverified:
                return NOT_UNVERIFIED
            if p.lifted:
                return SETTLED
            bar = self._bar(ctx, sender)
            if bar is not None:
                return bar
            v = self._count(p.vouchers, sender)
            if v != COUNTED or len(p.vouchers) < quorum:
                return v
            p.lifted = True
            ctx.standing(peer, STANDING_PROVED, None,
                         'delegated verification quorum met')
            return QUORUM

        if status is not ZtaStatus.REVOKED:
            return WRONG_STATUS
        # Never on the sender's word: our own check first, and our answer wins.
        own = ctx.own_check(peer)
        if own is ZtaStatus.VERIFIED:
            self.own_result(peer, own)
            return OWN_VERIFIED
        if own in _FAILED:
            self.own_result(peer, own)
            ctx.standing(peer, STANDING_FAILED,
                         failed_ceiling(own, ctx.revocation_penalty),
                         'credential %s (re-checked on an alert)'
                         % own.value.lower())
            return OWN_FAILED
        # We cannot answer (DDIL): count the alert, and bound the peer at quorum.
        p = self._find(peer, True)
        if p is None:
            return FULL
        p.unverified = True
        if p.bounded:
            return SETTLED
        bar = self._bar(ctx, sender)
        if bar is not None:
            return bar
        v = self._count(p.alerters, sender)
        if v != COUNTED or len(p.alerters) < quorum:
            return v
        p.bounded = True
        ctx.standing(peer, STANDING_CAPPED, ctx.ddil_cap,
                     'revocation alerts, unverified locally')
        return QUORUM
