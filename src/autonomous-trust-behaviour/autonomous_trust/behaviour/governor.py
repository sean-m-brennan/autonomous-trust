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
"""Host-side adapter (SOW Task 3 / O3 governed path).

:class:`PeerBehaviourGovernor` is the **pluggable component each node embeds** to
monitor *its own* peers. It composes a (portable, node-agnostic)
:class:`~autonomous_trust.behaviour.ensemble.BehaviorMonitor` with the thin glue
that the pure library deliberately does not contain: translating the library's
neutral :class:`~autonomous_trust.behaviour.ensemble.SlashProposal` into the core
``SlashAttestation`` and submitting it on the node's reputation queue, plus the
host-policy concerns (autonomous vs human-on-the-loop, idempotency, never-slash-
self, known-peer gating, identity).

This is the only piece that touches the trust machinery (``SlashAttestation`` /
``CfgIds`` / queues / identity), so it is **runtime-specific glue and is NOT part
of the future standalone ``.so``** -- the C node will reimplement an equivalent
handful of functions around the same library ABI. Because every node runs its own
governor, slash proposals come from many independent monitors and the existing
quorum-signed slash flow aggregates them: "ML proposes, deterministic consensus
disposes" -- no single node polices the mesh.

Usage (composition -- a node owns one and drives it from its tasking loop)::

    class MyNode(AutonomousTrust):
        def __init__(self, **kw):
            super().__init__(**kw)
            self.governor = PeerBehaviourGovernor(self, auto_slash=False)

        def autonomous_tasking(self, queues):
            for message in list(self.unhandled_messages):
                self.governor.ingest_message(message)   # observe peers
            self.governor.enforce(queues)                 # propose -> slash
            self._report_unhandled()
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from autonomous_trust.core import CfgIds
from autonomous_trust.core.reputation.reputation import SlashAttestation
from autonomous_trust.core.system import now, queue_cadence

from .ensemble import AnomalyDecision, BehaviorMonitor, SlashProposal
from .features import AccessEvent

logger = logging.getLogger(__name__)

#: Default reputation floor a sustained-anomaly slash pins to. Below the lowest
#: tier floor (0.50 -> tier 1 in reputation/repprocess.TIER_FLOORS), so the
#: floored peer drops to tier 0 and is shed by tier-gated negotiation.
DEFAULT_SLASH_FLOOR = 0.45


@dataclass(frozen=True)
class SlashRecommendation:
    """A human-on-the-loop slash the governor surfaces (logged + recorded)
    instead of submitting, when ``auto_slash`` is off."""
    target_uuid: str
    role: str
    reason: str
    floor: float
    score: float
    n_obs: int
    attributions: Dict[str, float] = field(default_factory=dict)


def _behavioural_evidence(proposal: SlashProposal) -> dict:
    """The behavioural-anomaly evidence_ref carried by the attestation: the
    explainable per-feature attribution (the detector's verdict). Distinct from
    the reputation process's Merkle inclusion proof (``build_slash_evidence``),
    which ties a slash to a committed ledger transaction."""
    return {
        'kind': 'behavioural_anomaly',
        'reason': proposal.reason,
        'role': proposal.role,
        'score': round(float(proposal.score), 6),
        'n_obs': int(proposal.n_obs),
        'attributions': {k: round(float(v), 6)
                         for k, v in proposal.attributions.items()},
    }


class PeerBehaviourGovernor:
    """Embeds a :class:`BehaviorMonitor` in a node and governs its proposals.

    Args:
        host:       the node (supplies ``.identity`` and ``.peers``).
        base_seed:  per-entity model seed (same on every node -> same model).
        slash_floor: reputation floor proposals pin to.
        auto_slash: False (default, fail-safe / human-on-the-loop) records a
                    :class:`SlashRecommendation`; True submits the attestation
                    into the quorum flow autonomously.
        default_role: role label used when a peer's role cannot be derived.
        detector_kwargs: forwarded to every per-entity detector.
    """

    def __init__(self, host, base_seed: int = 0,
                 slash_floor: float = DEFAULT_SLASH_FLOOR,
                 auto_slash: bool = False, default_role: str = 'peer',
                 detector_kwargs: Optional[dict] = None):
        self.host = host
        self.auto_slash = bool(auto_slash)
        self.default_role = str(default_role)
        self.monitor = BehaviorMonitor(
            base_seed=base_seed, slash_floor=slash_floor,
            reason=SlashAttestation.REASON_SUSTAINED_ANOMALY,
            **(detector_kwargs or {}))
        # Targets already acted on (idempotency across ticks), keyed by uuid str.
        self._acted: set = set()
        # Proposals whose submission hit a transient failure (e.g. a full queue);
        # retried next enforce so a momentary contention can't drop a slash.
        self._retry: List[SlashProposal] = []
        # Recommendations surfaced for a human (auto_slash off) + audit trail.
        self.recommendations: List[SlashRecommendation] = []

    # -- observation -------------------------------------------------------

    def observe(self, peer_id: str, role: str,
                event: AccessEvent) -> AnomalyDecision:
        """Fold one peer access event into its detector (proposals are queued
        in the monitor; drain them with :meth:`enforce`)."""
        return self.monitor.observe(peer_id, role, event)

    def ingest_message(self, message) -> Optional[AnomalyDecision]:
        """Translate a node message into an access event (via
        :meth:`access_event_from`) and observe it. Returns the decision or None
        if the message is not a recognizable peer access event."""
        triple = self.access_event_from(message)
        if triple is None:
            return None
        return self.observe(*triple)

    def access_event_from(
            self, message) -> Optional[Tuple[str, str, AccessEvent]]:
        """Translate one observed node message into ``(peer_id, role,
        AccessEvent)`` or None. Overridable seam -- the observable stream is
        deployment dependent. ``peer_id`` is always the actor's UUID *string*."""
        fn = getattr(message, 'function', None)
        frm = getattr(message, 'from_whom', None)
        uuid = getattr(frm, 'uuid', None)
        if fn is None or uuid is None:
            return None
        cap = self._capability_name(message)
        if cap is None:
            return None
        return (str(uuid), self.role_of(str(uuid), message),
                AccessEvent(time=now().timestamp(), capability=cap,
                            refused=bool(getattr(message, 'refused', False)),
                            counterparty=str(self.host.identity.uuid)))

    @staticmethod
    def _capability_name(message) -> Optional[str]:
        obj = getattr(message, 'obj', None)
        cap = getattr(obj, 'capability', None) or getattr(message, 'capability', None)
        name = getattr(cap, 'name', None)
        if name is not None:
            return str(name)
        return cap if isinstance(cap, str) else None

    def role_of(self, peer_id: str, message=None) -> str:
        """Role under which ``peer_id`` acted. Default is a single role label;
        override to key detectors by a deployment's actual role taxonomy."""
        return self.default_role

    # -- enforcement (governed path) ---------------------------------------

    def enforce(self, queues) -> None:
        """Drain the library's proposals and dispose of each: submit a slash
        (when autonomous) or record a recommendation (human-on-the-loop). A
        proposal whose submission transiently fails is kept and retried next
        call."""
        pending = self._retry + self.monitor.poll_proposals()
        self._retry = []
        for proposal in pending:
            if not self._govern(queues, proposal):
                self._retry.append(proposal)

    def _govern(self, queues, proposal: SlashProposal) -> bool:
        """Dispose of one proposal. Returns True when handled (or deliberately
        skipped) and False when a transient submit failure should be retried."""
        target = proposal.peer_id
        if target in self._acted:
            return True
        try:
            target_uuid = UUID(target)
        except (ValueError, AttributeError, TypeError):
            logger.debug('Anomaly target %r is not a uuid; skipping', target)
            return True
        if str(getattr(self.host.identity, 'uuid', None)) == target:
            return True  # never slash self
        if self.host.peers.find_by_uuid(target_uuid) is None:
            logger.debug('Anomaly target %s not a known peer; skipping', target)
            return True

        if not self.auto_slash:
            # Human-on-the-loop: record once and let an operator promote it.
            self.recommendations.append(SlashRecommendation(
                target_uuid=target, role=proposal.role, reason=proposal.reason,
                floor=proposal.floor, score=proposal.score, n_obs=proposal.n_obs,
                attributions=dict(proposal.attributions)))
            self._acted.add(target)
            logger.warning(
                'SLASH RECOMMENDED (human-on-the-loop): target=%s role=%s '
                'floor=%.2f why=%r -- set auto_slash=True or promote manually',
                target, proposal.role, proposal.floor, proposal.top_features(3))
            return True
        return self._submit_slash(queues, target_uuid, proposal)

    def _submit_slash(self, queues, target_uuid: UUID,
                      proposal: SlashProposal) -> bool:
        """Translate a proposal into a SlashAttestation and put it on the
        reputation queue (once per target). forward_slash stamps epoch/nonce,
        signs, self-applies the floor, and runs the co-sign quorum so peers
        adopt it. The quorum -- not this node -- is the disposer. Returns False
        on a transient put failure so the caller retries."""
        target = str(target_uuid)
        if target in self._acted:
            return True
        if queues is None or CfgIds.reputation not in queues:
            return True  # nowhere to submit; not a transient failure
        att = SlashAttestation(
            slasher_uuid=self.host.identity.uuid, target_uuid=target_uuid,
            reason=proposal.reason, floor_score=proposal.floor,
            evidence_ref=_behavioural_evidence(proposal))
        try:
            queues[CfgIds.reputation].put(att, block=True, timeout=queue_cadence)
        except Exception:
            logger.exception('Failed to submit slash for %s (will retry)', target)
            return False
        self._acted.add(target)
        logger.warning('SLASH submitted: target=%s reason=%s floor=%.2f',
                       target, proposal.reason, proposal.floor)
        return True
