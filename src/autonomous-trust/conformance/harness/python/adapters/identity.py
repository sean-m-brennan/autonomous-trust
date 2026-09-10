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

"""Identity-protocol adapter for the AT conformance corpus (Phase C).

Drives `kind: scenario` cases: builds real `IdentityProcess` instances
(with mocked subsystems and synchronous_dispatch flipped on so threading
becomes deterministic), feeds each step's inbound through the protocol's
handler registry, and captures every outbound message via shimmed queues.

Phase C wires the canonical new-node-admission flow plus an amnesia path.
Wire / crypto / negative kinds for the identity protocol are out of scope.
"""

from __future__ import annotations

import hashlib
import logging
import os
import queue
import tempfile
from dataclasses import dataclass, field
from types import SimpleNamespace
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid5

from autonomous_trust.core.algorithms.impl import AgreementImpl
from autonomous_trust.core.capabilities import Capabilities, PeerCapabilities
from autonomous_trust.core.config import Configuration, from_json_string, to_json_string
from autonomous_trust.core.identity import Group, Identity, Peers
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.identity.first_contact import _FLAG as FIRST_CONTACT_FLAG
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.identity.zta import ZtaPolicy
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.network.network import Network
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds, PackageHash

from ...common.negative_runner import run_wire_negative
from ...common.scenario_loader import Case
from ..scenario_engine import (
    CapturedMessage,
    ParticipantHandle,
    ScenarioContext,
    run_scenario,
)


# Twelve-byte canonical UUID prefix; per-participant identity_id is derived
# from this plus a stable suffix, so identity UUIDs are deterministic across
# scenario runs.
_DEFAULT_BLOCK_IMPL = AgreementImpl.POA.value

# Pseudo-function (not a wire message): a scenario step with this `function`
# drives the periodic caps-resync sweep on the target participant instead of
# dispatching a handler. Used by caps-resync-max-per-sweep to pin
# CAPS_RESYNC_MAX_PER_SWEEP. The C adapter recognizes the same string.
_TRIGGER_CAPS_RESYNC = 'trigger_caps_resync'

# Pseudo-function: drive the requestor-side subtree-roster enumeration on the
# target participant (aggregate_subtree_roster over a fetch that asks each
# gateway for its local members + child gateways). Used by
# subtree-member-roster. The C adapter recognizes the same string.
#: Namespace for the synthetic uuids these constructors mint -- the cohort ids
#: in a hierarchy claim, and the "nobody" peer a tier update can name. Fixed
#: so a replay produces the same bytes, and distinct from the participant-uuid
#: namespace so a minted cohort can never collide with a participant.
_HIER_NS = UUID('00000000-0000-0000-0000-000000000bbb')

_TRIGGER_SUBTREE_ROSTER = 'trigger_subtree_roster'
# Pseudo-function: re-derive this participant's place in the gateway tree
# (protocol step 7). Observable via the `parent_gateway` expected_state key; the
# advertisement it emits restates the derived value, so nothing wire-shaped is
# asserted. Mirrors the C adapter's trigger_hierarchy.
_TRIGGER_HIERARCHY = 'trigger_hierarchy'

# Pseudo-function: solicit membership in a cohort this participant is NOT in (runtime
# cross-group join, doc/architecture/gateway-reputation-tree.md). The step's payload
# names the target cohort (`group_uuid`), which the scenario pins via fixtures.groups so
# it is the same string in both harnesses. Unlike the other pseudo-functions this one
# DOES emit wire traffic -- the ordinary request_access, now carrying the target in
# payload slot 3 -- because the whole point is that a join is the ordinary admission and
# not a private side channel. The C adapter recognizes the same string.
_TRIGGER_COHORT_JOIN = 'trigger_cohort_join'

# Pseudo-function: drive one operator-attended pull (ethne D8/Q9) from the
# step's `from` participant against its `to` participant, end to end — mint the
# nonce, build the target's answer, verify it back at the puller. A pseudo-step
# rather than two wire steps because the two runtimes reach the attended state
# by DIFFERENT routes: Python's identity process must ask the main loop (which
# alone can see the console's OperatorSession), while C reads the
# identity_set_operator_attended seam directly. The adapter absorbs that
# difference so the observable — what the pull yields — is compared like for
# like. The C adapter recognizes the same string.
_TRIGGER_ATTEST_PULL = 'trigger_attest_pull'

# Pseudo-function: re-present the answer from the PREVIOUS pull. It must be
# refused: its nonce is retired, and an attestation replayable at will would
# say nothing about attendance NOW. The C adapter recognizes the same string.
_TRIGGER_ATTEST_REPLAY = 'trigger_attest_replay'

# Pseudo-function: drop the OPTIONAL first-contact handshake's in-memory
# spent-nonce guard without touching the file it persists to -- the closest a
# single-process harness gets to restarting the node. What the guard knows
# afterwards it read back off disk, which is the whole point of
# first-contact-nonce-survives-restart. The C adapter recognizes the same
# string. See doc/architecture/first-contact.md.
_TRIGGER_FC_RESTART = 'trigger_first_contact_restart'

# Pseudo-function: drive the INITIATOR half of the 1:1 handshake through the
# production call (first_contact.initiate) rather than handing the target a
# hello the harness built. A pseudo-step because `initiate` is an API call, not
# an inbound message -- there is nothing to dispatch. The C adapter recognizes
# the same string. See first-contact-initiate-reaches-the-hint.
_TRIGGER_FC_INITIATE = 'trigger_first_contact_initiate'


@dataclass
class _Participant:
    """Wraps an IdentityProcess and the captured outbox for a participant."""
    id: str
    role: str
    identity: Identity
    process: IdentityProcess
    queues: dict[str, Any]
    outbox_buffer: list[Message] = field(default_factory=list)
    # Persistent per-function emission tally (NOT cleared on drain). The
    # partition cooldown scenarios assert on how many probes a participant
    # emitted across N repeated signals; outbox_buffer is drained every
    # dispatch, so a separate running tally is needed. Keyed by the
    # Message.function string (e.g. 'group_partition_probe'). Mirrors the
    # C adapter's scan of the engine's captured[] for the same function.
    emit_tally: dict[str, int] = field(default_factory=dict)
    # Result of a trigger_subtree_roster enumeration on this participant: the
    # flattened member uuids (strings) of its cohort subtree. Filled by the
    # engine's _dispatch; read by the subtree_roster expected-state check.
    subtree_roster: list = field(default_factory=list)
    # Result of trigger_hierarchy: the DERIVED parent gateway as a participant
    # id, or '' for a node that tops its own cohort. Filled by _dispatch (which
    # holds the uuid->pid registry) and read by the parent_gateway check.
    parent_gateway_pid: str = ''
    # Results of trigger_attest_pull / trigger_attest_replay on this
    # participant (as the PULLER): the attested-now stamp the last accepted
    # pull yielded, and the accept/reject verdict of every pull in order.
    # Read by the attested_now / attest_accepted expected-state checks.
    attest_stamp: float = 0.0
    attest_accepted: list = field(default_factory=list)
    # The last answer received, kept so trigger_attest_replay can re-present it.
    attest_last_answer: dict = field(default_factory=dict)
    # Pinned attestation clock from the operator_session / clocks fixture
    # (0 = unset).
    attest_clock: float = 0.0
    # Cohort clock samples this participant MEASURED as the puller, relabelled
    # from the production handler's uuid key to the scenario's participant id so
    # expected_state can name a peer language-agnostically. The values come
    # straight out of IdentityProcess._peer_clock_samples -- the harness
    # relabels, it does not compute. See doc/architecture/cohort-clock-skew.md.
    attest_clock_samples: dict = field(default_factory=dict)
    # participant id -> uuid string, for every participant in the scenario.
    # Filled by the adapter at setup; see _uuid_for_pid.
    pid_to_uuid: dict = field(default_factory=dict)
    # Where trigger_first_contact_initiate actually addressed its hello: the
    # host on the outbound to_whom. Read by the
    # first_contact_hello_endpoint check, which pins that `initiate` prefers
    # the invitation's rendezvous hint over the inviter's advertised address.
    fc_hello_endpoint: str = ''

    def _uuid_for_pid(self, pid: str) -> str:
        """Resolve a scenario participant id to its uuid string.

        Raises rather than returning a miss: a state key naming a participant
        that does not exist is a broken fixture, and silently comparing
        against nothing would make the assertion pass vacuously.
        """
        try:
            return self.pid_to_uuid[pid]
        except KeyError:
            raise AssertionError(
                f'{self.id}: expected_state names unknown participant {pid!r}'
            ) from None

    def drain_outbox(self) -> list[CapturedMessage]:
        captured: list[CapturedMessage] = []
        # uuid -> participant id, inverted from the map every participant is
        # handed at setup. See _pid_of for why uuid and not petname.
        uuid_to_pid = {str(u): p for p, u in (self.pid_to_uuid or {}).items()}
        for msg in self.outbox_buffer:
            captured.append(_to_captured(msg, emitter_id=self.id,
                                         uuid_to_pid=uuid_to_pid))
        self.outbox_buffer.clear()
        return captured

    def _check_expected_state(self, asserts: dict[str, Any]) -> None:
        """Implements the engine's optional per-participant state check."""
        for key, expected in asserts.items():
            if key == 'phase':
                actual = self.process.phase
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: phase mismatch — expected {expected}, got {actual}'
                    )
            elif key == 'peer_count':
                actual = sum(len(level) for level in self.process.peers.hierarchy)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: peer_count mismatch — expected {expected}, got {actual}'
                    )
            elif key == 'has_peer':
                actual_uuids = {
                    str(p.uuid) for level in self.process.peers.hierarchy for p in level.values()
                }
                if expected not in actual_uuids:
                    raise AssertionError(
                        f'{self.id}: expected peer uuid {expected} in peer list, '
                        f'got {sorted(actual_uuids)}'
                    )
            elif key == 'direct_peers':
                # The OPTIONAL 1:1 first-contact handshake's admission, as
                # {participant_id: bool}. True asserts BOTH halves of what a
                # direct peer is: present in the peer list, and ABSENT from the
                # group address map. The second half is the security property --
                # a first-contact peer is directly reachable, not a group
                # member, so the shared group key must not follow it in.
                # False asserts the peer was not admitted at all (the refusal
                # cases). C mirrors by scanning protocol.peers[] and
                # protocol.group.address_map.
                grp = self.process.group
                # The address map's KEYS are the member uuids. Reached through
                # the private attribute deliberately: `Group.addresses` yields
                # the map's VALUES (the addresses), so comparing a uuid against
                # it would never match and the group half of this assertion
                # would pass vacuously -- which is exactly what a mutation test
                # of "let the group key follow a direct peer in" caught. The
                # map degrades to a non-dict in one legacy form (see
                # Group.to_canonical), which carries no uuids at all.
                raw = getattr(grp, '_address_map', None) if grp is not None else None
                in_group = {str(u) for u in raw} if isinstance(raw, dict) else set()
                have = {str(getattr(p, 'uuid', '')) for p in self.process.peers.all}
                for pid, want in (expected or {}).items():
                    peer_uuid = str(self._uuid_for_pid(pid))
                    if not want:
                        if peer_uuid in have:
                            raise AssertionError(
                                f'{self.id}: {pid} was admitted as a peer, '
                                f'expected refusal')
                        continue
                    if peer_uuid not in have:
                        raise AssertionError(
                            f'{self.id}: {pid} is not a peer, expected a '
                            f'direct-peer admission')
                    if peer_uuid in in_group:
                        raise AssertionError(
                            f'{self.id}: {pid} landed in the GROUP address map; '
                            f'a first-contact peer must not become a group '
                            f'member (the group key would follow)')
            elif key == 'first_contact_hello_endpoint':
                # Where trigger_first_contact_initiate addressed its hello.
                # Pins the resolution ORDER: the invitation's rendezvous hint
                # wins over the address the inviter's identity advertises.
                # Both are well-formed addresses, so preferring the wrong one
                # fails silently -- it works on a LAN and never reaches a
                # remote friend. C mirrors via ic_impl_t.fc_hello_endpoint.
                actual = self.fc_hello_endpoint
                if actual != str(expected):
                    raise AssertionError(
                        f'{self.id}: first_contact_hello_endpoint={actual!r}, '
                        f'expected {str(expected)!r}')
            elif key == 'first_contact_acks_emitted':
                # How many first_contact_hello_ack messages this participant
                # emitted over the whole scenario. The observable for the
                # single-use guard: the peer is legitimately admitted on the
                # first redemption, so a replay that was honored twice differs
                # ONLY in what went back out. C mirrors by scanning the
                # engine's captured[] for the same function.
                actual = self.emit_tally.get(IdentityProtocol.hello_ack, 0)
                if actual != int(expected):
                    raise AssertionError(
                        f'{self.id}: first_contact_acks_emitted={actual}, '
                        f'expected {int(expected)}')
            elif key == 'first_contact_nonce_spent':
                # The durable single-use guard itself, as {nonce: bool}. Read
                # after a trigger_first_contact_restart, this is the only place
                # the on-disk store is observed rather than inferred -- and the
                # two runtimes read each other's file only if they agree on its
                # shape. C mirrors via at_first_contact_nonce_spent.
                guard = getattr(self.process, '_first_contact_nonces', None)
                for nonce, want in (expected or {}).items():
                    actual = bool(guard is not None and str(nonce) in guard)
                    if actual != bool(want):
                        raise AssertionError(
                            f'{self.id}: first_contact_nonce_spent[{nonce!r}]='
                            f'{actual}, expected {bool(want)}')
            elif key == 'peer_caps_count':
                # Number of caps registered in self.peer_capabilities for
                # any OTHER participant's uuid. With per-cap dedup in
                # handle_caps_response, the count reflects unique caps
                # registered across all responders. C's accessor sums
                # over all non-self uuids in id_state.peer_caps_map, so
                # the assertion is symmetric.
                pcap = self.process.peer_capabilities
                count = 0
                for cap_name, uuid_list in pcap.items():
                    count += len(uuid_list)
                if count != expected:
                    raise AssertionError(
                        f'{self.id}: peer_caps_count={count}, expected {expected}'
                    )
            elif key == 'peer_caps_descriptor':
                # Assert a capability descriptor learned from caps_response.
                # expected = {cap_name: {field: value, ...}}; each field must
                # match the stored (size-bounded) descriptor. C's accessor
                # reads the equivalent per-cap descriptor from its peer_caps map.
                descriptors = getattr(self.process.peer_capabilities,
                                      'descriptors', {})
                for cap_name, fields in expected.items():
                    stored = descriptors.get(cap_name)
                    if stored is None:
                        raise AssertionError(
                            f'{self.id}: no descriptor for cap {cap_name!r}; '
                            f'have {sorted(descriptors)}')
                    for fk, fv in fields.items():
                        if stored.get(fk) != fv:
                            raise AssertionError(
                                f'{self.id}: descriptor[{cap_name!r}][{fk!r}]='
                                f'{stored.get(fk)!r}, expected {fv!r}')
            elif key == 'partition_probes_emitted':
                # Number of group_partition_probe messages this participant
                # emitted over the whole scenario. The signal-cooldown
                # scenario delivers N partition_signals from the same
                # from_addr and asserts the 10s per-addr cooldown collapses
                # them to a single emitted probe. C mirrors this by scanning
                # the engine's captured[] for (from==self, function==probe).
                actual = self.emit_tally.get(IdentityProtocol.partition_probe, 0)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: partition_probes_emitted={actual}, '
                        f'expected {expected}'
                    )
            elif key == 'partition_responses_emitted':
                actual = self.emit_tally.get(IdentityProtocol.partition_response, 0)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: partition_responses_emitted={actual}, '
                        f'expected {expected}'
                    )
            elif key == 'freshness_refusals':
                # {verb: N} -- messages this participant refused as stale,
                # per verb. The POSITIVE observable for the freshness guard:
                # every other partition observable is an emission count, and a
                # second delivery is already suppressed by the per-sender
                # response cooldown (and adoption by the in-flight recovery
                # marker), so "one response after two deliveries" is a number
                # the cooldown alone produces. Only the mark can produce a
                # refusal. C reads the same tally through
                # identity_freshness_refusals(); note it is process-global
                # there, so a case asserting this must have exactly one
                # participant doing the refusing.
                for verb, want in expected.items():
                    actual = self.process.freshness.refusals(verb)
                    if actual != int(want):
                        raise AssertionError(
                            f'{self.id}: freshness_refusals[{verb!r}]={actual}, '
                            f'expected {want}'
                        )
            elif key == 'caps_query_emitted':
                # Number of directed `peer_caps_query` messages this participant
                # emitted -- driven by the periodic caps-resync sweep (triggered
                # via the trigger_caps_resync pseudo-step). With more cap-less
                # peers than the per-sweep cap, the sweep emits exactly
                # CAPS_RESYNC_MAX_PER_SWEEP and defers the rest. C mirrors by
                # scanning captured[] for (from==self, peer_caps_query).
                actual = self.emit_tally.get(IdentityProtocol.caps_query, 0)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: caps_query_emitted={actual}, '
                        f'expected {expected}'
                    )
            elif key == 'propose_emitted':
                # Number of `propose` messages this (border-guard) participant
                # emitted. A welcomed newcomer triggers exactly one propose; a
                # ZTA-rejected newcomer triggers none — so this is the
                # admit/reject observable for the zta-x509-* scenarios. C
                # mirrors by scanning captured[] for (from==self, propose).
                actual = self.emit_tally.get(IdentityProtocol.propose, 0)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: propose_emitted={actual}, expected {expected}'
                    )
            elif key == 'votes_emitted':
                # Approval votes this participant emitted in response to a
                # received proposal. Python queues the vote in confirmed_block
                # during the propose handler (_process_id) and only emits it
                # on the next vote_response cycle, so _dispatch ticks
                # vote_response after a propose inbound to flush it; C emits
                # in-handler. Both converge on one vote_on_peer per accepted
                # proposal, and zero when the sybil/blacklist guard rejects.
                actual = self.emit_tally.get(IdentityProtocol.vote, 0)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: votes_emitted={actual}, expected {expected}'
                    )
            elif key == 'group_owns_private_key':
                # True iff this participant's group still holds the shared
                # PRIVATE box key (can decrypt group traffic). The invariant a
                # membership-only group_key_update must preserve: adopting a
                # larger but public-only group must NOT drop our private key.
                # C mirrors via sodium_is_zero(group.encryptor.private).
                grp = self.process.group
                actual = bool(grp is not None and grp.owns_private_key)
                if actual != bool(expected):
                    raise AssertionError(
                        f'{self.id}: group_owns_private_key={actual}, '
                        f'expected {bool(expected)}'
                    )
            elif key == 'group_size':
                # Number of addresses in this participant's group address map —
                # proves the larger membership WAS adopted (not a no-op). C
                # mirrors via map_size(group.address_map).
                grp = self.process.group
                actual = len(list(grp.addresses)) if grp is not None else 0
                if actual != int(expected):
                    raise AssertionError(
                        f'{self.id}: group_size={actual}, expected {int(expected)}'
                    )
            elif key == 'group_key_epoch':
                # How many times this participant's group key has been rotated.
                # Admission rotates (doc/architecture/gateway-reputation-tree.md), so a welcomer that admitted one
                # peer sits at 1 -- that is what keeps cohort traffic recorded
                # BEFORE a join closed to the joiner. C mirrors via
                # group_t.key_epoch.
                grp = self.process.group
                actual = int(grp.key_epoch) if grp is not None else 0
                if actual != int(expected):
                    raise AssertionError(
                        f'{self.id}: group_key_epoch={actual}, '
                        f'expected {int(expected)}'
                    )
            elif key == 'group_uuid':
                # This participant's PRIMARY group. Pinned by fixtures.groups,
                # so the scenario can state it language-agnostically. The
                # cross-group join asserts it is UNCHANGED: a gateway joining a
                # child cohort must not have swapped its own group for the one
                # it just joined. C mirrors via proc->protocol.group.uuid.
                grp = self.process.group
                actual = str(grp.uuid) if grp is not None else ''
                if actual != str(expected):
                    raise AssertionError(
                        f'{self.id}: group_uuid={actual}, expected {expected}'
                    )
            elif key == 'child_group_count':
                # Cohorts this participant gateways. A runtime join lands HERE
                # and not in the primary group -- that separation is the whole
                # observable. C mirrors via map_size(protocol.child_groups).
                actual = len(getattr(self.process, 'child_groups', {}) or {})
                if actual != int(expected):
                    raise AssertionError(
                        f'{self.id}: child_group_count={actual}, '
                        f'expected {int(expected)}'
                    )
            elif key == 'provisional_peer_count':
                # Peers this participant is holding PROVISIONAL under two-phase
                # admission (doc/architecture/identity-protocol.md): confirm(s) received but the distinct-
                # confirmer quorum not yet met, so the group key is withheld.
                # Cleared on promotion. C mirrors via identity_provisional_count.
                actual = len(getattr(self.process, '_provisional_confirmations', {}))
                if actual != int(expected):
                    raise AssertionError(
                        f'{self.id}: provisional_peer_count={actual}, '
                        f'expected {int(expected)}'
                    )
            elif key == 'subtree_roster':
                # The flattened membership roll of this gateway's cohort subtree
                # (trigger_subtree_roster), as sorted participant ids — each
                # roster member uuid mapped back to its participant by the
                # engine, so the check is language-agnostic. C mirrors via
                # identity_aggregate_subtree_roster + the same uuid->id mapping.
                actual = sorted(self.subtree_roster)
                want = sorted(expected)
                if actual != want:
                    raise AssertionError(
                        f'{self.id}: subtree_roster={actual}, expected {want}')
            elif key == 'hierarchy_of':
                # What this participant RECORDED from a peer's hierarchy claim
                # (protocol step 7), as {participant_id: {rank, children}}.
                # The recording is gated -- proved gateway authority, the
                # claim naming its own sender, and a freshness sequence above
                # the mark -- and every one of those gates is invisible in the
                # emitted traffic, so the store is the only place a refusal
                # can be observed. `null` asserts nothing was recorded for
                # that peer. C mirrors via identity_get_peer_hierarchy.
                for pid, want in (expected or {}).items():
                    peer_uuid = str(self._uuid_for_pid(pid))
                    claim = (getattr(self.process, 'peer_hierarchy', {})
                             or {}).get(peer_uuid)
                    if want is None:
                        if claim is not None:
                            raise AssertionError(
                                f'{self.id}: recorded a hierarchy claim from '
                                f'{pid}, expected none')
                        continue
                    if claim is None:
                        raise AssertionError(
                            f'{self.id}: no hierarchy claim recorded from '
                            f'{pid}, expected {want}')
                    if 'rank' in want and int(claim.get('rank', 0)) != int(want['rank']):
                        raise AssertionError(
                            f'{self.id}: hierarchy_of[{pid}].rank='
                            f'{claim.get("rank")}, expected {want["rank"]}')
                    if 'children' in want:
                        got_n = len(claim.get('children') or [])
                        if got_n != int(want['children']):
                            raise AssertionError(
                                f'{self.id}: hierarchy_of[{pid}].children='
                                f'{got_n}, expected {want["children"]}')
            elif key == 'peer_tier':
                # The reputation-derived trust tier this participant applied
                # to a peer, as {participant_id: tier}. Distinct from rank:
                # tier is the runtime, local-view trust attribute a
                # negotiation tier-gate reads (doc/architecture/trust-tiers.md),
                # and it arrives only over local IPC. C mirrors via
                # identity_get_peer_tier.
                for pid, want in (expected or {}).items():
                    peer_uuid = self._uuid_for_pid(pid)
                    actual = None
                    if str(self.identity.uuid) == str(peer_uuid):
                        actual = int(getattr(self.identity, '_tier', 0) or 0)
                    else:
                        for peer in self.process.peers.all:
                            if str(getattr(peer, 'uuid', '')) == str(peer_uuid):
                                actual = int(getattr(peer, '_tier', 0) or 0)
                                break
                    if actual is None:
                        raise AssertionError(
                            f'{self.id}: peer_tier names {pid}, which is not '
                            f'a known peer here')
                    if actual != int(want):
                        raise AssertionError(
                            f'{self.id}: peer_tier[{pid}]={actual}, '
                            f'expected {int(want)}')
            elif key == 'parent_gateway':
                # The higher-rank node this participant DERIVES as its parent (protocol
                # step 7, doc/architecture/gateway-reputation-tree.md), as a participant
                # id or '' for a node that tops its own cohort. Derived, never accepted
                # from a peer, so the pin is on the arithmetic: rank among members that
                # can prove a shared anchor, ties by greater uuid. C mirrors via
                # identity_get_parent_gateway.
                actual = self.parent_gateway_pid
                if actual != (expected or ''):
                    raise AssertionError(
                        f'{self.id}: parent_gateway={actual!r}, '
                        f'expected {(expected or "")!r}')
            elif key == 'attested_now':
                # The attended-now stamp this participant's last ACCEPTED pull
                # yielded: a pinned epoch when a human is at the target's
                # console, 0.0 when nobody is. A rejected pull leaves it
                # untouched, which is how "replay changes nothing" is stated.
                # Compared exactly — the scenario pins the clock
                # (fixtures.operator_session.clock) precisely so a live
                # wall-clock stamp can never enter the comparison. C mirrors
                # via the identity_set_attest_clock seam.
                #
                # Scope: this pins the SESSION -> STAMP derivation and the
                # nonce state machine. Whether the operator credential inside
                # the answer verifies against the operator anchor is pinned
                # separately by operator-bound-verified / -lying-rejected,
                # which need the X.509 toolchain.
                actual = float(self.attest_stamp)
                if actual != float(expected):
                    raise AssertionError(
                        f'{self.id}: attested_now={actual}, expected {float(expected)}')
            elif key in ('peer_clock_offset', 'peer_clock_delay',
                         'peer_clock_usable'):
                # Cohort clock skew measured from the attest round trip
                # (cohort-clock-skew.md, Stage 0). expected = {peer_ref: value},
                # peer_ref being a participant id.
                #
                # These read what the PRODUCTION handler recorded
                # (_peer_clock_samples), not anything the harness computed --
                # unlike attested_now/attest_accepted, which the harness derives
                # itself and which therefore stayed green when
                # handle_attest_response was half-broken by a signature change.
                for peer_ref, want in (expected or {}).items():
                    sample = self.attest_clock_samples.get(peer_ref)
                    if sample is None:
                        raise AssertionError(
                            f'{self.id}: no clock sample for {peer_ref}')
                    if key == 'peer_clock_usable':
                        if bool(sample.usable) != bool(want):
                            raise AssertionError(
                                f'{self.id}: {peer_ref} clock_usable='
                                f'{sample.usable}, expected {want}')
                        continue
                    actual = (sample.offset if key == 'peer_clock_offset'
                              else sample.delay).total_seconds()
                    # Tolerance, not equality: both runtimes reach this through
                    # double arithmetic, and pinned clocks make the value exact
                    # to well inside a microsecond.
                    if abs(actual - float(want)) > 1e-6:
                        raise AssertionError(
                            f'{self.id}: {peer_ref} {key}={actual}, '
                            f'expected {float(want)}')
            elif key == 'attest_accepted':
                # Per-pull accept/reject verdicts, in step order. The nonce
                # state machine: an answer counts only against the pull that
                # asked for it, so a re-presented answer must read false.
                actual = [bool(v) for v in self.attest_accepted]
                want = [bool(v) for v in expected]
                if actual != want:
                    raise AssertionError(
                        f'{self.id}: attest_accepted={actual}, expected {want}')
            elif key == 'operator_bound':
                # The welcomer's VERIFIED operator-attended determination for
                # each named stored peer (ethne D8/Q9). expected = {peer_ref:
                # bool}, where peer_ref is a participant id (matched against the
                # stored peer's nickname "<id>.scenario") or a raw uuid — both
                # language-agnostic, so C mirrors via the same accessor. Reads
                # the operator_bound the ZTA gate set on the stored peer.
                stored = [p for level in self.process.peers.hierarchy
                          for p in level.values()]

                def _find(ref):
                    for p in stored:
                        if (str(p.uuid) == ref or p.nickname == ref
                                or p.nickname == f'{ref}.scenario'):
                            return p
                    return None
                for ref, want_val in expected.items():
                    peer = _find(ref)
                    if peer is None:
                        raise AssertionError(
                            f'{self.id}: operator_bound: no stored peer {ref!r}')
                    actual_val = bool(getattr(peer, 'operator_bound', False))
                    if actual_val != bool(want_val):
                        raise AssertionError(
                            f'{self.id}: operator_bound[{ref}]={actual_val}, '
                            f'expected {want_val}')
            elif key == 'operator_guardian':
                # { peer_ref: bool } — whether the welcomer KEPT the peer's
                # advertised guardian key, which it does only after verifying
                # the binding against the operator anchor. Deliberately a bool
                # and not the key bytes: the assertion is about the verdict, and
                # comparing key material would pin the adapter's own derivation
                # in both languages instead of the rule. The stored key IS the
                # verdict (there is no separate verified flag), so an empty key
                # here means refused-or-never-offered.
                stored = [p for level in self.process.peers.hierarchy
                          for p in level.values()]

                def _find_g(ref):
                    for p in stored:
                        if (str(p.uuid) == ref or p.nickname == ref
                                or p.nickname == f'{ref}.scenario'):
                            return p
                    return None
                for ref, want_val in expected.items():
                    peer = _find_g(ref)
                    if peer is None:
                        raise AssertionError(
                            f'{self.id}: operator_guardian: no stored peer {ref!r}')
                    actual_val = bool(getattr(peer, 'operator_pubkey', b''))
                    if actual_val != bool(want_val):
                        raise AssertionError(
                            f'{self.id}: operator_guardian[{ref}]={actual_val}, '
                            f'expected {want_val}')
            else:
                raise AssertionError(f'{self.id}: unsupported expected_state key {key!r}')


def _uuid_of(ident) -> bytes:
    """A participant's uuid as raw bytes. Python holds it as a UUID or a string
    depending on how the identity was built; the binding covers the 16 raw bytes
    C binds, so the two must agree here rather than at each caller."""
    u = ident.uuid
    return u.bytes if isinstance(u, UUID) else UUID(str(u)).bytes


def _scenario_operator_binding(corpus_root: Path, ident: Identity,
                               variant: str) -> tuple[bytes, bytes]:
    """Mint an (operator_pubkey, binding) pair for a scenario participant.

    The operator key is derived deterministically from the participant's uuid
    rather than generated: conformance corpora must produce identical bytes on
    every run and in both languages, and a random keypair would make the C and
    Python adapters disagree for a reason that has nothing to do with the rule
    under test.

    The signature itself is real — RSA PKCS#1 v1.5 over SHA-256 with the leaf
    key from testdata, which is deterministic, so the two adapters produce the
    same bytes without either one pinning them.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    from autonomous_trust.core.identity.operator_binding import (
        operator_binding_preimage,
    )

    # Deterministic 32-byte "operator key": the uuid, domain-separated. Not a
    # real ed25519 secret — nothing in this path signs with it, and AT only ever
    # verifies the BINDING over it.
    op_pub = hashlib.sha256(b'conformance-operator-key:'
                            + _uuid_of(ident)).digest()

    bind_to = ident
    if variant == 'other-identity':
        # Correctly signed by the real operator, but naming a DIFFERENT node —
        # exactly what an attacker gets by harvesting a credential from a
        # clear-text announce (doc/architecture/zta-integration.md). Valid in every way except the
        # one that matters, which is why the pre-image names the node at all.
        bind_to = SimpleNamespace(
            uuid=UUID(bytes=bytes((b + 1) % 256 for b in _uuid_of(ident))),
            signature=ident.signature)

    preimage = operator_binding_preimage(bind_to, op_pub)

    key_name = ('impostor_leaf.key' if variant == 'forged'
                else 'operator_leaf.key')
    with open(corpus_root / 'testdata' / 'zta' / 'certs' / key_name, 'rb') as fp:
        priv = serialization.load_pem_private_key(fp.read(), password=None)
    sig = priv.sign(preimage, padding.PKCS1v15(), hashes.SHA256())
    return op_pub, sig


def _scenario_zta_binding(corpus_root: Path, ident: Identity, cred: bytes,
                          variant: str) -> bytes:
    """Mint a credential->identity binding for a scenario participant
    (doc/architecture/zta-integration.md).

    Signed AT SCENARIO TIME rather than pinned as a blob, for the same reason the
    operator binding is: pinning one recorded signature would let both
    implementations agree on a byte string while disagreeing about what is signed.
    RSA PKCS#1 v1.5 over SHA-256 is deterministic, so the two adapters produce
    identical bytes without either pinning them.

    Variants:
      valid           signed by the leaf whose certificate the peer presents
      forged          signed by an unrelated key (impostor_leaf.key) -- somebody
                      tried to prove entitlement and could not
      other-identity  correctly signed by the real leaf, but over a pre-image
                      naming a DIFFERENT node. This is the harvested-credential
                      case, and the one the whole binding exists to stop.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    from autonomous_trust.core.identity.zta_binding import zta_binding_preimage

    bind_to = ident
    if variant == 'other-identity':
        bind_to = SimpleNamespace(
            uuid=UUID(bytes=bytes((b + 1) % 256 for b in _uuid_of(ident))),
            signature=ident.signature)
    preimage = zta_binding_preimage(bind_to, cred)
    key_name = ('impostor_leaf.key' if variant == 'forged'
                else 'operator_leaf.key')
    with open(corpus_root / 'testdata' / 'zta' / 'certs' / key_name, 'rb') as fp:
        priv = serialization.load_pem_private_key(fp.read(), password=None)
    return priv.sign(preimage, padding.PKCS1v15(), hashes.SHA256())


def _to_captured(msg: Any, emitter_id: str,
                 uuid_to_pid: dict | None = None) -> CapturedMessage:
    """Project a network-bound `Message` into the engine's CapturedMessage."""
    if not isinstance(msg, Message):
        # Non-Message items (Group, Peers, PeerCapabilities updates) are
        # internal IPC traffic; surface them with a synthetic function name
        # so the engine ignores them in matching but they aren't lost.
        return CapturedMessage(
            from_id=emitter_id, to_id='internal',
            function=f'__ipc__/{type(msg).__name__}', payload=msg, raw=msg,
        )
    to_id = _resolve_to_id(msg, uuid_to_pid)
    return CapturedMessage(
        from_id=emitter_id,
        to_id=to_id,
        function=msg.function,
        payload=msg.obj,
        raw=msg,
    )


def _pid_of(ident, uuid_to_pid) -> str:
    """One recipient -> participant id, by UUID first.

    The petname is only a usable label for an identity the HARNESS built: it is
    a local Zooko name, never transmitted, so an identity reconstructed from the
    wire (a first-contact invitation carries the canonical public form, which is
    petname-free) gets a locally-DERIVED petname instead, matching no
    participant. Resolving by uuid first fixes that; the petname stays as the
    fallback for a recipient that is not a participant at all. The C adapter's
    _resolve_to_id has always matched on uuid.
    """
    uuid = str(getattr(ident, 'uuid', '') or '')
    if uuid_to_pid and uuid in uuid_to_pid:
        return uuid_to_pid[uuid]
    return getattr(ident, 'petname', '') or uuid or str(ident)


def _resolve_to_id(msg: Message, uuid_to_pid: dict | None = None) -> str:
    """Map a Message's to_whom into a scenario-level participant id."""
    to = msg.to_whom
    if to == Network.broadcast:
        return 'broadcast'
    if isinstance(to, Group):
        return 'broadcast'  # group-encrypted broadcast; engine treats both alike
    if isinstance(to, Identity):
        return _pid_of(to, uuid_to_pid)
    if isinstance(to, list) and to:
        return _pid_of(to[0], uuid_to_pid)
    return 'broadcast'


class _CapturingQueue:
    """Stand-in for a multiprocessing.Queue that records every put().

    Mirrors only the methods IdentityProcess actually calls during scenario
    execution: put() with optional block/timeout. get() raises Empty so the
    process loop's polling terminates cleanly if it ever runs.
    """

    def __init__(self, sink: list[Any], name: str) -> None:
        self._sink = sink
        self.name = name

    def put(self, item: Any, block: bool = True, timeout: float | None = None) -> None:
        self._sink.append(item)

    def put_nowait(self, item: Any) -> None:
        self._sink.append(item)

    def get(self, block: bool = True, timeout: float | None = None) -> Any:
        raise queue.Empty

    def get_nowait(self) -> Any:
        raise queue.Empty


class IdentityAdapter:
    """Phase C scenario adapter for the identity protocol."""

    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root
        # Each scenario gets its own scratch dir for any on-disk side effects
        # IdentityProcess._record_group / _record_peers may produce. Wiped on
        # context exit; never read by the harness.
        self._scratch: tempfile.TemporaryDirectory | None = None
        # automate.py stores the digest bytes (not the PackageHash object)
        # in configs[PackageHash.key]; mirror that contract.
        self._package_hash = PackageHash().digest

    def run_scenario(self, case: Case) -> None:
        self._scratch = tempfile.TemporaryDirectory(prefix='at-conformance-id-')
        fc_fix = (case.data.get('fixtures', {}) or {}).get('first_contact') or {}
        fc_prior = os.environ.get(FIRST_CONTACT_FLAG)
        try:
            os.environ[Configuration.ROOT_VARIABLE_NAME] = self._scratch.name
            os.makedirs(os.path.join(self._scratch.name, 'etc/at'), exist_ok=True)
            # The 1:1 handshake is opt-in, and the opt-in is read when the
            # IdentityProcess registers its handlers -- so it has to be set
            # BEFORE the participants are built, and cleared after, or the
            # next scenario inherits it. The durable spent-nonce store lands
            # in the per-scenario scratch root above, so nonces cannot leak
            # from one case into the next. Mirrors the C adapter.
            if fc_fix.get('enabled'):
                os.environ[FIRST_CONTACT_FLAG] = '1'
            else:
                os.environ.pop(FIRST_CONTACT_FLAG, None)

            participants = self._build_participants(case)
            ctx = ScenarioContext(
                case=case,
                participants=participants,
                build_inbound=lambda **kw: self._build_inbound(participants, **kw),
                describe=lambda cm: (cm.from_id, cm.to_id, cm.function, cm.payload),
            )
            run_scenario(ctx)
        finally:
            if fc_prior is None:
                os.environ.pop(FIRST_CONTACT_FLAG, None)
            else:
                os.environ[FIRST_CONTACT_FLAG] = fc_prior
            self._scratch.cleanup()
            self._scratch = None

    # Phase C does not yet wire wire/crypto/negative kinds for identity.
    def run_wire_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('identity wire_vector kind not implemented (Phase C: scenarios only)')

    def run_crypto_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('identity crypto_vector kind not implemented')

    def run_negative(self, case: Case) -> None:
        expected = case.data['expected']['reason_class']
        observed = run_wire_negative(self.corpus_root, case)
        if observed != expected:
            raise AssertionError(
                f'reason_class mismatch: expected {expected!r}, '
                f'observed {observed!r}'
            )

    # ------------------------------------------------------------------
    # Participant construction
    # ------------------------------------------------------------------

    def _build_participants(self, case: Case) -> dict[str, ParticipantHandle]:
        spec_participants = case.data['participants']
        fixtures = case.data.get('fixtures', {}) or {}
        keys_fix: dict[str, Any] = fixtures.get('keys', {}) or {}
        addresses: dict[str, str] = fixtures.get('addresses', {}) or {}

        identities: dict[str, Identity] = {}
        for spec in spec_participants:
            pid = spec['id']
            sig_seed, enc_seed = self._load_keys(pid, keys_fix)
            uuid = self._derive_uuid(pid, fixtures.get('uuids', {}))
            address = addresses.get(pid, f'10.0.0.{len(identities) + 1}')
            identity = Identity(
                uuid, address, f'{pid}.scenario',
                Signature(sig_seed, public_only=False),
                Encryptor(enc_seed, public_only=False),
                pid, False, 0, _DEFAULT_BLOCK_IMPL,
            )
            identities[pid] = identity

        # ZTA credential binding (zta-x509-* scenarios): attach each
        # participant's X.509 credential (DER) from fixtures.credentials so its
        # announce carries it. A participant absent from the map announces with
        # no credential (the "unsigned" forgery). Paths resolve against the
        # corpus root, like fixtures.keys. See doc/architecture/zta-python-parity.md §7.
        cred_fix: dict[str, str] = fixtures.get('credentials', {}) or {}
        for pid, rel in cred_fix.items():
            if pid in identities and rel:
                with open(self.corpus_root / rel, 'rb') as fp:
                    identities[pid].zta_credential = fp.read()

        # The credential->identity binding (doc/architecture/zta-integration.md).
        # `zta_bindings: {<pid>: <variant>}` signs one at scenario time over the
        # credential attached just above — so this must run after that loop, not
        # beside it. The binding rides in the repeated `zta_credentials` field
        # because fields 6-8 have nowhere to put one, which is the whole reason
        # field 16 exists. A participant absent from the map presents an UNBOUND
        # credential: legitimate under binding_mode off/prefer, refused under
        # require, and that difference is what the zta-binding-* pins measure.
        zbind_fix: dict[str, str] = fixtures.get('zta_bindings', {}) or {}
        for pid, variant in zbind_fix.items():
            if pid not in identities:
                continue
            ident = identities[pid]
            cred = getattr(ident, 'zta_credential', b'') or b''
            if not cred:
                continue
            binding = _scenario_zta_binding(self.corpus_root, ident, cred,
                                            str(variant))
            ident.zta_credential_binding = binding
            ident.zta_credentials = [{'der': cred, 'binding': binding,
                                      'issuer': getattr(ident, 'zta_issuer', '')}]

        # Advertised operator-attended claim (ethne D8/Q9): set the announcing
        # identity's operator_bound so the welcoming committee sees the CLAIM on
        # from_whom. The gate always neutralizes it and re-derives the truth from
        # operator-anchor verification — so a `true` claim on a non-operator
        # credential must end up false (operator-bound-lying-rejected). Mirrors
        # the C adapter's operator_claims wiring.
        claim_fix: dict[str, bool] = fixtures.get('operator_claims', {}) or {}
        for pid, want in claim_fix.items():
            if pid in identities:
                identities[pid].operator_bound = bool(want)

        # The OPT-IN guardian identity. `operator_bindings: {<pid>: <variant>}`
        # makes that participant advertise an operator ed25519 key together with
        # a binding signed AT SCENARIO TIME — not a pinned blob — so both
        # implementations must produce and accept the same signature scheme
        # rather than agreeing on one recorded output. Variants:
        #
        #   valid           signed by the leaf whose cert the peer presents
        #   forged          signed by an unrelated key (impostor_leaf.key)
        #   other-identity  correctly signed, but over a pre-image naming a
        #                   DIFFERENT node — the harvested-credential case
        #
        # A participant absent from the map advertises nothing, which is the
        # ordinary opted-out node and must stay indistinguishable from one built
        # before these fields existed.
        bind_fix: dict[str, str] = fixtures.get('operator_bindings', {}) or {}
        for pid, variant in bind_fix.items():
            if pid not in identities:
                continue
            ident = identities[pid]
            op_pub, binding = _scenario_operator_binding(
                self.corpus_root, ident, str(variant))
            ident.operator_pubkey = op_pub
            ident.operator_key_binding = binding

        # ZTA policy (zta-x509-* scenarios): a single policy applied to every
        # participant's IdentityProcess (the border guards consult it at
        # admission). ca_bundle_path resolves against the corpus root. Mirrors
        # the C adapter wiring proc->configs["zta_policy"].
        zta_policy: ZtaPolicy | None = None
        zta_fix = fixtures.get('zta_policy')
        if isinstance(zta_fix, dict):
            spec = dict(zta_fix)
            if spec.get('ca_bundle_path'):
                spec['ca_bundle_path'] = str(self.corpus_root / spec['ca_bundle_path'])
            # crl_path resolves against the corpus root too, so a revocation
            # scenario's CRL is loadable (mirrors the C adapter; without it the
            # verifier reports UNAVAILABLE -> admit and diverges from C's
            # REVOKED). See zta-x509-reject-revoked-credential.
            if spec.get('crl_path'):
                spec['crl_path'] = str(self.corpus_root / spec['crl_path'])
            # Distinct operator trust anchor (ethne D8/Q9): resolves against the
            # corpus root like ca_bundle_path. A credential is operator-class iff
            # it also chain-verifies here. Mirrors the C adapter wiring. See
            # operator-bound-verified.yaml.
            if spec.get('operator_ca_bundle_path'):
                spec['operator_ca_bundle_path'] = str(
                    self.corpus_root / spec['operator_ca_bundle_path'])
            # Named anchors carry their own bundle paths and need the same
            # resolution — easy to miss, and the failure is quiet: an anchor whose
            # bundle will not load verifies nothing, so the peer is simply not
            # admitted and the scenario looks like a policy disagreement rather
            # than a path bug. Mirrors the C adapter.
            if isinstance(spec.get('anchors'), list):
                spec['anchors'] = [
                    dict(a, ca_bundle_path=str(self.corpus_root
                                               / a['ca_bundle_path']))
                    if isinstance(a, dict) and a.get('ca_bundle_path') else a
                    for a in spec['anchors']]
            zta_policy = ZtaPolicy(**spec)

        # Distinct-group mode (partition-recovery scenarios): when
        # `fixtures.groups` is present, every listed participant gets its
        # OWN group with a pinned uuid and a fixed member count, and peers
        # are NOT cross-populated. That is what makes a split-brain
        # reproducible — each peer sees the other's group traffic as
        # foreign. See doc/architecture/partition-recovery.md §9.
        groups_fix: dict[str, Any] = fixtures.get('groups', {}) or {}
        distinct_groups = bool(groups_fix)
        group_by_pid: dict[str, Group] = {}
        if distinct_groups:
            for gi, (pid, spec_g) in enumerate(groups_fix.items()):
                group_by_pid[pid] = self._build_group_from_fixture(
                    pid, gi, identities[pid], spec_g)

        # Shared-group sparse-peers mode (identity-resync scenarios): ONE
        # group shared by every participant — each member's address is in
        # the address_map — but peers are NOT cross-populated. So each
        # participant holds the others' addresses yet not their Identities,
        # which is the cold/late-joiner precondition handle_identity_response
        # backfills. See doc/architecture/partition-recovery.md layer 3. The
        # group uuid is pinned so it is identical across the Python and C
        # harnesses (the resync query/response gate on it).
        shared_fix = fixtures.get('shared_group')
        shared_group_obj: Group | None = None
        if isinstance(shared_fix, dict) or shared_fix is True:
            pids_all = [s['id'] for s in spec_participants]
            seed_id = pids_all[0]
            if isinstance(shared_fix, dict) and shared_fix.get('uuid'):
                guuid = UUID(shared_fix['uuid'])
            else:
                guuid = identities[seed_id].uuid
            shared_group_obj = Group(
                guuid, {identities[seed_id].uuid: identities[seed_id].address},
                'shared-grp', Encryptor.generate(), False)
            for pid in pids_all[1:]:
                shared_group_obj.add_address(identities[pid].uuid,
                                             identities[pid].address)

        # All participants except the newcomer share the same group key in
        # Phase C scenarios. Newcomer is detected as the participant with role
        # `new_node`, mirroring the canonical scenario's role naming.
        newcomer_pid = next(
            (s['id'] for s in spec_participants if s.get('role') == 'new_node'),
            None,
        )
        existing_pids = [s['id'] for s in spec_participants if s['id'] != newcomer_pid]
        group: Group | None = None
        if existing_pids and not distinct_groups:
            seed = identities[existing_pids[0]]
            group = Group(seed.uuid, {seed.uuid: seed.address}, 'conformance-grp',
                          Encryptor.generate(), False)
            for pid in existing_pids[1:]:
                group.add_address(identities[pid].uuid, identities[pid].address)

        # Pre-populate each existing participant's Peers with all OTHER
        # existing participants so the canonical scenario doesn't need an
        # explicit warm-up step. The newcomer's announce is the start.
        # `amnesia_known` opt-in adds the newcomer to existing peers up front,
        # which is what the amnesia scenario asserts on.
        amnesia_known = bool((case.data.get('fixtures') or {}).get('amnesia_known', False))

        handles: dict[str, ParticipantHandle] = {}
        for spec in spec_participants:
            pid = spec['id']
            role = spec['role']
            identity = identities[pid]
            peers = Peers()
            if not distinct_groups and shared_group_obj is None:
                for other_pid in existing_pids:
                    if other_pid == pid:
                        continue
                    peers.add(identities[other_pid])
                if amnesia_known and pid in existing_pids and newcomer_pid is not None:
                    peers.add(identities[newcomer_pid])
            if distinct_groups:
                this_group = group_by_pid.get(pid)
            elif shared_group_obj is not None:
                this_group = shared_group_obj
            else:
                this_group = group
            participant = self._build_one(pid, role, identity, peers, this_group,
                                          zta_policy=zta_policy)
            # Border-guard flag (doc/architecture/identity-protocol.md, Policy B). Optional
            # per-participant `border_guard: false` makes this peer abstain
            # from voting on received proposals; defaults true (set in
            # _build_one) so existing scenarios are unaffected. Mirrors the C
            # adapter's identity_set_border_guard_mode plumbing.
            if 'border_guard' in spec:
                participant.process.border_guard_mode = bool(spec['border_guard'])
            # Two-phase admission quorum. fixtures.admission_quorum is
            # {participant_id: int}; a member withholds the group key until that
            # many distinct border-guards confirm. Default 1 (no fixture) keeps
            # single-confirm admission. Mirrors the C adapter's
            # identity_set_admission_quorum plumbing.
            aq_fix: dict[str, int] = fixtures.get('admission_quorum', {}) or {}
            if pid in aq_fix:
                participant.process._admission_quorum = int(aq_fix[pid])
            # Install own-capability allowlist from fixtures.capabilities;
            # mirrors the C adapter's `identity_set_own_capabilities`
            # plumbing. handle_caps_query reads
            # `self.capabilities.to_list()` and emits it as a JSON-array
            # caps_response payload.
            cap_fix: dict[str, list[str]] = fixtures.get('capabilities', {}) or {}
            for cap_name in cap_fix.get(pid, []):
                participant.process.protocol.capabilities.register_ability(
                    cap_name, None, [], {})
            # Inject N synthetic cap-less peers (fixtures.capless_peers[pid])
            # directly into this participant's roster: present in self.peers but
            # absent from peer_capabilities -- exactly the state the periodic
            # caps-resync sweep targets. caps-resync-max-per-sweep uses this to
            # drive > CAPS_RESYNC_MAX_PER_SWEEP cap-less peers and assert the
            # per-sweep cap. Mirrors the C adapter's capless_peers injection.
            capless_fix: dict[str, int] = fixtures.get('capless_peers', {}) or {}
            for i in range(int(capless_fix.get(pid, 0))):
                syn_pid = f'capless-{pid}-{i}'
                syn = Identity(
                    self._derive_uuid(syn_pid, {}),
                    f'10.90.{i // 256}.{i % 256}', f'{syn_pid}.scenario',
                    Signature(_stretch_seed(syn_pid, b'sig'), public_only=False),
                    Encryptor(_stretch_seed(syn_pid, b'enc'), public_only=False),
                    syn_pid, False, 0, _DEFAULT_BLOCK_IMPL)
                peers.add(syn)
            handles[pid] = ParticipantHandle(
                id=pid, role=role, impl=participant,
                dispatch=lambda msg, p=participant: self._dispatch(p, msg),
            )
        # Registry for the requestor-side subtree-roster walk (uuid -> impl,
        # uuid -> pid); the trigger enumeration routes/labels by these.
        self._handles = handles
        self._roster_by_uuid = {
            str(h.impl.identity.uuid): h.impl for h in handles.values()}
        self._roster_uuid_to_pid = {
            str(h.impl.identity.uuid): pid for pid, h in handles.items()}
        # The reverse map, handed to every participant so an expected_state key
        # can name a peer by participant id even when the store it reads is
        # keyed by uuid (hierarchy_of, peer_tier). The relabel-at-dispatch
        # trick the roster and clock-sample keys use does not work for those:
        # a handler writes them into process state directly, and there is no
        # adapter-side moment that sees both the uuid and the id.
        pid_to_uuid = {pid: str(h.impl.identity.uuid)
                       for pid, h in handles.items()}
        for h in handles.values():
            h.impl.pid_to_uuid = dict(pid_to_uuid)
        # ranks fixture: {pid: int} — the topology rank each participant HAS,
        # applied both to its own identity and to every other node's view of it.
        # Rank is what the hierarchy derivation reads (protocol step 7), so a
        # scenario pinning a parent has to be able to state it. Mirrors the C
        # adapter's ranks handling (identity_set_peer_rank + identity.rank).
        ranks_fix: dict[str, int] = fixtures.get('ranks', {}) or {}
        for pid, rank in ranks_fix.items():
            h = handles.get(pid)
            if h is None:
                raise AssertionError(f'ranks names unknown participant {pid!r}')
            h.impl.identity._rank = int(rank)
            for other in handles.values():
                # The peer_ranks seam, not the peer object: a cohort's
                # membership is an address map, so a member's rank has to be
                # knowable before its Identity is. Same seam C uses.
                other.impl.process.set_peer_rank(h.impl.identity.uuid, rank)
                try:
                    peer = other.impl.process.peers.find_by_uuid(
                        h.impl.identity.uuid)
                except Exception:
                    peer = None
                if peer is not None:
                    peer._rank = int(rank)
        # cohort_tree fixture: seed each gateway's child group + recursion
        # target so a subtree-roster enumeration spans the whole tree.
        self._apply_cohort_tree(handles, fixtures)
        # operator_session fixture: who has a human at the console, and the
        # pinned clock every stamp is taken from.
        self._apply_operator_session(handles, fixtures)
        # clocks fixture: per-participant clocks, so a scenario can pin two
        # nodes that DISAGREE. Applied after operator_session so it overrides
        # that fixture's single shared clock.
        self._apply_clocks(handles, fixtures)
        return handles

    def _apply_clocks(self, handles, fixtures) -> None:
        """Wire the ``clocks`` fixture: ``{<pid>: <epoch>}``.

        ``operator_session.clock`` pins ONE clock for every participant, which
        is all the attended-now scenarios need. Cohort skew is the difference
        BETWEEN two nodes' clocks, so it needs a distinct value per node. With
        constant pinned clocks the round trip's t1 and t4 are both the puller's
        value and t2/t3 are both the target's, so the derived offset is exactly
        the difference and the delay is exactly zero -- a comparison two
        languages can agree on to the bit. C mirrors via
        identity_set_attest_clock per participant.
        """
        clocks_fix = (fixtures or {}).get('clocks', {}) or {}
        for pid, epoch in clocks_fix.items():
            if pid not in handles:
                continue
            impl = handles[pid].impl
            impl.attest_clock = float(epoch)
            impl.process._now_epoch = lambda c=float(epoch): c

    def _apply_operator_session(self, handles, fixtures) -> None:
        """Wire the operator_session fixture (ethne D8/Q9 attended-now).

        ``{<pid>: active|locked|absent, clock: <epoch>}``. Python derives
        attendance by polling a live OperatorSession, so a stub session is
        attached per participant; C has none and asserts the same state through
        identity_set_operator_attended. Same fixture, same resulting answer —
        only the route differs, which is the documented asymmetry.

        The clock is pinned (never wall-clock) so the stamp is a fixed value
        both languages can be compared on.
        """
        session_fix = (fixtures or {}).get('operator_session', {}) or {}
        if not session_fix:
            return
        clock = float(session_fix.get('clock', 0.0) or 0.0)
        for pid, state in session_fix.items():
            if pid == 'clock' or pid not in handles:
                continue
            impl = handles[pid].impl
            impl.attest_clock = clock
            if clock:
                # Deterministic stamp: bind the process clock seam to it.
                impl.process._now_epoch = lambda c=clock: c
            if str(state) == 'absent':
                continue  # a node with no console attached at all
            impl.process.set_operator_session(
                _StubOperatorSession(str(state) == 'active'))

    def _load_keys(self, pid: str, keys_fix: dict[str, Any]) -> tuple[bytes, bytes]:
        """Resolve the (sig_seed, enc_seed) hex pair for a participant.

        Falls back to deterministic per-id seeds (a 32-byte stretch derived
        from the participant id) so authors don't have to provide key files
        for every scenario.
        """
        spec = keys_fix.get(pid)
        if isinstance(spec, dict):
            sig_path = self.corpus_root / spec['signature']
            enc_path = self.corpus_root / spec['encryption']
            return _read_hex_seed(sig_path), _read_hex_seed(enc_path)
        if isinstance(spec, str):
            sig_path = self.corpus_root / spec
            seed = _read_hex_seed(sig_path)
            return seed, _stretch_seed(pid, b'enc')
        return _stretch_seed(pid, b'sig'), _stretch_seed(pid, b'enc')

    def _derive_uuid(self, pid: str, uuid_fix: dict[str, Any]) -> UUID:
        if pid in uuid_fix:
            return UUID(uuid_fix[pid])
        # Deterministic UUID5 in a fixed namespace, so amnesia scenarios that
        # match by uuid keep matching across runs.
        ns = UUID('00000000-0000-0000-0000-000000000aaa')
        from uuid import uuid5
        return uuid5(ns, f'at-conformance:{pid}')

    def _build_group_from_fixture(self, pid: str, group_index: int,
                                  identity: Identity,
                                  spec: dict[str, Any]) -> Group:
        """Build a distinct Group for a partition-recovery participant.

        `spec` is `fixtures.groups[pid]` — `{uuid: <str>, size: <int>}`.
        The group is seeded with the participant's own (uuid -> address)
        and padded with `size - 1` synthetic filler members so
        `len(group.addresses) == size`, which is the value the partition
        handlers sign and compare. The group uuid is pinned so the
        equal-size uuid tiebreak in `handle_partition_response` is
        deterministic (and identical to the C harness, which pins the
        same string). Filler addresses must be distinct — `add_address`
        dedups by address.
        """
        from uuid import uuid5
        group_uuid = UUID(spec['uuid']) if spec.get('uuid') else identity.uuid
        size = int(spec.get('size', 1))
        # `public_only: true` builds a group holding ONLY the public key — the
        # wire shape of a membership-only group_key_update from a peer that does
        # not hold the shared private key (or one survived a protobuf
        # round-trip). Lets a scenario drive the "adopt larger membership but
        # KEEP our private key" path. See [[dod-microdrone-targets-live-vs-playback]].
        public_only = bool(spec.get('public_only', False))
        enc = Encryptor.generate()
        if public_only:
            enc = Encryptor(enc.publish(), public_only=True)
        grp = Group(group_uuid, {identity.uuid: identity.address},
                    f'grp-{pid}', enc, public_only)
        ns = UUID('00000000-0000-0000-0000-000000000aaa')
        for k in range(max(0, size - 1)):
            # str() the filler uuid: address-map keys must be strings (matches
            # production and the C harness). A UUID-object key breaks JSON
            # serialization once the group is put on the wire via to_canonical
            # (e.g. group_key_update), which earlier partition scenarios never
            # exercised (probes serialize only uuid+size, not the address map).
            filler_uuid = str(uuid5(ns, f'at-conformance-fill:{pid}:{k}'))
            filler_addr = f'10.9.{group_index}.{k + 2}'
            grp.add_address(filler_uuid, filler_addr)
        return grp

    def _apply_cohort_tree(self, handles: dict[str, ParticipantHandle],
                           fixtures: dict[str, Any]) -> None:
        """Seed a gateway hierarchy from the `cohort_tree` fixture so a
        subtree-roster enumeration spans multiple levels.

        `cohort_tree.nodes.<pid>` may carry: `child_group` (participant ids
        that make up the cohort this node gateways), `gateway` (which of them
        is the deeper gateway to recurse into), and `members` (extra
        primary-group members). Each named id must be a participant. Mirrors
        the C adapter's cohort_tree handling in _apply_fixtures.
        """
        tree = fixtures.get('cohort_tree')
        if not isinstance(tree, dict):
            return
        nodes = tree.get('nodes', {}) or {}
        from uuid import uuid5

        def _impl(name: str):
            h = handles.get(name)
            if h is None:
                raise AssertionError(
                    f'cohort_tree references unknown participant {name!r}')
            return h.impl

        for pid, spec in nodes.items():
            me = _impl(pid)
            proc = me.process
            # Primary group = self + any extra members.
            grp = Group(me.identity.uuid,
                        {me.identity.uuid: me.identity.address},
                        f'grp-{pid}', Encryptor.generate(), False)
            for m_pid in (spec.get('members') or []):
                m = _impl(m_pid)
                grp.add_address(m.identity.uuid, m.identity.address)
            proc.group = grp
            # A child cohort this node gateways + the recursion target.
            child_members = spec.get('child_group') or []
            if child_members:
                cg_uuid = str(uuid5(
                    UUID('00000000-0000-0000-0000-000000000aaa'),
                    f'at-conformance-cg:{pid}'))
                cgrp = Group(UUID(cg_uuid), {}, f'cg-{pid}',
                             Encryptor.generate(), False)
                for m_pid in child_members:
                    m = _impl(m_pid)
                    cgrp.add_address(m.identity.uuid, m.identity.address)
                proc.child_groups[cg_uuid] = cgrp
                gw_pid = spec.get('gateway')
                if gw_pid is not None:
                    proc.child_gateways[cg_uuid] = str(_impl(gw_pid).identity.uuid)

    def _build_one(self, pid: str, role: str, identity: Identity,
                   peers: Peers, group: Group | None,
                   zta_policy: ZtaPolicy | None = None) -> _Participant:
        net_sink: list[Any] = []
        main_sink: list[Any] = []
        neg_sink: list[Any] = []
        proc_sink: list[Any] = []

        queues = {
            CfgIds.identity: _CapturingQueue(proc_sink, CfgIds.identity),
            CfgIds.network: _CapturingQueue(net_sink, CfgIds.network),
            CfgIds.main: _CapturingQueue(main_sink, CfgIds.main),
            CfgIds.negotiation: _CapturingQueue(neg_sink, CfgIds.negotiation),
        }

        configurations = {
            CfgIds.identity: identity,
            CfgIds.peers: peers,
            CfgIds.capabilities: PeerCapabilities(),
            PackageHash.key: self._package_hash,
            'processes': [_FakeDep(CfgIds.network)],
        }
        # ZTA admission policy (zta-x509-* scenarios). IdentityProcess._zta_policy
        # reads configs[ZtaPolicy.CONFIG_KEY]; mirrors the C proc->configs entry.
        if zta_policy is not None:
            configurations[ZtaPolicy.CONFIG_KEY] = zta_policy

        process = IdentityProcess(
            configurations,
            ProcessTracker(),
            log_q=queue.Queue(),
            suppress_log=True,
        )
        process.synchronous_dispatch = True

        # Capability registry needs at least one capability or
        # acquire_capabilities() loops; we don't run that path, but
        # vote-collection paths need self.capabilities to exist.
        process.protocol.capabilities = Capabilities()

        # Move past the init phases. Existing peers run as border guards
        # in phase 3; the newcomer remains in phase 1 so handle_acceptance
        # gates work (handle_acceptance requires phase >= 2 actually; we set
        # newcomer to phase 2 so it can receive an `accept` message).
        if role == 'new_node':
            process.phase = 2
        else:
            process.phase = 3
        process.border_guard_mode = True
        process.group = group

        # Lock is initialized at process()-loop start in production; tests
        # need it earlier. A real RLock keeps re-entrant access from the
        # synchronous _vote_collection -> _peer_accepted call chain.
        import threading as _t
        process.lock = _t.RLock()

        # Hook the network queue: every put becomes a record AND a delivery
        # candidate. The engine pulls outbound messages via drain_outbox.
        captured = _Participant(
            id=pid, role=role, identity=identity, process=process,
            queues=queues,
        )

        original_put = queues[CfgIds.network].put

        def _record_and_put(item, *args, **kwargs):
            if isinstance(item, Message):
                captured.outbox_buffer.append(item)
                captured.emit_tally[item.function] = \
                    captured.emit_tally.get(item.function, 0) + 1
            original_put(item, *args, **kwargs)

        queues[CfgIds.network].put = _record_and_put  # type: ignore[method-assign]

        return captured

    # ------------------------------------------------------------------
    # Step driver
    # ------------------------------------------------------------------

    def _run_attest_pull(self, puller: _Participant, target: _Participant,
                         replay: bool) -> None:
        """One attended-now pull, end to end, inside the harness.

        Python's responder cannot answer alone: handle_attest_request asks the
        main loop, because only the main loop shares an address space with the
        console's OperatorSession. There is no main loop here, so this stands
        in for one — deriving attendance from the stub session exactly as
        AutonomousTrust._operator_attended does (via the shared is_attended)
        and feeding the answer back in. What is compared afterwards is the
        outcome, which C reaches in one hop from its seam.

        On ``replay`` the previous answer is re-presented instead of a fresh
        pull: same nonce, already retired, and it must be refused.
        """
        from autonomous_trust.core.operator.session import is_attended

        if replay:
            answer = dict(puller.attest_last_answer)
            if not answer:
                raise AssertionError('attest replay: no prior answer to replay')
        else:
            # Deterministic per-pull nonce (production mints a random one).
            # Nothing compares the nonce itself — only that the state machine
            # binds an answer to the pull that asked for it — and a fixed value
            # keeps the two runs identical.
            nonce = '%s-%d' % (puller.id, len(puller.attest_accepted))
            # Third element is the round trip's t1 -- the puller's own clock at
            # send. Production records it in handle_attest_trigger; here the
            # pull is injected, so the harness must supply it or no clock sample
            # can be measured (cohort-clock-skew.md).
            puller.process._attest_sent[nonce] = (
                str(target.identity.uuid),
                (puller.attest_clock or 0.0) + 10.0,
                puller.attest_clock or 0.0)
            # The target answers. Its own session state decides the stamp, and
            # its own clock supplies both of the readings it reports.
            session = getattr(target.process, '_operator_session', None)
            attended = bool(session is not None and is_attended(session))
            epoch = target.attest_clock if attended else 0.0
            answer = target.process._attest_payload(nonce, epoch,
                                                    target.attest_clock or 0.0)
            puller.attest_last_answer = dict(answer)

        before = dict(puller.process._attest_sent)
        msg = Message(CfgIds.identity, IdentityProtocol.attest_resp,
                      to_json_string(answer),
                      from_whom=target.identity)
        puller.process.handle_attest_response(puller.queues, msg)
        # Accepted iff the answer consumed an outstanding pull; a replayed or
        # unsolicited answer matches nothing and leaves the table untouched.
        accepted = len(puller.process._attest_sent) < len(before)
        puller.attest_accepted.append(accepted)
        if accepted:
            puller.attest_stamp = float(answer.get('operator_attested_at') or 0.0)
        # Relabel whatever the handler measured for this peer under the target's
        # participant id. Absent (no readings in the answer) records nothing, so
        # a scenario asserting on it fails loudly rather than reading a stale one.
        sample = puller.process._peer_clock_samples.get(str(target.identity.uuid))
        if sample is not None:
            puller.attest_clock_samples[target.id] = sample

    def _dispatch(self, participant: _Participant, inbound: Any) -> list[CapturedMessage]:
        if not isinstance(inbound, Message):
            raise AssertionError(f'expected a Message, got {type(inbound).__name__}')
        if inbound.function == _TRIGGER_CAPS_RESYNC:
            # Pseudo-function: invoke the periodic caps-resync sweep directly
            # (it is timer-gated in production, so there is no wire message to
            # dispatch). The emitted caps_query messages are captured in
            # emit_tally; caps_query_emitted asserts the per-sweep cap.
            participant.process._periodic_caps_resync(participant.queues)
            return participant.drain_outbox()
        if inbound.function in (_TRIGGER_ATTEST_PULL, _TRIGGER_ATTEST_REPLAY):
            # `participant` is the pull TARGET; from_whom is the puller.
            puller = self._roster_by_uuid.get(str(inbound.from_whom.uuid))
            if puller is None:
                raise AssertionError('attest pull: unknown puller')
            self._run_attest_pull(
                puller, participant,
                replay=(inbound.function == _TRIGGER_ATTEST_REPLAY))
            return participant.drain_outbox()
        if inbound.function == _TRIGGER_COHORT_JOIN:
            target = ''
            if inbound.obj:
                target = str(from_json_string(inbound.obj).get('group_uuid', ''))
            participant.process.request_cohort_join(participant.queues, target)
            return participant.drain_outbox()
        if inbound.function == _TRIGGER_HIERARCHY:
            participant.process._refresh_hierarchy(participant.queues)
            uuid = participant.process.parent_gateway
            participant.parent_gateway_pid = (
                self._roster_uuid_to_pid.get(str(uuid), str(uuid))
                if uuid else '')
            return participant.drain_outbox()
        if inbound.function == _TRIGGER_FC_INITIATE:
            # `participant` is the INITIATOR. Mint the ticket from the
            # participant the step names, then let the production call decide
            # what to send and where -- the point is the decision, not the
            # bytes the harness could have assembled itself.
            from autonomous_trust.core.contacts import create_invitation
            from autonomous_trust.core.identity import first_contact as _fc
            spec = from_json_string(inbound.obj) if inbound.obj else {}
            minter_pid = str(spec.get('minted_by'))
            minter_uuid = participant._uuid_for_pid(minter_pid)
            minter = self._roster_by_uuid[str(minter_uuid)].identity
            blob = create_invitation(
                minter,
                rendezvous=list(spec.get('rendezvous') or []),
                expiry=int(spec.get('expiry', 0) or 0),
                ttl_seconds=0,
                nonce=str(spec.get('nonce', '')),
            ).encode()
            _fc.initiate(participant.process, participant.queues, blob)
            emitted = participant.drain_outbox()
            for cm in emitted:
                if cm.function == IdentityProtocol.hello:
                    to_whom = cm.raw.to_whom
                    target = to_whom[0] if isinstance(to_whom, list) else to_whom
                    participant.fc_hello_endpoint = str(
                        getattr(target, 'address', '') or '')
            return emitted
        if inbound.function == _TRIGGER_FC_RESTART:
            # Forget the in-memory spent-nonce guard, keep the file: a fresh
            # SpentNonces re-reads <data_dir>/first_contact_nonces.cfg.json,
            # which is exactly what a restarted node does. C mirrors with
            # at_first_contact_reset().
            from autonomous_trust.core.identity import first_contact as _fc
            participant.process._first_contact_nonces = _fc.SpentNonces()
            return participant.drain_outbox()
        if inbound.function == _TRIGGER_SUBTREE_ROSTER:
            # Pseudo-function: run the requestor-side subtree-roster walk on
            # this participant. fetch asks each gateway (by uuid) for its
            # roster response via the SAME helper the wire handler uses, so
            # the enumeration is faithful. The flattened member uuids are
            # mapped back to participant ids and stored for the check.
            from autonomous_trust.core.identity.idprocess import (
                aggregate_subtree_roster)

            def _fetch(gw_uuid):
                impl = self._roster_by_uuid.get(str(gw_uuid))
                return impl.process._roster_response() if impl is not None else None

            top_uuid = str(participant.identity.uuid)
            members, _complete, _private = aggregate_subtree_roster(top_uuid, _fetch)
            ids = [self._roster_uuid_to_pid[str(m['uuid'])]
                   for m in members if str(m.get('uuid')) in self._roster_uuid_to_pid]
            participant.subtree_roster = sorted(ids)
            return participant.drain_outbox()
        # The protocol's handler dispatch is run synchronously. Threads
        # spawned via _spawn() are inlined because synchronous_dispatch is on.
        participant.process.protocol.run_message_handlers(participant.queues, inbound)
        # A propose handler (_process_id) only queues the approval vote in
        # confirmed_block; the actual vote_on_peer message is sent by the
        # separate vote_response phase-3 task. Drive one cycle here so the
        # deferred vote is captured in the same step — C sends in-handler, so
        # this is what makes votes_emitted symmetric across the two impls.
        if inbound.function == IdentityProtocol.propose:
            participant.process.vote_response(participant.queues)
        # Same reason, one seam further out: the attest responder cannot answer
        # inline either. handle_attest_request parks the pull and asks the MAIN
        # loop, because only the main loop shares an address space with the
        # console's OperatorSession; handle_operator_state_response is what
        # finally emits the attestation. C reaches the answer in one hop from
        # its own seam, so without a main loop here the Python responder half
        # never runs at all and the two runtimes are compared on nothing.
        if inbound.function == IdentityProtocol.attest_req:
            self._answer_operator_state_query(participant)
        return participant.drain_outbox()

    def _answer_operator_state_query(self, participant: _Participant) -> None:
        """Stand in for the main loop's `_answer_operator_state`.

        Consumes whatever operator_state_query the identity process just put on
        its main queue and feeds back the reply that loop would send, deriving
        attendance from the stub session through the SAME `is_attended` the
        production loop uses -- so the two processes cannot drift apart here any
        more than they can in the real node. The epoch is the participant's
        fixture clock rather than `time.time()`: production stamps wall clock,
        and a scenario has to be reproducible.
        """
        from autonomous_trust.core.operator.session import is_attended

        sink = participant.queues[CfgIds.main]._sink
        queries = [m for m in sink
                   if isinstance(m, Message)
                   and m.function == IdentityProtocol.operator_state_req]
        if not queries:
            return
        for m in queries:
            sink.remove(m)
        session = getattr(participant.process, '_operator_session', None)
        attended = bool(session is not None and is_attended(session))
        # One answer serves every pull in flight -- they all asked the same
        # question of the same session -- which is exactly what the handler
        # assumes when it drains the whole pending table.
        reply = Message(CfgIds.identity, IdentityProtocol.operator_state_resp,
                        to_json_string({
                            'attended': attended,
                            'epoch': (participant.attest_clock or 0.0) if attended else 0.0,
                            'have_session': session is not None,
                        }),
                        from_whom=participant.identity)
        participant.process.handle_operator_state_response(participant.queues,
                                                           reply)

    # ------------------------------------------------------------------
    # Inbound construction
    # ------------------------------------------------------------------

    def _build_inbound(self, participants: dict[str, ParticipantHandle], *,
                       from_id: str, to_id: str, function: str, payload: dict[str, Any]) -> Message:
        sender = participants[from_id].impl  # _Participant
        sender_identity = sender.identity

        # Translate the high-level YAML payload into the form the protocol
        # expects on the wire. Each function gets its own constructor.
        if function == IdentityProtocol.announce:
            # DRY request_access contract: identity rides the envelope from_*
            # fields (set via from_whom on the Message below — the canonical
            # cross-runtime sender representation); the payload carries only
            # [package_hash, capabilities_list]. Mirrors
            # idprocess._broadcast_request_access and the C _build_announcement.
            caps_list = payload.get('capabilities', [])
            obj = to_json_string((self._package_hash, caps_list))
        elif function == IdentityProtocol.accept:
            caps_list = payload.get('capabilities', [])
            obj = to_json_string((sender_identity.publish(),
                                  self._package_hash, caps_list))
        elif function == IdentityProtocol.confirm:
            target_pid = payload.get('peer') or payload.get('candidate')
            target = participants[target_pid].impl.identity
            from autonomous_trust.core.identity.history import IdentityObj
            blob = IdentityObj(target.publish(), target.uuid)
            # Envelope carrying the confirmer's freshness sequence beside the
            # identity blob. `unstamped: true` omits it, modelling a
            # pre-change sender or a stripped field; both runtimes must refuse
            # that rather than fall back to a lenient path.
            body = {'peer': blob.to_string()}
            if not payload.get('unstamped'):
                body['seq'] = int(payload.get('seq', 1))
            obj = to_json_string(body)
        elif function == IdentityProtocol.propose:
            # A peer proposal for voting. `handle_vote_on_peer` reads
            # message.obj as the candidate's IdentityObj (Configuration
            # string), exactly as welcoming_committee emits it
            # (id_obj.to_string()). The candidate is named by participant id.
            target_pid = (payload.get('candidate') or payload.get('peer')) \
                if isinstance(payload, dict) else None
            if target_pid is None:
                # No candidate named — older scenarios inject a propose only
                # to exercise the dispatch path. Preserve the historical
                # passthrough so handle_vote_on_peer no-ops on the empty blob.
                obj = to_json_string(payload)
            else:
                target = participants[target_pid].impl.identity
                from autonomous_trust.core.identity.history import IdentityObj
                blob = IdentityObj(target.publish(), target.uuid)
                obj = blob.to_string()
        elif function == IdentityProtocol.update:
            # Emit the DRY canonical flat group (matches production
            # _update_group + C's group_to_json) so the wire form the harness
            # exercises is the cross-runtime one. handle_group_update parses it
            # via Group.from_canonical. See [[project_group_key_sync]].
            target_group = sender.process.group
            obj = to_json_string(target_group.to_canonical()) if target_group else ''
        elif function == IdentityProtocol.hierarchy_req:
            # A late joiner asking the group to state their positions
            # (protocol step 7). The handler answers from its own claim and
            # reads nothing out of the payload, so the requestor field is
            # informational -- carried anyway, because it is what production
            # sends (_request_hierarchy) and a scenario should exercise the
            # bytes the wire actually has.
            obj = to_json_string({'requestor': str(sender_identity.uuid)})
        elif function == IdentityProtocol.hierarchy:
            # A node's claim about ITS OWN place in the tree. `node` is the
            # sender by construction: handle_hierarchy refuses a claim naming
            # anybody else, and `payload.claims` lets a scenario name another
            # participant deliberately to exercise that refusal.
            #
            # `children` are the GROUP uuids of the cohorts the sender
            # gateways (idprocess._hierarchy_claim reads self.child_groups),
            # not peer uuids -- so a scenario gives a count-shaped list and
            # the adapter mints stable uuid5s for it. That keeps the fixture
            # from having to know a group uuid it never created.
            claimant = payload.get('claims')
            node = (str(participants[claimant].impl.identity.uuid)
                    if claimant else str(sender_identity.uuid))
            parent_pid = payload.get('parent')
            n_children = int(payload.get('children', 0) or 0)
            children = [str(uuid5(_HIER_NS, f'{node}:cohort:{i}'))
                        for i in range(n_children)]
            body = {
                'node':     node,
                'parent':   (str(participants[parent_pid].impl.identity.uuid)
                             if parent_pid else ''),
                'children': children,
                'rank':     int(payload.get('rank', 0) or 0),
            }
            # `unstamped: true` omits the freshness sequence, modelling a
            # replayable claim; both runtimes must refuse it rather than
            # record it, because this dict is what child-gateway discovery
            # recurses into.
            if not payload.get('unstamped'):
                body['seq'] = int(payload.get('seq', 1))
            obj = to_json_string(body)
        elif function == IdentityProtocol.hello:
            # The OPTIONAL 1:1 handshake's ticket. The scenario names WHO minted
            # the invitation (`minted_by`) plus the nonce and expiry, and the
            # adapter mints it here from that participant's own signable
            # identity -- rather than pinning a blob in the fixture -- because
            # the participants' keys are generated per run. ed25519 signing is
            # deterministic, so both runtimes mint the same bytes from the same
            # seed anyway; what the case compares is the inviter's DECISION.
            #
            # The obj is the raw base64url blob, exactly as production sends it
            # (first_contact.initiate forwards the link untouched, and the
            # signature covers those bytes).
            from autonomous_trust.core.contacts import create_invitation
            minter_pid = payload.get('minted_by') or from_id
            minter = participants[minter_pid].impl.identity
            obj = create_invitation(
                minter,
                rendezvous=list(payload.get('rendezvous') or []),
                expiry=int(payload.get('expiry', 0) or 0),
                ttl_seconds=0,
                nonce=str(payload.get('nonce', '')),
            ).encode()
        elif function == IdentityProtocol.hello_ack:
            # The accept. The echoed nonce is informational -- what makes the
            # ack trustworthy is that the initiator already holds the
            # accepter's key from the invitation it redeemed -- so the handler
            # reads no further, on either runtime.
            obj = to_json_string({'nonce': str(payload.get('nonce', ''))})
        elif function == IdentityProtocol.roster_req:
            # Subtree-roster query. `requesting_process` is load-bearing: the
            # answer is addressed to the process the requestor names, and the
            # aggregation that consumes it lives in the main loop, not here.
            obj = to_json_string({
                'requestor': str(sender_identity.uuid),
                'requesting_process': payload.get('proc', CfgIds.main),
            })
        elif function == IdentityProtocol.attest_req:
            # Attended-now pull, as it arrives on the wire. The nonce is what
            # binds an answer to the request that asked for it, so it is
            # spelled out by the scenario rather than minted here; omitting it
            # (`no_nonce`) is a distinct case, because an unnonced attestation
            # is replayable forever and must be refused rather than answered.
            body = {}
            if not payload.get('no_nonce'):
                body['nonce'] = str(payload.get('nonce', 'n1'))
            obj = to_json_string(body)
        elif function == IdentityProtocol.tier_update:
            # Local IPC from the reputation process, not a wire message: the
            # payload is the (peer_uuid, tier) pair _publish_tier_change
            # emits. `peer` names a participant; `unknown_peer` sends a uuid
            # for nobody, which both runtimes must drop quietly rather than
            # apply to somebody.
            target_pid = payload.get('peer')
            if payload.get('unknown_peer'):
                target_uuid = str(uuid5(_HIER_NS, 'tier:nobody'))
            elif target_pid:
                target_uuid = str(participants[target_pid].impl.identity.uuid)
            else:
                target_uuid = str(sender_identity.uuid)
            obj = to_json_string((target_uuid, int(payload.get('tier', 0))))
        elif function == IdentityProtocol.diff:
            obj = to_json_string([])
        elif function == IdentityProtocol.history:
            grp = sender.process.group
            steps = sender.process._history.recite() if grp else []
            obj = to_json_string((grp, steps))
        elif function == IdentityProtocol.vote:
            # `count_vote` expects `(blob, proof, (msg, sig))`. The
            # production wire flow is consistent — `Identity.sign`
            # and `Identity.verify` both use HexEncoder, and the
            # JSON encoder round-trips bytes via base64 — so the
            # on-wire path works correctly. Here we deliver the tuple
            # in-memory; `Identity.verify` calls NaCl with HexEncoder
            # which decodes the bytes as hex, so the SignedMessage
            # input must be hex-ASCII. 128 '0' chars decodes to 64
            # zero bytes (correct NaCl sig length, corrupt content),
            # so `verify` raises BadSignatureError, caught by
            # count_vote.
            obj = ({}, '', (b'', b'0' * 128))
        elif function == IdentityProtocol.caps_query:
            # Python's handle_caps_query reads no payload — it just emits
            # a caps_response back. Send an empty string so message.obj
            # is something parseable but unused.
            obj = ''
        elif function == IdentityProtocol.caps_response:
            # handle_caps_response parses an envelope {caps: [...], seq: N}
            # whose items are either bare capability names (legacy) or
            # descriptor objects {name, required_tier, description, kind,
            # arg_schema}. `caps` -> names; `descriptors` -> objects.
            # `seq` is the responder's freshness sequence; `unstamped: true`
            # omits it, modelling a pre-change sender or a stripped field,
            # which must be refused rather than accepted leniently.
            if isinstance(payload, dict) and payload.get('descriptors'):
                items = payload['descriptors']
            else:
                items = payload.get('caps', []) if isinstance(payload, dict) else []
            body = {'caps': items}
            if not (isinstance(payload, dict) and payload.get('unstamped')):
                seq = int(payload.get('seq', 1)) if isinstance(payload, dict) else 1
                body['seq'] = seq
            obj = to_json_string(body)
        elif function == IdentityProtocol.id_query:
            # Identity-resync query (layer 3): {group_uuid, have:[uuids]}.
            # The group_uuid is the asker's group (== the responder's in a
            # shared-group scenario); handle_identity_query gates on that
            # match and on the asker's uuid being absent from `have`.
            have = payload.get('have', []) if isinstance(payload, dict) else []
            grp = sender.process.group
            group_uuid = str(grp.uuid) if grp is not None \
                else '00000000-0000-0000-0000-000000000000'
            obj = to_json_string({'group_uuid': group_uuid, 'have': have})
        elif function == IdentityProtocol.id_response:
            # Identity-resync response: the responder's published identity +
            # address. handle_identity_response gates on `from_address` being
            # in the recipient's group addresses, then adds it to peers.
            obj = to_json_string({'from_identity': sender_identity.publish(),
                                  'from_address': sender_identity.address})
        elif function == IdentityProtocol.partition_signal:
            # Local-only IPC from NetProcess: the payload is the raw
            # from_addr string of the rejected cross-group message.
            # See doc/architecture/partition-recovery.md §5.1.
            from_addr = payload.get('from_addr', 'mock-addr:0') \
                if isinstance(payload, dict) else 'mock-addr:0'
            obj = from_addr
        elif function == IdentityProtocol.partition_probe:
            # Cross-group probe: structured JSON payload (see).
            # For conformance the harness builds a self-consistent
            # payload signed by the sender; the receiver verifies and
            # emits a partition_response.
            from nacl.encoding import HexEncoder
            group_uuid = payload.get('group_uuid', '00000000-0000-0000-0000-000000000000')
            group_size = int(payload.get('group_size', 1))
            # `seq` is the prober's freshness sequence and is part of the
            # SIGNED bytes. Defaults to 1 so existing single-probe scenarios
            # are unchanged; `unstamped: true` drops the field, which is
            # `group-partition-probe-unstamped-refused`.
            #
            # A probe-replay scenario delivers the same seq twice (via the
            # engine's `repeat`), which the mark refuses -- but the per-sender
            # response cooldown suppresses the second reply on its own, so an
            # emission count cannot tell the two mechanisms apart. That case,
            # `group-partition-probe-replay-refused`, asserts the
            # `freshness_refusals` observable instead, which only the mark can
            # move. The unit twins get the same isolation by clearing the
            # cooldown: `test_replayed_probe_refused` and
            # `test_replayed_response_refused_within_round` in
            # tests/a_unit/test_partition_recovery.py.
            seq = int(payload.get('seq', 1))
            from autonomous_trust.core.identity.idprocess import IdentityProcess
            canon = IdentityProcess._partition_probe_canonical(
                group_uuid, group_size, seq)
            signed = sender_identity.sign(canon)
            probe_body = {
                'from_identity':   sender_identity.publish(),
                'from_address':    sender_identity.address,
                'my_group_uuid':   group_uuid,
                'my_group_size':   group_size,
                'seq':             seq,
                'signature':       signed.signature.decode('ascii'),
            }
            # `unstamped: true` models a sender from before the freshness
            # change (or an attacker stripping the field): the seq is omitted
            # entirely. Both runtimes must REFUSE it rather than fall back to
            # a lenient path — see doc/architecture/reputation.md, "Quorum
            # attestation", for why there is no lenient mode.
            if payload.get('unstamped'):
                probe_body.pop('seq')
            obj = to_json_string(probe_body)
        elif function == IdentityProtocol.partition_response:
            from autonomous_trust.core.identity.idprocess import IdentityProcess
            group_uuid = payload.get('group_uuid', '00000000-0000-0000-0000-000000000000')
            group_size = int(payload.get('group_size', 1))
            in_response_to = payload.get('in_response_to', '00000000-0000-0000-0000-000000000000')
            # `in_response_to_id` names the PROBING participant instead of
            # hard-coding its uuid, which is runtime-derived and differs
            # between the two harnesses. Only a source-step response needs it:
            # an assertion step re-delivers the captured response, whose
            # `in_response_to` the real handler already filled in. C resolves
            # the same key the same way (its engine rebuilds every step from
            # the payload, so it needs it on assertion steps too).
            in_resp_pid = payload.get('in_response_to_id')
            if in_resp_pid is not None:
                in_response_to = str(participants[in_resp_pid].impl.identity.uuid)
            # `probe_seq` names the probe round being answered; the receiver
            # refuses an echo that does not match the probe it is currently
            # running. `seq` is the responder's own sequence.
            probe_seq = int(payload.get('probe_seq', 1))
            seq = int(payload.get('seq', 1))
            canon = IdentityProcess._partition_response_canonical(
                group_uuid, group_size, in_response_to, probe_seq, seq)
            signed = sender_identity.sign(canon)
            obj = to_json_string({
                'from_identity':           sender_identity.publish(),
                'from_address':            sender_identity.address,
                'in_response_to':          in_response_to,
                'in_response_to_seq':      probe_seq,
                'my_group_uuid':           group_uuid,
                'my_group_size':           group_size,
                'my_group_leader':         payload.get('leader_uuid', '00000000-0000-0000-0000-000000000000'),
                'my_group_leader_address': payload.get('leader_address', sender_identity.address),
                'seq':                     seq,
                'signature':               signed.signature.decode('ascii'),
            })
        else:
            obj = to_json_string(payload)

        if function in (_TRIGGER_CAPS_RESYNC, _TRIGGER_SUBTREE_ROSTER,
                        _TRIGGER_ATTEST_PULL, _TRIGGER_ATTEST_REPLAY,
                        _TRIGGER_HIERARCHY):
            # Pseudo-function: no wire payload; _dispatch invokes the sweep /
            # roster enumeration directly instead of a handler.
            obj = ''

        msg = Message(CfgIds.identity, function, obj,
                      from_whom=sender_identity,
                      to_whom=Network.broadcast if to_id == 'broadcast' else None,
                      encrypt=(function != IdentityProtocol.announce))
        return msg


class _StubOperatorSession:
    """Minimal stand-in for a live OperatorSession (ethne D8/Q9).

    The real session is built by the console app against PIV/MFA hardware,
    which no test rig has. What the attested-now path actually consumes is a
    two-valued answer — ACTIVE and not due for re-verification, or not — so
    that is what this provides. C has no session type at all and asserts the
    same state through identity_set_operator_attended.
    """

    def __init__(self, active: bool):
        from autonomous_trust.core.operator.session import SessionState
        self.state = SessionState.ACTIVE if active else SessionState.LOCKED

    def poll(self):
        return self.state

    def needs_reverify(self) -> bool:
        return False


@dataclass
class _FakeDep:
    name: str


def _read_hex_seed(path: Path) -> bytes:
    """Read a 32-byte seed from a key file (hex, optional 0x prefix, trailing ws)."""
    raw = path.read_text(encoding='utf-8').strip()
    if raw.startswith('0x'):
        raw = raw[2:]
    if len(raw) != 64:
        raise AssertionError(f'expected 32-byte hex seed in {path}, got {len(raw)//2} bytes')
    return raw.encode('ascii')


def _stretch_seed(pid: str, role: bytes) -> bytes:
    """Deterministic 32-byte (hex-encoded, 64-char) seed from a participant id.

    Used when a scenario doesn't pin keys explicitly; produces stable seeds
    so re-runs yield identical Identity instances.
    """
    import hashlib
    digest = hashlib.sha256(b'at-conformance:' + role + b':' + pid.encode('utf-8')).hexdigest()
    return digest.encode('ascii')
