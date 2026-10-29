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

"""Reputation-protocol adapter for the AT conformance corpus (Phase F).

Drives `kind: scenario` for `protocol: reputation`. Builds real
ReputationProcess instances and turns on synchronous_dispatch so the
threaded paths (handle_reputation_request -> _compute_reputation) execute
inline.

Every group places its order (doc/architecture/reputation.md, "Agreeing on an
order"): a half is co-signed (transaction / tx accepted / tx committed) and
placement decides where it goes in the chain.
"""

from __future__ import annotations

import hashlib
import math
import os
import queue
import tempfile
import threading
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from autonomous_trust.core.capabilities import PeerCapabilities
from autonomous_trust.core.config import Configuration, to_json_string
from autonomous_trust.core.reputation.reputation import (
    RESOLVE_TTL_DEFAULT, PeerReputation, resolve_query_to_dict,
    resolved_to_dict, Transaction, attest_task_id, AttestedScore,
    SignedAttestation, commit_designation, half_designation)
from autonomous_trust.core._python.identity.identity import (
    public_identity_to_canonical)
from autonomous_trust.core.identity import Group, Identity, Peers
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import (
    TransactionScore, SlashAttestation, SignedSlash,
    Checkpoint, SignedCheckpoint, evidence_to_dict, place_designation,
    place_value_digest, placement_entry, score_to_milli)
from autonomous_trust.core.reputation.placement import entry_to_dict
from autonomous_trust.core.reputation.reputation import TransactionHistory
from autonomous_trust.core.system import CfgIds, PackageHash
from autonomous_trust.core._python.identity.join_policy import (
    INERT as INERT_JOIN_POLICY, parse_join_policy)
from autonomous_trust.core._python.identity.peer_standing import (
    PeerStanding, STANDING_CAPPED)

from ...common.scenario_loader import Case
from ..scenario_engine import (
    CapturedMessage,
    ParticipantHandle,
    ScenarioContext,
    run_scenario,
)


_NS = UUID('00000000-0000-0000-0000-000000000aaa')
# The anchored cohort's uuid when a case stages one (RD_14.4 Phase 6), the
# same in both adapters; a scenario names it as `cohort`.
_COHORT_UUID = uuid5(_NS, 'group:anchored-cohort')


class _CapturingQueue:
    def __init__(self, sink: list[Any]) -> None:
        self._sink = sink

    def put(self, item: Any, block: bool = True, timeout: float | None = None) -> None:
        self._sink.append(item)

    def put_nowait(self, item: Any) -> None:
        self._sink.append(item)

    def get(self, block: bool = True, timeout: float | None = None) -> Any:
        raise queue.Empty

    def get_nowait(self) -> Any:
        raise queue.Empty


class _Participant:
    def __init__(self, pid: str, role: str, identity: Identity,
                 process: ReputationProcess, queues: dict[str, Any]) -> None:
        self.id = pid
        self.role = role
        self.identity = identity
        self.process = process
        self.queues = queues
        self.outbox_buffer: list[Any] = []
        # Populated by ReputationAdapter._build_participants after all
        # participants exist; _check_expected_state[reputation_of] uses
        # it to resolve pid -> Identity.uuid for self.process.reputations
        # lookups.
        self._all_participants: dict[str, '_Participant'] = {}
        # Cumulative count of slash proposals this participant ORIGINATED,
        # tallied in _record_and_put rather than read off a drained outbox:
        # the engine clears the outbox each step, and the assertion this
        # exists for is "over the whole scenario, none" (R+D.md §12.8). A
        # per-step outbox cannot express that, and the engine's step matching
        # is permissive about extra messages, so an unpinned stray proposal
        # would pass silently.
        self.slashes_proposed = 0
        # Cumulative count of attestation co-signatures this participant SENT
        # (doc/architecture/reputation.md, "Verifier-attested scores"), for the
        # same reason: the cases this exists for are mostly "it declined".
        self.attest_signs_sent = 0

    def drain_outbox(self) -> list[CapturedMessage]:
        captured: list[CapturedMessage] = []
        for msg in self.outbox_buffer:
            captured.append(_to_captured(msg, emitter_id=self.id))
        self.outbox_buffer.clear()
        return captured

    def _check_expected_state(self, asserts: dict[str, Any]) -> None:
        participants = self._all_participants
        for key, expected in asserts.items():
            if key == 'history_len':
                actual = len(self.process.history)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: history_len={actual}, expected {expected}'
                    )
            elif key == 'chain_tasks':
                # The resident chain's tasks in index order, by slug.
                want = [uuid5(_NS, f'tx:{slug}') for slug in expected]
                actual = [tx.task_id for tx in self.process.history]
                if [str(t) for t in actual] != [str(t) for t in want]:
                    raise AssertionError(f'{self.id}: chain_tasks differ '
                                         f'({len(actual)} resident)')
            elif key == 'pool_count':
                # How many entries wait in the primary chain's pool.
                have = self.process.history.pooled_count()
                if have != expected:
                    raise AssertionError(f'{self.id}: pool_count={have}, '
                                         f'expected {expected}')
            elif key in ('chain_entries', 'pooled_entries', 'pool_tasks'):
                # The resident chain's entries in index order, or the pool's
                # entries as a set, by chain-spec slug ("chain:<slug>"); or the
                # pool's tasks as a set, by task slug ("tx:<slug>").
                ns = 'tx' if key == 'pool_tasks' else 'chain'
                want = [str(uuid5(_NS, f'{ns}:{slug}')) for slug in expected]
                hist = self.process.history
                actual = ([str(tx.task_id) for tx in hist] if key == 'chain_entries'
                          else sorted(str(t) for t in hist._pool))
                if key != 'chain_entries':
                    want = sorted(want)
                if actual != want:
                    raise AssertionError(f'{self.id}: {key} differ '
                                         f'({len(actual)} held)')
            elif key == 'catchup_told':
                # [index, ...], order-free: the primary-chain entries marked
                # told by catch-up under the join policy (RD_14.4 plan,
                # D2 (b)). C mirrors via reputation_catchup_marks.
                actual = sorted(self.process._catchup_marks.get('', set()))
                if actual != sorted(int(i) for i in expected or []):
                    raise AssertionError(f'{self.id}: catchup_told={actual}, '
                                         f'expected {sorted(expected or [])}')
            elif key == 'equivocations':
                # {count, index, both: [pid, ...]}: how many equivocation
                # records the primary chain holds, and the newest one's fork
                # index and the members who signed both values (R+D.md §14.1).
                # Mirrors the C adapter.
                held = self.process._fork_records('')
                newest = held[-1] if held else {}
                uuid_of = {str(p.identity.uuid).lower(): pid
                           for pid, p in participants.items()}
                actual = {'count': len(held)}
                if 'index' in expected:
                    actual['index'] = newest.get('index')
                if 'both' in expected:
                    actual['both'] = sorted(uuid_of.get(u, u)
                                            for u in newest.get('both', ()))
                want = dict(expected)
                if 'both' in want:
                    want['both'] = sorted(want['both'])
                if actual != want:
                    raise AssertionError(f'{self.id}: equivocations={actual}, '
                                         f'expected {want}')
            elif key == 'place_promised':
                # {n, by: <pid>}, or null for no promise.
                have = self.process._place_state('')['promised']
                if expected is None:
                    ok = have is None
                else:
                    by = participants[expected['by']].identity.uuid
                    ok = have == (int(expected['n']), str(by).lower())
                if not ok:
                    raise AssertionError(f'{self.id}: place_promised={have!r}, '
                                         f'expected {expected!r}')
            elif key == 'committed_tx_count':
                # Count of transactions resident in the hash-linked chain
                # (== len(history) here). The C twin reads tx_history rather
                # than its paxos.chain_len ballot counter, so this key stays
                # meaningful cross-language after a catch-up replay where the
                # two C counters diverge.
                actual = len(self.process.history)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: committed_tx_count={actual}, '
                        f'expected {expected}'
                    )
            elif key in ('halves_held', 'certified_halves', 'signed_halves',
                         'cohort_halves_held'):
                # Ordinary halves held (in the chain or waiting in the pool),
                # how many carry a commit certificate
                # (doc/architecture/reputation.md, "Commit certificates"), and
                # how many carry their scorer's own signature (R+D.md §14.2).
                # cohort_halves_held counts the anchored cohort's chain
                # instead (RD_14.4 Phase 6); 0 when none is held.
                held = certified = signed = 0
                hist = self.process.history
                if key == 'cohort_halves_held':
                    ck = self.process._cohort_key()
                    hist = (self.process._chain_for_group(ck) if ck
                            else TransactionHistory())
                for tx in (list(hist._task_mapping.values())
                           + list(hist._pool.values())):
                    if tx.attested:
                        continue
                    for scorer in (tx.p1_id, tx.p2_id):
                        if scorer is None:
                            continue
                        held += 1
                        certified += tx.certificate_of(scorer) is not None
                        signed += tx.half_sig_of(scorer) is not None
                actual = {'halves_held': held, 'certified_halves': certified,
                          'signed_halves': signed,
                          'cohort_halves_held': held}[key]
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: {key}={actual}, expected {expected}')
            elif key == 'window_root':
                # Phase 2: RFC 6962 ordered Merkle root over the resident
                # committed window. Pins cross-language byte-identity of the
                # checkpoint commitment — C's transaction_window_root must
                # reproduce this exact hex from byte-identical entry_hashes.
                actual = self.process.history.window_root()
                if isinstance(actual, bytes):
                    actual = actual.decode('ascii')
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: window_root={actual}, expected {expected}'
                    )
            elif key == 'checkpoint_root':
                # Phase 2: the root of the latest finalized quorum-signed
                # checkpoint this node stored (handle_checkpoint_final). Empty
                # string when none. Pins the final->store path cross-language.
                ckpt = getattr(self.process, '_checkpoint', None)
                actual = ''
                if ckpt is not None and ckpt.root:
                    actual = (ckpt.root.decode('ascii')
                              if isinstance(ckpt.root, bytes) else str(ckpt.root))
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: checkpoint_root={actual}, expected {expected}'
                    )
            elif key == 'checkpoint_cosigns_parked':
                # A proposal this node could not co-sign on arrival, kept for
                # a later one (ISSUES §2.29). Mirrors C reputation_parked_cosign_count.
                actual = len(getattr(self.process, '_cosigns_parked', {}))
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: checkpoint_cosigns_parked={actual}, '
                        f'expected {expected}'
                    )
            elif key == 'evidence_doc':
                # Verifiable warm start (doc/architecture/reputation.md). The persisted-evidence
                # document is the ONE artifact both runtimes read, so its shape
                # belongs in the corpus. Pinned by the fields that carry
                # meaning across the boundary: the schema (a mismatch is a
                # refusal to rebuild rather than a misparse), the entry count,
                # and the root the checkpoint block commits to.
                if not isinstance(expected, dict):
                    raise AssertionError(
                        f'{self.id}: evidence_doc must be a mapping, got '
                        f'{type(expected).__name__}'
                    )
                ckpt = getattr(self.process, '_checkpoint', None)
                signed = None
                if ckpt is not None:
                    signed = SignedCheckpoint(
                        checkpoint=ckpt,
                        sigs=dict(getattr(self.process,
                                          '_checkpoint_sigs_final', {})))
                doc = evidence_to_dict(self.process.history, signed,
                                       forks=self.process._fork_records(''))
                actual = {
                    'schema': doc['schema'],
                    'chain_len': len(doc['chain']),
                    # Equivocation records the document carries (R+D.md §14.1).
                    'forks': len(doc.get('forks') or ()),
                    'checkpoint_root': ((doc['checkpoint'] or {}).get('root')
                                        or ''),
                }
                for field, want in expected.items():
                    if field not in actual:
                        raise AssertionError(
                            f'{self.id}: unsupported evidence_doc field '
                            f'{field!r}'
                        )
                    if actual[field] != want:
                        raise AssertionError(
                            f'{self.id}: evidence_doc.{field}='
                            f'{actual[field]!r}, expected {want!r}'
                        )
            elif key == 'resolved_reputation':
                # The verdict on a deep-resolution answer, and the score this
                # node computed FROM the attested window rather than the one
                # the answer claimed. Both runtimes must reach the same
                # verdict on the same evidence, or the same peer is trusted on
                # one implementation and refused on the other.
                if not isinstance(expected, dict):
                    raise AssertionError(
                        f'{self.id}: resolved_reputation must be a mapping, '
                        f'got {type(expected).__name__}'
                    )
                peer_pid = expected.get('peer')
                other = participants.get(peer_pid)
                if other is None:
                    raise AssertionError(
                        f'{self.id}.resolved_reputation: unknown participant '
                        f'{peer_pid!r}'
                    )
                entry = self.process.resolved_reps.get(
                    str(other.identity.uuid))
                if entry is None:
                    raise AssertionError(
                        f'{self.id}.resolved_reputation[{peer_pid}]: no answer '
                        f'recorded'
                    )
                score, verified, reason = entry
                if 'verified' in expected and verified != bool(expected['verified']):
                    raise AssertionError(
                        f'{self.id}.resolved_reputation.verified={verified!r}, '
                        f'expected {expected["verified"]!r} (reason: {reason})'
                    )
                if 'score' in expected:
                    want = expected['score']
                    if want is None:
                        if score is not None:
                            raise AssertionError(
                                f'{self.id}.resolved_reputation.score='
                                f'{score!r}, expected none'
                            )
                    elif score is None or abs(score - float(want)) > 1e-3:
                        raise AssertionError(
                            f'{self.id}.resolved_reputation.score={score!r}, '
                            f'expected {want!r}'
                        )
            elif key == 'evidence_ceiling_of':
                # { "<other_pid>": float } — the score ceiling the resident
                # window supports for that peer. This is the security
                # parameter of warm start made observable: if the two runtimes
                # disagree here they hand the same peer different tiers on
                # restore, with nothing else to show it.
                if not isinstance(expected, dict):
                    raise AssertionError(
                        f'{self.id}: evidence_ceiling_of must be a mapping, '
                        f'got {type(expected).__name__}'
                    )
                window = self.process.history._indexed_window()
                ceilings = self.process._evidence_ceilings(window)
                for other_pid, want in expected.items():
                    other = participants.get(other_pid)
                    if other is None:
                        raise AssertionError(
                            f'{self.id}.evidence_ceiling_of: unknown '
                            f'participant {other_pid!r}'
                        )
                    got = ceilings.get(str(other.identity.uuid))
                    if got is None:
                        raise AssertionError(
                            f'{self.id}.evidence_ceiling_of[{other_pid}]: not '
                            f'bounded by the window (expected {want!r})'
                        )
                    if abs(got - float(want)) > 1e-3:
                        raise AssertionError(
                            f'{self.id}.evidence_ceiling_of[{other_pid}]='
                            f'{got:.4f}, expected {float(want):.4f}'
                        )
            elif key == 'slashes_proposed':
                # How many slash proposals this participant ORIGINATED
                # (R+D.md §12.8). Its reason for existing is the zero case:
                # a hard-channel refutation that arrived FROM A PEER must not
                # let that peer accuse a third party, because the sender picks
                # its own channel tag. Both runtimes enforce that structurally
                # -- the accused subject is local-only and never serialized --
                # and this key is what makes the two agree about it in the
                # corpus rather than only in each side's unit tests.
                actual = self.slashes_proposed
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: slashes_proposed={actual}, '
                        f'expected {expected}'
                    )
            elif key == 'attest_signs_sent':
                # How many attestation co-signatures this participant sent.
                # Zero is the declining cases' pin: an inadmissible
                # attestation, or one about this participant itself.
                actual = self.attest_signs_sent
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: attest_signs_sent={actual}, '
                        f'expected {expected}')
            elif key == 'app_roster':
                # Which peers the app-facing roster pull reported, as
                # participant ids. The carrier is local IPC toward the main
                # loop -- a PeerReputation object on AT_MAIN_QUEUE, not a
                # network Message (doc/architecture/app-peer-carrier.md) --
                # so it is read off the main queue rather than the outbox.
                #
                # Asserted as a SET of ids rather than a count because the
                # content is the point: the roster is peers only and never
                # carries this node itself. Python emitted a self-entry (N+1)
                # while C emitted N until that was aligned, and a bare count
                # would have hidden which entry differed.
                seen = set()
                for item in participants[self.id].queues[CfgIds.main]._sink:
                    if isinstance(item, PeerReputation):
                        seen.add(str(item.peer_uuid))
                by_uuid = {str(p.identity.uuid): pid
                           for pid, p in participants.items()}
                actual = sorted(by_uuid.get(u, u) for u in seen)
                if actual != sorted(expected):
                    raise AssertionError(
                        f'{self.id}: app_roster={actual}, '
                        f'expected {sorted(expected)}'
                    )
            elif key == 'reputation_of':
                # `expected` is { "<other_pid>": float } — compare
                # self.process.reputations[uuid_of(other)] with 1e-3
                # tolerance (C twin uses the same). Catches weighted-pure
                # / CTFT math regressions.
                if not isinstance(expected, dict):
                    raise AssertionError(
                        f'{self.id}: reputation_of must be a mapping, got '
                        f'{type(expected).__name__}'
                    )
                for other_pid, want in expected.items():
                    other = participants.get(other_pid)
                    if other is None:
                        raise AssertionError(
                            f'{self.id}.reputation_of: unknown participant '
                            f'{other_pid!r}'
                        )
                    other_uuid = other.identity.uuid
                    if other_uuid not in self.process.reputations:
                        raise AssertionError(
                            f'{self.id}.reputation_of[{other_pid}]: not present '
                            f'(expected {want!r})'
                        )
                    got = self.process.reputations[other_uuid]
                    if abs(got - float(want)) > 1e-3:
                        raise AssertionError(
                            f'{self.id}.reputation_of[{other_pid}]={got:.4f}, '
                            f'expected {float(want):.4f}'
                        )
            elif key in ('brought_of', 'bounded_of'):
                # { "<other_pid>": float | null }: the brought score (null:
                # none held) or what a decision reads (RD_14.4 Phase 4).
                # Mirrors the C adapter.
                for other_pid, want in expected.items():
                    other = participants.get(other_pid)
                    if other is None:
                        raise AssertionError(
                            f'{self.id}.{key}: unknown participant {other_pid!r}')
                    other_uuid = other.identity.uuid
                    if key == 'brought_of':
                        got = self.process.reputations.brought.get(str(other_uuid))
                    else:
                        told = (self.process.reputations[other_uuid]
                                if other_uuid in self.process.reputations else None)
                        got = self.process._bounded(other_uuid, told)
                    if want is None or got is None:
                        if want is not got:
                            raise AssertionError(
                                f'{self.id}.{key}[{other_pid}]={got!r}, '
                                f'expected {want!r}')
                    elif abs(got - float(want)) > 1e-3:
                        raise AssertionError(
                            f'{self.id}.{key}[{other_pid}]={got:.4f}, '
                            f'expected {float(want):.4f}')
            elif key == 'unrated':
                # `expected` is [ "<pid>", ... ] -- participants this one
                # holds NO stored score for (the negation reputation_of cannot
                # express). C twin reads the same snapshot slot.
                if not isinstance(expected, list):
                    raise AssertionError(
                        f'{self.id}: unrated must be a list, got '
                        f'{type(expected).__name__}'
                    )
                for other_pid in expected:
                    other = participants.get(other_pid)
                    if other is None:
                        raise AssertionError(
                            f'{self.id}.unrated: unknown participant '
                            f'{other_pid!r}'
                        )
                    other_uuid = other.identity.uuid
                    if other_uuid in self.process.reputations:
                        raise AssertionError(
                            f'{self.id}.unrated[{other_pid}]: scored '
                            f'{self.process.reputations[other_uuid]:.4f}'
                        )
            else:
                raise AssertionError(f'{self.id}: unsupported expected_state key {key!r}')



def _milli(score):
    """A scenario's score (0.0..1.0, as an application gives one) as the
    integer thousandths the wire and the chain carry. A value off the scale is
    passed through still off it (thousandths when finite, else as it came;
    the C adapter sends INT_MIN for the latter), so a scenario that sends 7.5
    or NaN still reaches the gate that refuses it.
    Mirrors the C adapter's _milli."""
    try:
        return score_to_milli(score)
    except ValueError:
        try:
            value = float(score)
        except (TypeError, ValueError):
            return score
        if not math.isfinite(value) or abs(value) > 1e6:
            return value
        # C's lround: half away from zero.
        return int(math.copysign(math.floor(abs(value) * 1000 + 0.5), value))


def _chain_half_pid(entry: dict, half: int, parties=None):
    """The participant id of one half of a chain entry: its `p1_id` / `p2_id`,
    else the scenario's `chain_parties` fixture ([p1, p2]), else None."""
    pid = entry.get('p1_id' if half == 1 else 'p2_id')
    if pid is None and parties:
        pid = parties[half - 1]
    return pid


def _chain_half(entry: dict, half: int, task: str, uuid_of,
                parties=None) -> UUID:
    """The uuid of one half of a `local_chain` / `latest update` chain entry:
    the participant named by its `p1_id` / `p2_id`, or by the scenario's
    `chain_parties` fixture, when there is one (so a scenario can make an
    entry this node's OWN half, Agora Phase 4 DDIL, and so a half can be
    signed by its scorer, R+D.md §14.2), else the synthetic ``chainp1:<task>``
    / ``chainp2:<task>`` derivation, which nobody can sign. Both builders go
    through here so the chains hash-match up to the fork. Mirrors the C
    adapter's _chain_half_uuid."""
    pid = _chain_half_pid(entry, half, parties)
    if pid is not None:
        u = uuid_of(pid)
        if u is not None:
            return u
    return uuid5(_NS, f"chainp{half}:{task}")


def _write_roster(hist, entry, member, sign) -> None:
    """A roster entry of a chain spec, placed alone at the chain's next index
    (doc/architecture/reputation.md, "Who is in the group"): {roster: genesis,
    members: [ids]} or {roster: add, member: id}, its placement certificate
    signed by `placed_by: [ids]`. `n_min: N` declares an N_min (RD_13.2 plan
    §0.4). `member(id)` returns [uuid, key]. Mirrors the C adapter's
    _write_roster."""
    from autonomous_trust.core.reputation.reputation import (roster_digest,
                                                             roster_task_id)
    op, who = entry['roster'], None
    if op == 'genesis':
        members = [member(m) for m in entry['members']]
        prev = None
    else:
        r = hist.latest_roster()
        members, prev = list(map(list, r.roster_members)), r.task_id
        if op == 'add':
            m = member(entry['member'])
            members, who = members + [m], m[0]
    d = roster_digest(members)
    n_min = entry.get('n_min') or None
    tx = Transaction(roster_task_id(prev, op, who, d, n_min), roster_op=op,
                     roster_uuid=None if who is None else UUID(who),
                     roster_digest=d, roster_members=members, roster_n_min=n_min)
    k = hist.next_index
    by = entry.get('placed_by')
    sigs = (sign(by, place_designation(k, hist.head_hash,
                                       place_value_digest([tx], k)))
            if isinstance(by, list) else None)
    hist.apply_placed(k, [tx], sigs)


def _write_chain(hist, spec, uuid_of, sign, member=None, parties=None) -> None:
    """Write a `local_chain` / `latest update` chain spec into `hist` through
    the production writers. An entry without `batch` is written the legacy way
    (two update() halves). Consecutive entries sharing a `batch` are written as
    ONE decided placement at the chain's next index (apply_placed); the batch's
    last entry may name `placed_by: [ids]`, who sign its placement certificate
    (doc/architecture/reputation.md, "Agreeing on an order"). `certified_by:
    [ids]` certifies both halves of an entry. `sign(ids, designation)` returns
    {uuid str: signature hex}.

    Each half of an entry between two participants is signed by its scorer
    over `half_designation` (R+D.md §14.2) unless the entry says `unsigned:
    true`; `half_forged_by: id` signs both halves with that participant's key
    instead. `parties` is the `chain_parties` fixture. Mirrors the C adapter's
    _write_chain."""
    i = 0
    while i < len(spec):
        entry = spec[i]
        if isinstance(entry.get('roster'), str):
            _write_roster(hist, entry, member, sign)
            i += 1
            continue
        if entry.get('batch') is None:
            tk = uuid5(_NS, f"chain:{entry['task']}")
            hist.update(tk, _chain_half(entry, 1, entry['task'], uuid_of, parties),
                        _milli(entry['p1']))
            hist.update(tk, _chain_half(entry, 2, entry['task'], uuid_of, parties),
                        _milli(entry['p2']))
            i += 1
            continue
        group = []
        while i < len(spec) and spec[i].get('batch') == entry['batch']:
            group.append(spec[i])
            i += 1
        entries = [placement_entry(Transaction(
            uuid5(_NS, f"chain:{e['task']}"),
            p1_id=_chain_half(e, 1, e['task'], uuid_of, parties),
            p1_score_milli=_milli(e['p1']),
            p2_id=_chain_half(e, 2, e['task'], uuid_of, parties),
            p2_score_milli=_milli(e['p2'])))
            for e in group]
        k = hist.next_index
        by = group[-1].get('placed_by')
        sigs = (sign(by, place_designation(k, hist.head_hash,
                                           place_value_digest(entries, k)))
                if isinstance(by, list) else None)
        hist.apply_placed(k, entries, sigs)
    for entry in spec:
        by = entry.get('certified_by')
        if not isinstance(by, list) or 'task' not in entry:
            continue
        tx = hist._task_mapping.get(uuid5(_NS, f"chain:{entry['task']}"))
        if tx is None:
            continue
        for scorer, score in ((tx.p1_id, tx.p1_score_milli),
                              (tx.p2_id, tx.p2_score_milli)):
            tx.attach_certificate(scorer, sign(
                by, commit_designation(scorer, tx.task_id, score)))
    for entry in spec:
        if 'task' not in entry or entry.get('unsigned'):
            continue
        tx = hist._task_mapping.get(uuid5(_NS, f"chain:{entry['task']}"))
        pids = [_chain_half_pid(entry, h, parties) for h in (1, 2)]
        if tx is None or None in pids:
            continue
        pid_of = {str(uuid_of(p)): p for p in pids if uuid_of(p) is not None}
        for scorer, other, score in ((tx.p1_id, tx.p2_id, tx.p1_score_milli),
                                     (tx.p2_id, tx.p1_id, tx.p2_score_milli)):
            pid = pid_of.get(str(scorer))
            if pid is None or other is None:
                continue
            signer = entry.get('half_forged_by') or pid
            got = sign([signer], half_designation(tx.task_id, scorer, other,
                                                  score))
            if got:
                tx.attach_half_sig(scorer, next(iter(got.values())))


def _to_captured(msg: Any, emitter_id: str) -> CapturedMessage:
    if not isinstance(msg, Message):
        return CapturedMessage(
            from_id=emitter_id, to_id='internal',
            function=f'__ipc__/{type(msg).__name__}', payload=msg, raw=msg,
        )
    to_id = _resolve_to_id(msg)
    return CapturedMessage(
        from_id=emitter_id, to_id=to_id,
        function=msg.function, payload=msg.obj, raw=msg,
    )


def _resolve_to_id(msg: Message) -> str:
    to = msg.to_whom
    if isinstance(to, Identity):
        return getattr(to, 'petname', '') or str(to.uuid)
    if isinstance(to, Group):
        return 'broadcast'
    if isinstance(to, list) and to:
        first = to[0]
        return getattr(first, 'petname', '') or str(getattr(first, 'uuid', first))
    return 'broadcast'


class ReputationAdapter:
    """Phase F scenario adapter for the reputation protocol."""

    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root
        self._scratch: tempfile.TemporaryDirectory | None = None
        self._package_hash = PackageHash().digest

    def run_scenario(self, case: Case) -> None:
        self._scratch = tempfile.TemporaryDirectory(prefix='at-conformance-rep-')
        try:
            os.environ[Configuration.ROOT_VARIABLE_NAME] = self._scratch.name
            os.makedirs(os.path.join(self._scratch.name, 'etc/at'), exist_ok=True)

            participants = self._build_participants(case)
            ctx = ScenarioContext(
                case=case,
                participants=participants,
                build_inbound=lambda **kw: self._build_inbound(participants, **kw),
                describe=lambda cm: (cm.from_id, cm.to_id, cm.function, cm.payload),
            )
            run_scenario(ctx)
        finally:
            self._scratch.cleanup()
            self._scratch = None

    def run_wire_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('reputation wire_vector kind not implemented')

    def run_crypto_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('reputation does not own crypto vectors')

    def run_negative(self, case: Case) -> None:
        from ...common.negative_runner import run_wire_negative
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
        # The two participants a chain entry is between when it names none
        # ([p1, p2]), so its halves can be signed by their scorers (R+D.md
        # §14.2). Absent keeps the synthetic, unsignable halves.
        self._chain_parties = fixtures.get('chain_parties') or None
        # Preset state for handlers that gate on history length -- see
        # scenario YAML keys for documentation.
        preset_history_len: dict[str, int] = fixtures.get('history_len', {}) or {}
        # proposals pre-stages a proposer's outstanding rounds. Each entry:
        # {id1, id2, task_id, score, channel?}. handle_accepted looks the
        # round's score up by (id1, id2). Mirrors the C adapter.
        preset_proposals: dict[str, list[dict[str, Any]]] = fixtures.get('proposals', {}) or {}
        # tx_history pre-stages bilateral Transactions in self.process.history.
        # { pid -> [{task_id, p1, p1_score, p2, p2_score}, ... ] }. p1/p2
        # reference other participant ids; the adapter resolves them to
        # UUIDv5(rep:<pid>). Required by reputation_pure / _contrite_tft
        # to score against committed bilateral txs.
        preset_tx_history: dict[str, list[dict[str, Any]]] = fixtures.get('tx_history', {}) or {}
        # local_chain: { pid -> [{task, p1, p2}] } -- the participant's OWN
        # committed chain, built through history.update() with the SAME uuid
        # derivation as the `latest update` payload builder, so it hash-matches
        # a reported chain up to wherever the two fork. Mirrors C.
        preset_local_chain: dict[str, list[dict[str, Any]]] = fixtures.get('local_chain', {}) or {}
        # reputations pre-stages self.process.reputations. { pid -> { other_pid -> float } }.
        # Used to pin the counterparty's reputation (consumed by reputation_pure)
        # and the subject peer's `previous` value (consumed by _compute_reputation's
        # coop-mode latch).
        preset_reputations: dict[str, dict[str, float]] = fixtures.get('reputations', {}) or {}
        # task_weights pre-stages self.process.task_weights. { pid -> { task_slug -> int } }.
        # Mirrors how the C twin stages weights via reputation_install_task_weight.
        preset_task_weights: dict[str, dict[str, int]] = fixtures.get('task_weights', {}) or {}
        # coop_mode pre-stages self.process._coop_mode. { pid -> { other_pid -> bool } }.
        # Hysteresis latch read by _compute_reputation; combined with `reputations`,
        # pins which branch (pure vs. CTFT) runs.
        preset_coop_mode: dict[str, dict[str, bool]] = fixtures.get('coop_mode', {}) or {}
        # peer_standing pre-sets what an authority has found about a peer
        # (doc/architecture/zta-integration.md):
        # { pid -> { other_pid -> <spec> | [<spec>, ...] } }, where <spec> is
        # {status, ceiling, source?, reason?}. Installed directly rather than
        # driven through an admission step because the verdict is produced by
        # the IDENTITY process and this protocol's harness stands up only the
        # reputation one -- the cross-language claim being pinned is what
        # reputation DOES with a standing, not how identity reaches it.
        # A LIST lets two authorities speak about the same peer, which is the
        # only way to pin the minimum-over-sources reduction.
        preset_peer_standing: dict[str, dict[str, Any]] = fixtures.get('peer_standing', {}) or {}
        # tenure pre-sets the tenure gate (doc/architecture/reputation.md,
        # "Tenure"): { pid -> {min_sec: N, <other_pid>: seconds_ago, ...} },
        # the minimum and when this participant first held each member.
        # Installed directly, like peer_standing: the clock is started by the
        # rescore sweep, which this harness does not run.
        preset_tenure: dict[str, dict[str, Any]] = fixtures.get('tenure', {}) or {}
        # checkpoint pre-seeds a finalized Phase 2 checkpoint root.
        # { pid -> {root: <hex>, epoch: int} }. Lets a single-step scenario
        # verify an evidence-bearing slash against a checkpoint (Phase 3); the
        # C harness resets per step, so the checkpoint can't be carried from a
        # prior checkpoint_final step. Mirrors reputation_install_checkpoint.
        preset_checkpoint: dict[str, dict[str, Any]] = fixtures.get('checkpoint', {}) or {}
        # num_updates pre-sets self.process.num_updates (the catch-up quorum).
        # { pid -> int }. Lets a single-step scenario exercise the verifiable
        # catch-up path (Phase 1) without accumulating across steps — the C
        # conformance harness resets state per step, so cross-step quorum
        # accumulation isn't portable. Default stays the production value (3).
        preset_num_updates: dict[str, int] = fixtures.get('num_updates', {}) or {}
        # slash_enabled arms the slash protocol for this case. It is opt-in in
        # production (R+D.md §12.8): unarmed, a node originates nothing,
        # declines to co-sign a proposal, and ignores a finalized slash, so a
        # scenario that drives that protocol has to say so -- and every
        # scenario that does NOT say so is a pin that the default is off.
        # Scenario-level rather than per-participant, because the C twin's
        # knob is an environment variable and the whole cohort shares it.
        preset_slash_enabled: bool = bool(fixtures.get('slash_enabled', False))
        # n_min: {pid: N} -- the N_min a participant is configured for
        # (AT_REP_N_MIN; RD_13.2 plan §0.4). Mirrors the C adapter, which sets
        # the variable for the participant a step is delivered to.
        preset_n_min: dict = fixtures.get('n_min', {}) or {}
        # attest_conflicts: [[pid, ...], ...] -- the teams whose members do not
        # witness for each other (ISSUES §2.54). Scenario-level: every node
        # holds the same set, as every node holding one verified team roster
        # does. Mirrors the C adapter's reputation_set_attest_conflicts.
        preset_attest_conflicts: list = fixtures.get('attest_conflicts') or []

        identities: dict[str, Identity] = {}
        for idx, spec in enumerate(spec_participants):
            pid = spec['id']
            sig = hashlib.sha256(b'rep:sig:' + pid.encode()).hexdigest().encode('ascii')
            enc = hashlib.sha256(b'rep:enc:' + pid.encode()).hexdigest().encode('ascii')
            identity = Identity(
                uuid5(_NS, f'rep:{pid}'), f'10.0.60.{idx + 1}',
                f'{pid}.rep',
                Signature(sig, public_only=False),
                Encryptor(enc, public_only=False),
                pid, False, 0, 'authority',
            )
            identities[pid] = identity

        # Group seeded by first participant; every existing participant in
        # the group's address map, except the `direct_peers`: a first-contact
        # direct peer is in every peer list and in no group (R+D.md §13.5 D2).
        # The first participant must not be one. Mirrors the C adapter.
        direct = {str(d) for d in fixtures.get('direct_peers') or ()}
        seed_pid = spec_participants[0]['id']
        group = Group(identities[seed_pid].uuid, {identities[seed_pid].uuid: identities[seed_pid].address},
                      'rep-grp', Encryptor.generate(), False)
        for spec in spec_participants[1:]:
            if spec['id'] not in direct:
                group.add_address(identities[spec['id']].uuid, identities[spec['id']].address)
        # Every group places its order (doc/architecture/reputation.md,
        # "Agreeing on an order"). Placement state lives in a directory per
        # participant, fresh per case: every participant shares this process
        # and its config directory.
        place_root = tempfile.mkdtemp(prefix='at-conf-place-')
        preset_place_promised = fixtures.get('place_promised', {}) or {}
        # The roster in force before the scenario starts: every participant,
        # unless `roster` names one per participant ({} for none, an unfounded
        # chain). Mirrors the C adapter.
        if 'roster' in fixtures:
            preset_roster = fixtures.get('roster') or {}
        else:
            everyone = [p['id'] for p in spec_participants
                        if p['id'] not in direct]
            preset_roster = {p['id']: everyone for p in spec_participants}
        self._fixture_roster = preset_roster

        handles: dict[str, ParticipantHandle] = {}
        for spec in spec_participants:
            pid = spec['id']
            role = spec['role']
            identity = identities[pid]

            peers = Peers()
            for other_pid, other_id in identities.items():
                if other_pid == pid:
                    continue
                peers.add(other_id)

            participant = self._build_one(pid, role, identity, peers, group)
            where = os.path.join(place_root, pid)
            os.makedirs(where, exist_ok=True)
            participant.process._placement_path = (
                lambda key, where=where: os.path.join(
                    where, 'reputation-placement' + ('-' + key if key else '')
                    + Configuration.file_ext))
            if pid in preset_roster:
                # roster: {pid: [member pids]} -- the roster in force on pid's
                # primary chain before the scenario starts, each member with
                # its signing key (doc/architecture/reputation.md, "Who is in
                # the group"). An anchor with no index, so the scenario's
                # instances keep theirs. Mirrors the C adapter.
                from nacl.encoding import HexEncoder
                from autonomous_trust.core.reputation.reputation import (
                    Transaction, roster_digest, roster_task_id)
                members = [[str(identities[m].uuid),
                            identities[m].signature.public.encode(
                                encoder=HexEncoder).decode('ascii')]
                           for m in preset_roster[pid]]
                digest = roster_digest(members)
                participant.process.history.roster_anchor = Transaction(
                    roster_task_id(None, 'genesis', None, digest),
                    roster_op='genesis', roster_digest=digest,
                    roster_members=members)
            if pid in preset_place_promised:
                spec_pp = preset_place_promised[pid]
                participant.process._place_state('')['promised'] = (
                    int(spec_pp['n']),
                    str(identities[spec_pp['by']].uuid).lower())

            # Preset history_len: append N zero-Transaction stubs so
            # len(history) returns the expected value without altering
            # other state.
            from autonomous_trust.core.reputation.reputation import Transaction
            n = preset_history_len.get(pid, 0)
            for i in range(n):
                tx = Transaction(uuid5(_NS, f'preset:{pid}:{i}'), uuid5(_NS, 'preset:p1'),
                                 0.5, uuid5(_NS, 'preset:p2'), 0.5, index=i)
                participant.process.history._chain.append(tx)
                participant.process.history._task_mapping[tx.task_id] = tx

            if pid in preset_num_updates:
                participant.process.num_updates = int(preset_num_updates[pid])
            # Instance attribute, shadowing the class-level default that reads
            # the environment at import: the corpus must not depend on how the
            # harness process was launched.
            participant.process.SLASH_ENABLED = preset_slash_enabled
            participant.process.N_MIN = preset_n_min.get(pid)

            if pid in preset_checkpoint:
                spec_ck = preset_checkpoint[pid]
                root = spec_ck.get('root', '')
                participant.process._checkpoint = Checkpoint(
                    proposer_uuid=identity.uuid,
                    root=root.encode('ascii') if isinstance(root, str) else root,
                    epoch=int(spec_ck.get('epoch', 1)),
                    first_index=int(spec_ck.get('first_index', 0)),
                    count=int(spec_ck.get('count', 0)))

            for entry in preset_proposals.get(pid, []):
                idx = (int(entry['id1']), int(entry['id2']))
                # Whom the proposer's half names (R+D.md §14.2): `names`,
                # else the first other participant. Mirrors the C adapter.
                names = entry.get('names') or next(
                    (p['id'] for p in spec_participants if p['id'] != pid), None)
                score = TransactionScore(
                    task_id=str(uuid5(_NS, f'tx:{entry.get("task_id", "default")}')),
                    score=float(entry.get('score', 1.0)),
                    # Absent -> TX_CHANNEL_TASK_OUTCOME (R+D.md §12.8).
                    channel=entry.get('channel'),
                    subject_uuid=(identities[names].uuid if names in identities
                                  else None),
                )
                participant.process.proposals[idx] = score
                # `group: cohort` binds the round to the anchored cohort, as
                # _start_paxos does for a half about a member (RD_14.4 Phase
                # 6). Mirrors the C adapter.
                participant.process.round_group[idx] = (
                    str(_COHORT_UUID) if entry.get('group') == 'cohort'
                    else str(group.uuid))

            # tx_history: each entry installs a bilateral Transaction via
            # two history.update calls (matching how handle_committed
            # builds bilateral history in production). p1/p2 reference
            # participant ids; missing ids on either side are skipped.
            def _ident_uuid(other):
                return identities[other].uuid if other in identities else None
            local = preset_local_chain.get(pid, [])
            if any('batch' in e or 'certified_by' in e or 'roster' in e
                   for e in local):
                # A placed (or certified) local chain: built apart, then
                # loaded verbatim with its certificates, as catch-up loads one.
                def _sign_ids(ids, desig):
                    return {str(identities[i].uuid):
                            ReputationProcess._detached_sig(identities[i], desig)
                            for i in ids if i in identities}
                tmp = TransactionHistory(max_chain_len=len(local) + 1)
                def _member(i):
                    from nacl.encoding import HexEncoder
                    return [str(identities[i].uuid).lower(),
                            identities[i].signature.public.encode(
                                encoder=HexEncoder).decode('ascii')]
                _write_chain(tmp, local, _ident_uuid, _sign_ids, _member,
                             self._chain_parties)
                built = list(tmp)
                participant.process.history.reconcile(
                    built, certified={t.index for t in built})
            else:
                for entry in local:
                    tk = uuid5(_NS, f"chain:{entry['task']}")
                    participant.process.history.update(
                        tk, _chain_half(entry, 1, entry['task'], _ident_uuid,
                                        self._chain_parties),
                        _milli(entry['p1']))
                    participant.process.history.update(
                        tk, _chain_half(entry, 2, entry['task'], _ident_uuid,
                                        self._chain_parties),
                        _milli(entry['p2']))

            for entry in preset_tx_history.get(pid, []):
                if entry.get('attested'):
                    # A verifier-attested entry: p1 is the verifier, its task
                    # id derived from its content. Mirrors the C adapter.
                    v, subj = entry.get('p1'), entry.get('subject')
                    if v in identities and subj in identities:
                        vu, su = identities[v].uuid, identities[subj].uuid
                        dig = entry.get('evidence_digest')
                        participant.process.history.append_attested(Transaction(
                            attest_task_id(vu, su, dig), p1_id=vu,
                            p1_score_milli=_milli(entry.get('p1_score', 0.0)),
                            p1_channel=entry.get('p1_channel'), attested=True,
                            subject_id=su, evidence_digest=dig,
                            attest_scope=entry.get('attest_scope')))
                    continue
                slug = entry.get('task_id')
                p1_id = entry.get('p1')
                p2_id = entry.get('p2')
                if slug is None or p1_id not in identities:
                    continue
                task_uuid = uuid5(_NS, f'tx:{slug}')
                if p2_id is None:
                    # One side only, waiting in the pool for its counterpart,
                    # as a committed half does (mirrors C's
                    # reputation_install_tx_single): lets a single step drive
                    # the arrival that completes the entry, since the C
                    # harness resets state between steps.
                    # `names: id` is whom the half names (R+D.md §14.2);
                    # absent, it pairs as a half held before names did.
                    names = entry.get('names')
                    participant.process.history.record_half(
                        task_uuid, identities[p1_id].uuid,
                        _milli(entry.get('p1_score', 0.0)),
                        entry.get('p1_channel'),
                        counterparty=(identities[names].uuid
                                      if names in identities else None))
                    continue
                participant.process.history.update(
                    task_uuid, identities[p1_id].uuid,
                    _milli(entry.get('p1_score', 0.0)),
                    entry.get('p1_channel'))
                if p2_id not in identities:
                    continue
                participant.process.history.update(
                    task_uuid, identities[p2_id].uuid,
                    _milli(entry.get('p2_score', 0.0)),
                    entry.get('p2_channel'))

            for other_pid, score in preset_reputations.get(pid, {}).items():
                if other_pid not in identities:
                    continue
                participant.process.reputations.update(
                    identities[other_pid].uuid, float(score))

            for slug, weight in preset_task_weights.get(pid, {}).items():
                participant.process.task_weights[
                    str(uuid5(_NS, f'tx:{slug}'))
                ] = int(weight)

            for other_pid, in_coop in preset_coop_mode.get(pid, {}).items():
                if other_pid not in identities:
                    continue
                participant.process._coop_mode[
                    identities[other_pid].uuid
                ] = bool(in_coop)

            for other_pid, spec in preset_peer_standing.get(pid, {}).items():
                if other_pid not in identities:
                    continue
                specs = spec if isinstance(spec, list) else [spec]
                for one in specs:
                    ceiling = one.get('ceiling')
                    found = PeerStanding(identities[other_pid].uuid,
                                         one.get('status', STANDING_CAPPED),
                                         None if ceiling is None else float(ceiling),
                                         one.get('verified_at'),
                                         one.get('reason', ''),
                                         one.get('source'))
                    # Keyed by the finding's own (peer, source) key, exactly as
                    # Protocol.run_message_handlers would file it.
                    participant.process.protocol.peer_standing[found.key] = found
            # Always set, so a conflict file another case wrote into the
            # shared config dir is never read: no teams unless staged.
            participant.process.set_attest_conflicts({'teams': [
                [str(uuid5(_NS, f'rep:{m}')) for m in team]
                for team in preset_attest_conflicts]})
            tenure = preset_tenure.get(pid) or {}
            if tenure:
                import time as _time
                proc = participant.process
                proc._tenure_min_override = float(tenure.get('min_sec', 0))
                proc._tenure_seeded = True
                for other_pid, ago in tenure.items():
                    if other_pid == 'min_sec' or other_pid not in identities:
                        continue
                    proc._member_since[str(identities[other_pid].uuid)] = (
                        None, _time.time() - float(ago))
            # join_policy: the declaration's own JSON (RD_14.4 plan, Phase 3),
            # under which catch-up is marked. Always set, and the marks
            # cleared, so nothing a case's config dir holds leaks in. Mirrors
            # the C adapter's reputation_set_join_policy.
            participant.process.join_policy = (
                parse_join_policy(fixtures['join_policy'])
                if fixtures.get('join_policy') is not None else INERT_JOIN_POLICY)
            participant.process._catchup_marks = {}
            # Phase 4 (RD_14.4): `catchup_told` {pid: [index, ...]} pre-marks
            # primary-chain entries as told; `anchored` {pid: [other, ...]}
            # is the AnchoredSet identity would have sent; `seeds`
            # {pid: {other: seed}} offers each seed as an extension would,
            # after the reputations above. Mirrors the C adapter.
            # Staged scores are not a warm start; nothing a case's config dir
            # held is either.
            participant.process._warm_started = set()
            told = (fixtures.get('catchup_told') or {}).get(pid)
            if told:
                participant.process._catchup_marks = {'': {int(i) for i in told}}
            participant.process.protocol.anchored = frozenset(
                str(identities[o].uuid)
                for o in (fixtures.get('anchored') or {}).get(pid) or ()
                if o in identities)
            # Phase 6 (RD_14.4): `anchored_cohort` {pid: [member, ...]} is the
            # cohort identity would have published (AnchoredCohort), members
            # this participant included. Mirrors the C adapter.
            members = (fixtures.get('anchored_cohort') or {}).get(pid)
            participant.process.protocol.anchored_cohort = Group(
                _COHORT_UUID, {str(identities[m].uuid): identities[m].address
                               for m in members if m in identities},
                'anchored', Encryptor.generate(), False) if members else None
            for other_pid, seed in ((fixtures.get('seeds') or {}).get(pid)
                                    or {}).items():
                if other_pid in identities:
                    participant.process._offer_seed(
                        'fixture', identities[other_pid].uuid, seed, 'seed')
            if preset_peer_standing.get(pid):
                # ACT on them, not merely record them: the C adapter's
                # reputation_apply_peer_standing does the unwind at install time,
                # and in production the reputation process loop does it every
                # pass. Recording only would leave Python a step behind C and
                # report an asymmetry that is the harness's, not the runtime's.
                participant.process._apply_peer_standings({})

            handles[pid] = ParticipantHandle(
                id=pid, role=role, impl=participant,
                dispatch=lambda msg, p=participant: self._dispatch(p, msg),
            )
        # Cross-wire each participant impl with the full table so
        # _check_expected_state[reputation_of] can resolve other_pid ->
        # Identity.uuid without touching the engine.
        impls = {pid: h.impl for pid, h in handles.items()}
        for impl in impls.values():
            impl._all_participants = impls
        return handles

    def _build_one(self, pid: str, role: str, identity: Identity,
                   peers: Peers, group: Group) -> _Participant:
        net_sink: list[Any] = []
        main_sink: list[Any] = []
        id_sink: list[Any] = []
        neg_sink: list[Any] = []
        rep_sink: list[Any] = []

        queues = {
            CfgIds.reputation: _CapturingQueue(rep_sink),
            CfgIds.network: _CapturingQueue(net_sink),
            CfgIds.main: _CapturingQueue(main_sink),
            CfgIds.identity: _CapturingQueue(id_sink),
            CfgIds.negotiation: _CapturingQueue(neg_sink),
        }

        configurations = {
            CfgIds.identity: identity,
            CfgIds.peers: peers,
            CfgIds.capabilities: PeerCapabilities(),
            CfgIds.group: group,
            PackageHash.key: self._package_hash,
            'processes': [
                _FakeDep(CfgIds.network),
                _FakeDep(CfgIds.identity),
                _FakeDep(CfgIds.negotiation),
            ],
        }

        process = ReputationProcess(
            configurations,
            ProcessTracker(),
            log_q=queue.Queue(),
            suppress_log=True,
        )
        process.synchronous_dispatch = True
        # _try_again sleeps for backoff[idx] seconds and _paxos_timeout
        # waits up to protocol_timeout. With sync_dispatch on, both run
        # inline in the harness — neutralize their wait windows so
        # scenarios stay fast. backoff_mult=0 sets backoff[idx] to 0 on
        # the first nack, so _try_again returns immediately.
        process.backoff_mult = 0
        process.protocol_timeout = 0

        captured = _Participant(
            pid=pid, role=role, identity=identity,
            process=process, queues=queues,
        )

        original_put = queues[CfgIds.network].put

        def _record_and_put(item, *args, **kwargs):
            if isinstance(item, Message):
                captured.outbox_buffer.append(item)
                if item.function == ReputationProtocol.slash_propose:
                    captured.slashes_proposed += 1
                if item.function == ReputationProtocol.attest_sign:
                    captured.attest_signs_sent += 1
            original_put(item, *args, **kwargs)

        queues[CfgIds.network].put = _record_and_put  # type: ignore[method-assign]

        return captured

    # ------------------------------------------------------------------
    # Step driver
    # ------------------------------------------------------------------

    def _dispatch(self, participant: _Participant, inbound: Any) -> list[CapturedMessage]:
        if not isinstance(inbound, Message):
            raise AssertionError(f'expected a Message, got {type(inbound).__name__}')
        participant.process.protocol.run_message_handlers(participant.queues, inbound)
        # Stand in for the process loop's forwarding tick. The rep_req and
        # consensus_rep_req handlers do not answer inline: they compute a
        # roster and park it on `requested_reps`, which production drains
        # from ReputationProcess.process() on the next pass. C answers from
        # inside its handler (`_send_rep_response`), so without this the two
        # runtimes are not comparable on the reply at all -- Python would
        # emit nothing and any assertion on the answer could only ever hold
        # on one side. Draining here is a no-op for every handler that
        # already replied inline.
        participant.process.forward_reputation(participant.queues)
        return participant.drain_outbox()

    # ------------------------------------------------------------------
    # Inbound construction
    # ------------------------------------------------------------------

    @staticmethod
    def _detached_sig(identity, designation: bytes) -> str:
        """One participant's detached signature over ``designation``, in the
        ASCII-hex form both runtimes' handlers verify."""
        return identity.sign(designation).signature.decode('ascii')

    def _cosignatures(self, participants: dict[str, ParticipantHandle],
                      payload: dict[str, Any], designation: bytes,
                      exclude: str = None) -> dict:
        """Build the ``sigs`` map a ``*_final`` step carries.

        A finalizer is only applied if the RECEIVER can verify more than
        ``floor(N/2)`` distinct co-signatures over these exact bytes, so the
        map is real cryptography built at scenario time by each named
        co-signer's own key.

        ``cosigners`` names them (participant ids); the default is every
        participant except ``exclude`` (the slash target -- a peer does not
        co-sign its own slash), which is the ordinary quorum-agreed case.
        Negative controls override it: a shorter list is sub-quorum, and
        ``forged_by`` makes ONE participant sign every entry while the entries
        stay labelled with the others' uuids -- the case where a finalizer
        mints the whole map itself.
        """
        ids = payload.get('cosigners') if isinstance(payload, dict) else None
        if ids is None:
            ids = [pid for pid in participants if pid != exclude]
        forger = payload.get('forged_by') if isinstance(payload, dict) else None
        signer = participants[forger].impl.identity if forger else None
        sigs = {}
        for pid in ids:
            if pid not in participants:
                raise AssertionError(f'cosigner {pid!r} not a known participant')
            ident = participants[pid].impl.identity
            sigs[str(ident.uuid)] = self._detached_sig(signer or ident,
                                                      designation)
        return sigs

    def _resolved_answer(self, participants: dict[str, ParticipantHandle],
                         from_id: str, to_id: str,
                         payload: dict[str, Any]) -> dict:
        """The answer document a deep-resolution reply carries, built from the
        SENDER's real window and checkpoint -- real evidence at scenario time,
        the same way ``_cosignatures`` builds real signatures rather than
        placeholder bytes.

        The receiver only accepts an answer to a query it is waiting for, so
        the query is registered on it here. That is harness setup standing in
        for the resolve this scenario does not send: registering it is what
        makes the step test VERIFICATION rather than the relay bookkeeping,
        which has its own coverage.

        ``omit_last`` drops the final entry, which is the negative control the
        whole payload shape exists for: the answer stays internally consistent
        and every entry in it is genuine, but the window no longer reproduces
        the root a quorum signed.
        """
        holder = participants[from_id].impl.process
        holder_id = participants[from_id].impl.identity
        target = participants[payload['peer']].impl.identity.uuid
        qid = str(payload.get('query_id', 'q1'))
        window = holder.history._indexed_window()
        if not window:
            raise AssertionError(
                f'{from_id} has no committed window to answer with')
        # The checkpoint is built over the holder's ACTUAL window and signed
        # here by real keys, rather than taken from the `checkpoint` fixture:
        # that fixture installs a root and no co-signatures, and an answer
        # carrying an unsigned root would be refused for a reason the scenario
        # is not trying to test. Same principle as _cosignatures -- real
        # cryptography at scenario time.
        ckpt = Checkpoint(proposer_uuid=holder_id.uuid,
                          root=holder.history.window_root(),
                          epoch=int(payload.get('epoch', 1)),
                          first_index=window[0].index, count=len(window))
        cosigners = payload.get('cosigners') or [from_id]
        sigs = {}
        for pid in cosigners:
            if pid not in participants:
                raise AssertionError(f'cosigner {pid!r} not a known participant')
            ident = participants[pid].impl.identity
            sigs[str(ident.uuid)] = self._detached_sig(ident, ckpt.designation)
        signed = SignedCheckpoint(checkpoint=ckpt, sigs=sigs)
        signers = [public_identity_to_canonical(participants[pid].impl.identity)
                   for pid in cosigners]
        doc = resolved_to_dict(qid, target, window, signed, signers=signers,
                               score=payload.get('score'))
        if payload.get('omit_last') and doc['chain']:
            doc['chain'] = doc['chain'][:-1]
        receiver = participants[to_id].impl.process
        receiver._resolve_outstanding[qid] = (
            str(target), float('inf'))
        return doc

    def _half_elements(self, participants, payload, to_id, scorer_id,
                       task_id, score) -> tuple:
        """Elements 7 and 8 of a `committed` (R+D.md §14.2): whom the half
        names, and its scorer's signature over it. `names` defaults to the
        scorer of the half the recipient already pools for this task, else
        the recipient. Negative controls: `unsigned: true` omits the
        signature, `unnamed: true` the name, `half_forged_by: id` signs with
        that participant's key, `half_names: id` signs a half naming somebody
        other than the one sent, `half_score` signs another score. Mirrors
        the C adapter's _rp_half_elements."""
        names = payload.get('names')
        if names is None and to_id in participants:
            held = participants[to_id].impl.process.history.pooled(task_id)
            if held is not None and len(held) == 1:
                uid = str(held.p1_id if held.p1_id is not None else held.p2_id)
                names = next((pid for pid, h in participants.items()
                              if str(h.impl.identity.uuid) == uid), None)
            if names is None:
                names = to_id
        if names not in participants:
            raise AssertionError(f'names {names!r} not a known participant')
        scorer = participants[scorer_id].impl.identity
        named = participants[names].impl.identity.uuid
        signed_name = participants[payload.get('half_names', names)].impl.identity.uuid
        signer = participants[payload.get('half_forged_by', scorer_id)].impl.identity
        sig = None if payload.get('unsigned') else self._detached_sig(
            signer, half_designation(task_id, scorer.uuid, signed_name,
                                     _milli(payload['half_score'])
                                     if 'half_score' in payload else score,
                                     payload.get('channel')))
        return (None if payload.get('unnamed') else str(named), sig)

    #: A member no participant knows (roster specs). Mirrors the C adapter.
    STRANGER = ['5e5e5e5e-0000-4000-8000-000000000005', '55' * 32]

    def _roster_member(self, participants, pid):
        if pid == 'stranger':
            return list(self.STRANGER)
        from nacl.encoding import HexEncoder
        ident = participants[pid].impl.identity
        return [str(ident.uuid).lower(),
                ident.signature.public.encode(encoder=HexEncoder).decode('ascii')]

    def _roster_spec(self, participants, spec, base):
        """A roster entry from its spec (doc/architecture/reputation.md, "Who
        is in the group"): {roster: genesis, members: [pid...]}, {roster: add,
        member: pid[, key: hex]} or {roster: restate}, each optionally
        declaring `n_min: N`; an add or restate builds on the recipient's
        `roster` fixture (`base`). Mirrors the C adapter's _rp_roster_entry."""
        from autonomous_trust.core.reputation.reputation import (roster_digest,
                                                                 roster_task_id)
        op = spec['roster']
        who = None
        n_min = spec.get('n_min') or None
        if op == 'genesis':
            members = [self._roster_member(participants, p) for p in spec['members']]
            d = roster_digest(members)
            task = roster_task_id(None, 'genesis', None, d, n_min)
        else:
            members = [self._roster_member(participants, p) for p in base or []]
            prev = roster_task_id(None, 'genesis', None, roster_digest(members))
            if op == 'add':
                m = self._roster_member(participants, spec['member'])
                if spec.get('key'):
                    m[1] = spec['key']
                members = members + [m]
                who = m[0]
            d = roster_digest(members)
            task = roster_task_id(prev, op, who, d, n_min)
        return Transaction(task, roster_op=op,
                           roster_uuid=None if who is None else UUID(who),
                           roster_digest=d, roster_members=members,
                           roster_n_min=n_min)

    def _place_value(self, participants, payload, base=None):
        """A placement value from its spec: {task_id, p1, p1_score, p2,
        p2_score} entries, each half certified by `cosigners` (default every
        participant but the entry's two parties) unless `uncertified`, halves
        in canonical order unless `swap`, entries by task id unless the step
        says `unsorted`. Returns (entries, wire list). Mirrors the C adapter's
        _rp_place_value."""
        out = []
        for spec in payload.get('value') or []:
            if isinstance(spec.get('roster'), str):
                out.append(self._roster_spec(participants, spec, base))
                continue
            a, b = spec['p1'], spec['p2']
            ia = participants[a].impl.identity
            ib = participants[b].impl.identity
            task = uuid5(_NS, f'tx:{spec["task_id"]}')
            sa, sb = _milli(spec['p1_score']), _milli(spec['p2_score'])
            certs = None
            if not spec.get('uncertified'):
                signers = spec.get('cosigners') or [
                    pid for pid in participants if pid not in (a, b)]
                certs = {}
                for who, score in ((ia, sa), (ib, sb)):
                    certs[str(who.uuid)] = {
                        str(participants[pid].impl.identity.uuid):
                            self._detached_sig(participants[pid].impl.identity,
                                               commit_designation(who.uuid, task, score))
                        for pid in signers}
            # Each scorer signs its own half naming the other (R+D.md §14.2),
            # unless the spec says `unsigned`.
            halves = None if spec.get('unsigned') else {
                str(ia.uuid): self._detached_sig(
                    ia, half_designation(task, ia.uuid, ib.uuid, sa)),
                str(ib.uuid): self._detached_sig(
                    ib, half_designation(task, ib.uuid, ia.uuid, sb))}
            tx = placement_entry(Transaction(task, p1_id=ia.uuid, p1_score_milli=sa,
                                             p2_id=ib.uuid, p2_score_milli=sb,
                                             commit_sigs=certs,
                                             half_sigs=halves))
            if spec.get('swap'):
                tx.p1_id, tx.p2_id = tx.p2_id, tx.p1_id
                tx.p1_score_milli, tx.p2_score_milli = (tx.p2_score_milli,
                                                        tx.p1_score_milli)
            out.append(tx)
        out.sort(key=lambda tx: str(tx.task_id).lower())
        if payload.get('unsorted'):
            out.reverse()
        return out, [entry_to_dict(tx) for tx in out]

    def _place_body(self, participants, from_id, to_id, function, payload):
        """{group: '', k, ballot: {n, by}, head[, value]} or, for placed,
        {group: '', k, value, sigs}. `head` is a literal, '' by default, or
        `recipient` for the recipient's own head. `signers` name a placement
        certificate's signers (default every participant); `forged_by` makes
        one sign for all. Mirrors the C adapter."""
        k = int(payload.get('k', 0))
        head = payload.get('head', '')
        if head == 'recipient':
            head = participants[to_id].impl.process.history.head_hash.decode('ascii')
        body = {'group': '', 'k': k}
        if function != ReputationProtocol.placed:
            ballot = payload.get('ballot') or {}
            by = participants[ballot.get('by', from_id)].impl.identity.uuid
            body['ballot'] = {'n': int(ballot.get('n', 1)), 'by': str(by).lower()}
            body['head'] = head
        if function == ReputationProtocol.place_request:
            return body
        entries, wire = self._place_value(
            participants, payload,
            (getattr(self, '_fixture_roster', None) or {}).get(to_id))
        body['value'] = wire
        if function == ReputationProtocol.placed:
            desig = place_designation(k, head, place_value_digest(entries, k))
            signers = payload.get('signers') or list(participants)
            forger = payload.get('forged_by')
            by_key = participants[forger].impl.identity if forger else None
            body['sigs'] = {
                str(participants[pid].impl.identity.uuid):
                    self._detached_sig(by_key or participants[pid].impl.identity,
                                       desig)
                for pid in signers}
        return body

    def _build_inbound(self, participants: dict[str, ParticipantHandle], *,
                       from_id: str, to_id: str, function: str,
                       payload: dict[str, Any]) -> Message:
        sender = participants[from_id].impl
        sender_identity = sender.identity
        recipient = participants[to_id].impl.identity if to_id != 'broadcast' else None

        # Paxos id-tuple convention used by the request/grant/transaction/
        # accepted family. peer_id refers to the *requestor* (the proposer
        # who originated the round). For grant/accepted, the requestor is
        # also the recipient of the response — it's the one the granter
        # is responding to.
        proposer_id = payload.get('proposer', from_id)
        if proposer_id not in participants:
            raise AssertionError(f'proposer {proposer_id!r} not a known participant')
        proposer_uuid = participants[proposer_id].impl.identity.uuid

        if function == ReputationProtocol.rep_resolve:
            # A query names a peer and nothing else -- deliberately no originator, which
            # is the opacity property (doc/architecture/gateway-reputation-tree.md).
            target = participants[payload['peer']].impl.identity.uuid
            obj = to_json_string(resolve_query_to_dict(
                str(payload.get('query_id', 'q1')), target,
                ttl=int(payload.get('ttl', RESOLVE_TTL_DEFAULT))))
        elif function == ReputationProtocol.rep_resolved:
            obj = to_json_string(self._resolved_answer(participants,
                                                       from_id, to_id, payload))
        elif function in ReputationProtocol.retired:
            # A verb of the retired half round, as a build that still runs it
            # sends one: [id1, id2, proposer]. Mirrors the C adapter.
            obj = to_json_string((int(payload.get('id1', 1)),
                                  int(payload.get('id2', 1)), proposer_uuid))
        elif function == ReputationProtocol.transaction:
            # The proposal's wire shape is a JSON object with named fields, the
            # same body the C adapter builds, so one scenario puts identical
            # bytes on the wire in both runtimes.
            body = {'id1': int(payload['id1']), 'id2': int(payload['id2']),
                    'peer_uuid': proposer_uuid,
                    'score_milli': _milli(payload.get('score', 1.0))}
            # The evidence channel goes through verbatim (R+D.md §12.8), so a
            # scenario can send a bogus one and assert both twins refuse it.
            # Absent means "task outcome", the pre-channel behavior.
            if payload.get('channel') is not None:
                body['channel'] = payload['channel']
            # A proposer asks for certification and names its group ('' is the
            # primary). `certify: false` or `placing: false` leaves one off, to
            # stand for a half-round build's proposal, which is dropped.
            if payload.get('certify', True) is True:
                body['certify'] = True
            if payload.get('placing', True) is True:
                # `group: cohort` names the anchored cohort (RD_14.4 Phase 6).
                body['group'] = (str(_COHORT_UUID)
                                 if payload.get('group') == 'cohort' else '')
            if payload.get('task_id') is not None:
                body['task_uuid'] = str(uuid5(_NS, f'tx:{payload["task_id"]}'))
            obj = to_json_string(body)
        elif function == ReputationProtocol.accepted:
            tup = (int(payload['id1']), int(payload['id2']), proposer_uuid)
            if payload.get('signed') is True:
                # The acceptor's signature over the half's commit_designation
                # (doc/architecture/reputation.md, "Commit certificates"). Only a SOURCE step builds here; a
                # response step re-delivers the real message, which is why the
                # C adapter needs these same keys to rebuild it.
                task_id = uuid5(_NS, f'tx:{payload.get("task_id", "default")}')
                tup = tup + (self._detached_sig(
                    sender_identity, commit_designation(
                        proposer_uuid, task_id, _milli(payload.get('score', 1.0)),
                        payload.get('channel'))),)
            obj = to_json_string(tup)
        elif function == ReputationProtocol.committed:
            # Phase 3 broadcast — (task_id, peer_id, score, group_uuid,
            # channel).  Mirrors repprocess.py's commit_msg payload in
            # handle_accepted, which appends both trailing elements the same
            # length-tolerant way. A scenario that names no channel sends the
            # legacy 3-tuple, so every pre-channel vector is unchanged.
            # UUID objects, not strings: `ConfigJSONEncoder` round-trips them
            # with a `__type__` tag, so the handler receives the same types
            # production puts in (`repprocess.handle_accepted` passes
            # `score.task_id` and `peer_id` unchanged). Stringifying here made
            # the task key a `str` while a staged fixture keyed the same task
            # by `UUID` -- two entries for one task, so an arriving commit
            # could never complete a staged one.
            task_id = uuid5(_NS, f'tx:{payload.get("task_id", "default")}')
            tup = (task_id, proposer_uuid, _milli(payload.get('score', 1.0)))
            if payload.get('channel') is not None:
                tup = tup + (None, str(payload['channel']))
            if 'cosigners' in payload or 'forged_by' in payload:
                # A commit certificate (doc/architecture/reputation.md, "Commit certificates"): real
                # signatures over commit_designation, built at scenario time.
                # Only when the scenario names one. Mirrors the C adapter.
                if len(tup) == 3:
                    tup = tup + (None, payload.get('channel'))
                # certified_score: the certificate is cut over a DIFFERENT
                # score than the one committed (the binding's negative control).
                tup = tup + (self._cosignatures(
                    participants, payload, commit_designation(
                        proposer_uuid, task_id,
                        _milli(payload['certified_score'])
                        if 'certified_score' in payload else tup[2],
                        payload.get('channel'))),)
                tup = tup + self._half_elements(participants, payload, to_id,
                                                proposer_id, task_id, tup[2])
            obj = to_json_string(tup)
        elif function == ReputationProtocol.outdated:
            obj = str(payload.get('length', 0))
        elif function == ReputationProtocol.update:
            # Phase 1: optionally carry a real hash-linked chain so a
            # catch-up scenario can exercise verify-on-replay. The payload's
            # `chain` is a list of {task, p1, p2} committed entries; the
            # adapter builds them through a temp TransactionHistory so the
            # prev_hash links are computed by the production code. With
            # `tamper: true`, a committed score is mutated AFTER linking, so
            # the successor's recorded prev_hash no longer matches and the
            # receiver's catchup must reject the whole segment. Default
            # (no `chain`) stays the empty-chain no-crash case.
            spec = payload.get('chain') if isinstance(payload, dict) else None
            if not spec:
                obj = to_json_string([])
            else:
                from autonomous_trust.core.reputation.reputation import (
                    TransactionHistory)
                tmp = TransactionHistory(max_chain_len=max(len(spec) + 1, 2))
                def _part_uuid(other):
                    return (participants[other].impl.identity.uuid
                            if other in participants else None)
                # certified_by: [ids] certifies both halves of an entry with
                # those participants' signatures (doc/architecture/reputation.md,
                # "Commit certificates"); batch / placed_by write placements.
                _write_chain(tmp, spec, _part_uuid,
                             lambda ids, desig: self._cosignatures(
                                 participants, {'cosigners': ids}, desig),
                             lambda pid: self._roster_member(participants, pid),
                             getattr(self, '_chain_parties', None))
                built = list(tmp)
                if payload.get('tamper') and len(built) >= 2:
                    # Any other valid score: the link, not the range
                    # check, is what must catch it. Mirrors the C adapter.
                    built[1].p2_score_milli = (built[1].p2_score_milli + 1) % 1001
                # from: N sends the chain from its Nth entry on, as a peer whose
                # window has moved past the start would.
                built = built[int(payload.get('from') or 0):]
                # to: N stops before the Nth entry (with from, one page's
                # slice of a window).
                if payload.get('to') is not None:
                    built = built[:int(payload['to']) - int(payload.get('from') or 0)]
                # page / of / head: send it as one page of a paged window
                # (ISSUES §2.67), as a responder over the page size would.
                if payload.get('page') is not None:
                    obj = to_json_string({'page': payload['page'],
                                          'of': payload.get('of'),
                                          'head': payload.get('head', 'h'),
                                          'chain': built})
                else:
                    obj = to_json_string(built)
        elif function in (ReputationProtocol.rep_req,
                          ReputationProtocol.consensus_rep_req):
            # Canonical wire form (BUGS.md §P9B): JSON object with named
            # fields, matching C's `handle_rep_request`. Python's
            # `handle_reputation_request` now accepts both the object form
            # and the legacy tuple form, so both languages parse the same
            # bytes — wire interop is restored. consensus_rep_req takes
            # the identical payload (peer_uuid + requesting_process); the
            # op name alone selects the consensus computation path.
            target_pid = payload.get('target', from_id)
            if target_pid in participants:
                target_uuid = str(participants[target_pid].impl.identity.uuid)
            else:
                target_uuid = target_pid
            req_proc = payload.get('proc', 'negotiation')
            obj = to_json_string({
                'peer_uuid': target_uuid,
                'requesting_process': req_proc,
            })
        elif function == ReputationProtocol.app_roster_request:
            # The app pulling the current peer view. The verb carries no
            # payload at all: it names no subject, because the answer is the
            # whole roster (doc/architecture/app-peer-carrier.md).
            obj = to_json_string({})
        elif function == ReputationProtocol.consensus_rep_batch_req:
            # Batched consensus request: one message naming MANY subjects,
            # answered with one roster. Same fields as the single-subject form
            # but plural (`peer_uuids`), and both adapters build these identical
            # bytes so cross-language wire interop is pinned here too. `targets`
            # is a list of participant ids; a non-participant id passes through
            # verbatim so a scenario can name an unknown uuid deliberately.
            target_pids = payload.get('targets') or [payload.get('target', from_id)]
            uuids = []
            for target_pid in target_pids:
                if target_pid in participants:
                    uuids.append(str(participants[target_pid].impl.identity.uuid))
                else:
                    uuids.append(target_pid)
            obj = to_json_string({
                'peer_uuids': uuids,
                'requesting_process': payload.get('proc', 'negotiation'),
            })
        elif function in (ReputationProtocol.slash_propose,
                          ReputationProtocol.slash_sign,
                          ReputationProtocol.slash_final):
            # Slashing — Python's native shapes (per-implementation;
            # byte_pinning:false checks state equivalence). propose/final
            # carry a SlashAttestation / SignedSlash (Configuration);
            # sign is a (target, epoch, voter, sig) tuple. The slasher is
            # the proposer so a node receiving slash_final (self != slasher)
            # applies the floor rather than self-skipping.
            target_pid = payload.get('target', from_id)
            target_uuid = (str(participants[target_pid].impl.identity.uuid)
                           if target_pid in participants else target_pid)
            floor = _milli(payload.get('floor_score', 0.0))
            epoch = int(payload.get('epoch', 1))
            reason = payload.get('reason',
                                 SlashAttestation.REASON_PEER_EXCLUDE)
            att = SlashAttestation(
                slasher_uuid=str(proposer_uuid), target_uuid=target_uuid,
                reason=reason, floor_milli=floor, epoch=epoch)
            if function == ReputationProtocol.slash_sign:
                # Co-signatures are SIGNED HERE, at scenario time, by the
                # sending participant's own key -- not pinned as blobs -- so
                # both adapters are held to the same pre-image and scheme
                # rather than to one side's recorded output (the doc/architecture/zta-integration.md
                # precedent). The ack names its sender, because the receiver
                # credits the authenticated sender rather than the claim. The
                # sign step's payload must therefore describe the SAME round
                # as its propose (reason + floor_score + epoch): the
                # designation covers those fields, so a sign step that omits
                # them signs different bytes and is correctly refused.
                obj = to_json_string(
                    (target_uuid, epoch, str(sender_identity.uuid),
                     self._detached_sig(sender_identity, att.designation)))
            else:
                # Phase 3: optional Merkle evidence {task_id, leaf, proof,
                # root} tying the slash to a checkpoint-committed tx.
                if isinstance(payload, dict) and payload.get('evidence'):
                    att.evidence_ref = payload['evidence']
                if function == ReputationProtocol.slash_final:
                    sigs = self._cosignatures(participants, payload,
                                              att.designation,
                                              exclude=target_pid)
                    obj = to_json_string(SignedSlash(attestation=att,
                                                     sigs=sigs))
                else:
                    obj = to_json_string(att)
        elif function in (ReputationProtocol.attest_propose,
                          ReputationProtocol.attest_sign,
                          ReputationProtocol.attest_final):
            # Verifier-attested scores -- Python's native shapes (per-impl;
            # byte_pinning:false checks state equivalence). propose/final
            # carry an AttestedScore / SignedAttestation; sign is a
            # (task, voter, sig) tuple. The VERIFIER is the proposer (the
            # step's `from` for propose/final, its `to` for sign), so every
            # step of one round must name the same subject, score, channel and
            # digest: the designation covers them all.
            subject_pid = payload.get('subject')
            subject_uuid = (str(participants[subject_pid].impl.identity.uuid)
                            if subject_pid in participants else subject_pid)
            verifier_pid = payload.get(
                'verifier',
                to_id if function == ReputationProtocol.attest_sign else from_id)
            att = AttestedScore(
                verifier_uuid=str(participants[verifier_pid].impl.identity.uuid),
                subject_uuid=subject_uuid,
                score_milli=_milli(payload.get('score', 0.3)),
                channel=payload.get('channel', 'probe'),
                evidence_digest=payload.get('evidence_digest', 'ab' * 32),
                attest_scope=payload.get('scope'))
            if function == ReputationProtocol.attest_sign:
                obj = to_json_string(
                    (str(att.task_id), str(sender_identity.uuid),
                     self._detached_sig(sender_identity, att.designation)))
            elif function == ReputationProtocol.attest_final:
                sigs = self._cosignatures(participants, payload,
                                          att.designation,
                                          exclude=subject_pid)
                obj = to_json_string(SignedAttestation(attestation=att,
                                                       sigs=sigs))
            else:
                obj = to_json_string(att)
        elif function in (ReputationProtocol.checkpoint_propose,
                          ReputationProtocol.checkpoint_sign,
                          ReputationProtocol.checkpoint_final):
            # Phase 2 checkpoints — Python's native shapes (per-impl;
            # byte_pinning:false checks state equivalence). propose/final
            # carry a Checkpoint / SignedCheckpoint; sign is a
            # (proposer, epoch, voter, sig) tuple. The proposer is the sender
            # so a node receiving checkpoint_final (self != proposer) stores
            # the root rather than self-skipping. ``root`` is the agreed
            # window Merkle root as a hex string; carried as its ASCII bytes
            # so the stored value round-trips to the same hex the C twin
            # stores (the `checkpoint_root` observable).
            root_hex = payload.get('root', '')
            epoch = int(payload.get('epoch', 1))
            first_index = int(payload.get('first_index', 0))
            count = int(payload.get('count', 0))
            ck = Checkpoint(
                proposer_uuid=str(proposer_uuid),
                root=root_hex.encode('ascii') if isinstance(root_hex, str)
                else root_hex,
                epoch=epoch, first_index=first_index, count=count)
            if function == ReputationProtocol.checkpoint_sign:
                # Signed at scenario time by the sender, as for slash_sign.
                # The sign step's payload must name the same root / epoch /
                # bounds as its propose, since the designation covers them.
                obj = to_json_string(
                    (str(proposer_uuid), epoch, str(sender_identity.uuid),
                     self._detached_sig(sender_identity, ck.designation)))
            elif function == ReputationProtocol.checkpoint_final:
                sigs = self._cosignatures(participants, payload,
                                          ck.designation)
                obj = to_json_string(SignedCheckpoint(checkpoint=ck,
                                                      sigs=sigs))
            else:
                obj = to_json_string(ck)
        elif function in (ReputationProtocol.place_request,
                          ReputationProtocol.place, ReputationProtocol.placed):
            obj = to_json_string(self._place_body(participants, from_id, to_id,
                                                  function, payload))
        else:
            raise AssertionError(f'unsupported reputation function {function!r}')

        # An app verb comes from this node's own app, with no sender, unless
        # the step says it came off the wire (`from_wire: true`), which
        # production refuses (ISSUES §2.17). Mirrors the C adapter.
        if function.startswith('app_') and not payload.get('from_wire'):
            sender_identity = None
        msg = Message(
            CfgIds.reputation, function, obj,
            from_whom=sender_identity,
            to_whom=recipient,
            encrypt=True,
        )
        # handle_transaction / handle_accepted gate on message.verified;
        # the harness signs locally so set verified=True to mirror the
        # production "I just received a verified network message" state.
        msg.verified = True
        return msg


class _FakeDep:
    def __init__(self, name: str) -> None:
        self.name = name
