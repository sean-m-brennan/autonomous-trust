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
threaded paths (handle_grant -> _paxos_timeout, handle_nack -> _try_again,
handle_reputation_request -> _compute_reputation) execute inline.

Phase F covers the leaderless Byzantine multi-Paxos request/grant/transaction
flow plus the chain-length backdate and stale-id nack branches.
"""

from __future__ import annotations

import hashlib
import os
import queue
import tempfile
import threading
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from autonomous_trust.core.capabilities import PeerCapabilities
from autonomous_trust.core.config import Configuration, to_json_string
from autonomous_trust.core.identity import Group, Identity, Peers
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import (
    TransactionScore, SlashAttestation, SignedSlash,
    Checkpoint, SignedCheckpoint)
from autonomous_trust.core.system import CfgIds, PackageHash

from ...common.scenario_loader import Case
from ..scenario_engine import (
    CapturedMessage,
    ParticipantHandle,
    ScenarioContext,
    run_scenario,
)


_NS = UUID('00000000-0000-0000-0000-000000000aaa')


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
            elif key == 'last_id_set':
                actual = self.process.last_id is not None
                if actual != bool(expected):
                    raise AssertionError(
                        f'{self.id}: last_id_set={actual}, expected {expected}'
                    )
            elif key == 'requests_count':
                actual = len(self.process.requests)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: requests_count={actual}, expected {expected}'
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
            else:
                raise AssertionError(f'{self.id}: unsupported expected_state key {key!r}')


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
        # Preset state for handlers that gate on history length / last_id /
        # requests list — see scenario YAML keys for documentation.
        preset_history_len: dict[str, int] = fixtures.get('history_len', {}) or {}
        preset_last_id: dict[str, int] = fixtures.get('last_id', {}) or {}
        preset_requests: dict[str, list[list[int]]] = fixtures.get('requests', {}) or {}
        # my_requests pre-stages a proposer's outstanding paxos rounds. Each
        # entry: {id1, id2, task_id, score}. Required by handle_nack
        # / handle_grant to recognize the round and look up the score.
        preset_my_requests: dict[str, list[dict[str, Any]]] = fixtures.get('my_requests', {}) or {}
        # tx_history pre-stages bilateral Transactions in self.process.history.
        # { pid -> [ {task_id, p1, p1_score, p2, p2_score}, ... ] }. p1/p2
        # reference other participant ids; the adapter resolves them to
        # UUIDv5(rep:<pid>). Required by reputation_pure / _contrite_tft
        # to score against committed bilateral txs.
        preset_tx_history: dict[str, list[dict[str, Any]]] = fixtures.get('tx_history', {}) or {}
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
        # the group's address map.
        seed_pid = spec_participants[0]['id']
        group = Group(identities[seed_pid].uuid, {identities[seed_pid].uuid: identities[seed_pid].address},
                      'rep-grp', Encryptor.generate(), False)
        for spec in spec_participants[1:]:
            group.add_address(identities[spec['id']].uuid, identities[spec['id']].address)

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

            if pid in preset_last_id:
                participant.process.last_id = preset_last_id[pid]

            if pid in preset_num_updates:
                participant.process.num_updates = int(preset_num_updates[pid])

            if pid in preset_checkpoint:
                spec_ck = preset_checkpoint[pid]
                root = spec_ck.get('root', '')
                participant.process._checkpoint = Checkpoint(
                    proposer_uuid=identity.uuid,
                    root=root.encode('ascii') if isinstance(root, str) else root,
                    epoch=int(spec_ck.get('epoch', 1)),
                    first_index=int(spec_ck.get('first_index', 0)),
                    count=int(spec_ck.get('count', 0)))

            for r in preset_requests.get(pid, []):
                # Each preset request entry is [id1, id2] — pre-stage the
                # acceptor's `requests` list so handle_transaction's check
                # `if idx not in self.requests` passes.
                participant.process.requests.append(tuple(r))

            for entry in preset_my_requests.get(pid, []):
                from autonomous_trust.core.reputation.repprocess import TxCount
                idx = (int(entry['id1']), int(entry['id2']))
                score = TransactionScore(
                    task_id=str(uuid5(_NS, f'tx:{entry.get("task_id", "default")}')),
                    score=float(entry.get('score', 1.0)),
                )
                participant.process.my_requests[idx] = TxCount(score, 0)
                # Also stage the proposals dict so handle_grant /
                # handle_accepted can look up the score by idx.
                participant.process.proposals[idx] = score

            # tx_history: each entry installs a bilateral Transaction via
            # two history.update calls (matching how handle_committed
            # builds bilateral history in production). p1/p2 reference
            # participant ids; missing ids on either side are skipped.
            for entry in preset_tx_history.get(pid, []):
                slug = entry.get('task_id')
                p1_id = entry.get('p1')
                p2_id = entry.get('p2')
                if slug is None or p1_id not in identities or p2_id not in identities:
                    continue
                task_uuid = uuid5(_NS, f'tx:{slug}')
                participant.process.history.update(
                    task_uuid, identities[p1_id].uuid,
                    float(entry.get('p1_score', 0.0)))
                participant.process.history.update(
                    task_uuid, identities[p2_id].uuid,
                    float(entry.get('p2_score', 0.0)))

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

        if function == ReputationProtocol.request:
            tup = (int(payload['id1']), int(payload['id2']), proposer_uuid)
            obj = to_json_string(tup)
        elif function == ReputationProtocol.grant:
            id_tup = (int(payload['id1']), int(payload['id2']), proposer_uuid)
            last_id = payload.get('last_id')
            last_idx = int(payload.get('last_idx', 0))
            last_val = payload.get('last_val')
            ack = (id_tup, (last_id, last_idx), last_val)
            obj = to_json_string(ack)
        elif function in (ReputationProtocol.nack, ReputationProtocol.backdate):
            tup = (int(payload['id1']), int(payload['id2']), proposer_uuid)
            obj = to_json_string(tup)
        elif function == ReputationProtocol.transaction:
            id_tup = (int(payload['id1']), int(payload['id2']), proposer_uuid)
            score = TransactionScore(
                task_id=str(uuid5(_NS, f'tx:{payload.get("task_id", "default")}')),
                score=float(payload.get('score', 1.0)),
            )
            obj = to_json_string((id_tup, score))
        elif function == ReputationProtocol.accepted:
            tup = (int(payload['id1']), int(payload['id2']), proposer_uuid)
            obj = to_json_string(tup)
        elif function == ReputationProtocol.committed:
            # Phase 3 broadcast — (task_id, peer_id, score).  Mirrors
            # repprocess.py's commit_msg payload in handle_accepted.
            task_id = str(uuid5(_NS, f'tx:{payload.get("task_id", "default")}'))
            obj = to_json_string((task_id, proposer_uuid,
                                  float(payload.get('score', 1.0))))
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
                for entry in spec:
                    tk = uuid5(_NS, f"chain:{entry['task']}")
                    p1 = uuid5(_NS, f"chainp1:{entry['task']}")
                    p2 = uuid5(_NS, f"chainp2:{entry['task']}")
                    tmp.update(tk, p1, float(entry['p1']))
                    tmp.update(tk, p2, float(entry['p2']))
                built = list(tmp)
                if payload.get('tamper') and len(built) >= 2:
                    built[1].p2_score = -1.0
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
            floor = float(payload.get('floor_score', 0.0))
            epoch = int(payload.get('epoch', 1))
            reason = payload.get('reason',
                                 SlashAttestation.REASON_PEER_EXCLUDE)
            att = SlashAttestation(
                slasher_uuid=str(proposer_uuid), target_uuid=target_uuid,
                reason=reason, floor_score=floor, epoch=epoch)
            if function == ReputationProtocol.slash_sign:
                # Co-signatures are SIGNED HERE, at scenario time, by the
                # sending participant's own key -- not pinned as blobs -- so
                # both adapters are held to the same pre-image and scheme
                # rather than to one side's recorded output (the §1.5
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
        else:
            raise AssertionError(f'unsupported reputation function {function!r}')

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
