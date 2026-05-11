# ******************
#  Copyright 2026 Sean M. Brennan and contributors
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
from autonomous_trust.core.reputation.reputation import TransactionScore
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

    def drain_outbox(self) -> list[CapturedMessage]:
        captured: list[CapturedMessage] = []
        for msg in self.outbox_buffer:
            captured.append(_to_captured(msg, emitter_id=self.id))
        self.outbox_buffer.clear()
        return captured

    def _check_expected_state(self, asserts: dict[str, Any]) -> None:
        for key, expected in asserts.items():
            if key == 'history_len':
                actual = len(self.process.history)
                if actual != expected:
                    raise AssertionError(
                        f'{self.id}: history_len={actual}, expected {expected}'
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
        return getattr(to, 'nickname', '') or str(to.uuid)
    if isinstance(to, Group):
        return 'broadcast'
    if isinstance(to, list) and to:
        first = to[0]
        return getattr(first, 'nickname', '') or str(getattr(first, 'uuid', first))
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

        identities: dict[str, Identity] = {}
        for idx, spec in enumerate(spec_participants):
            pid = spec['id']
            sig = hashlib.sha256(b'rep:sig:' + pid.encode()).hexdigest().encode('ascii')
            enc = hashlib.sha256(b'rep:enc:' + pid.encode()).hexdigest().encode('ascii')
            identity = Identity(
                uuid5(_NS, f'rep:{pid}'), f'10.0.60.{idx + 1}',
                f'{pid}.rep', pid,
                Signature(sig, public_only=False),
                Encryptor(enc, public_only=False),
                'me', False, 0, 'authority',
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

            handles[pid] = ParticipantHandle(
                id=pid, role=role, impl=participant,
                dispatch=lambda msg, p=participant: self._dispatch(p, msg),
            )
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
        elif function == ReputationProtocol.outdated:
            obj = str(payload.get('length', 0))
        elif function == ReputationProtocol.update:
            obj = to_json_string([])  # empty chain by default
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
