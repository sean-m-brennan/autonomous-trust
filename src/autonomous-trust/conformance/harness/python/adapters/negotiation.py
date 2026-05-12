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

"""Negotiation-protocol adapter for the AT conformance corpus (Phase E).

Drives `kind: scenario` for `protocol: negotiation`. Constructs real
NegotiationProcess instances per participant, mocks subsystems and queues,
and wires the existing scenario engine — same shape as the IdentityAdapter,
minus the synchronous_dispatch hook (Negotiation handlers are already
synchronous; no Thread().start() in the inner handlers).

Phase E covers: invitation/acceptance/refusal happy paths and the haggle
counter-proposal cycle. status_req/status_resp and result-forwarding paths
are out of scope for this pass.
"""

from __future__ import annotations

import hashlib
import os
import queue
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from autonomous_trust.core.capabilities import Capabilities, Capability, PeerCapabilities
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Group, Identity, Peers
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.negotiation.negotiation import Task, TaskParameters, TaskResult, TaskStatus
from autonomous_trust.core.negotiation.negprocess import NegotiationProcess
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
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
                 process: NegotiationProcess, queues: dict[str, Any]) -> None:
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
            if key == 'has_my_task':
                # `expected` is a slug; derive the same task uuid the
                # adapter mints in `_build_inbound`
                # (`uuid5(_NS, f'task:{slug}')`) and look it up in
                # process.my_tasks. The prior literal-string comparison
                # never matched a slug against uuid strings — fixed
                # alongside the symmetric C-side `has_my_task` accessor
                # so the two adapters agree on what this key means.
                want_uuid = uuid5(_NS, f'task:{expected}')
                if want_uuid not in self.process.my_tasks:
                    raise AssertionError(
                        f'{self.id}: my_tasks does not contain task uuid '
                        f'{want_uuid} (slug {expected!r}); have '
                        f'{sorted(str(u) for u in self.process.my_tasks)}'
                    )
            elif key == 'confirmed':
                if not self.process.confirmed:
                    raise AssertionError(f'{self.id}: confirmed map is empty')
            elif key == 'task_in_stack':
                actual = any(True for _ in self.process.task_stack._heap)
                if actual != bool(expected):
                    raise AssertionError(
                        f'{self.id}: task_in_stack={actual}, expected {expected}'
                    )
            elif key == 'flood_count':
                # `expected` is {task: <slug>, count: <int>}. Derive the
                # same task uuid `_build_inbound` mints from the slug and
                # read `flood_counts[uuid]` — the per-task flood counter
                # `handle_invite` increments on each observed invite.
                # Mirrors the C accessor
                # `negotiation_get_task_flood_count`, which reads the
                # symmetric "flood:<uuid>" key from `proposed_tasks`.
                if not isinstance(expected, dict):
                    raise AssertionError(
                        f'{self.id}: flood_count expects '
                        f'{{task: <slug>, count: <int>}}, got {expected!r}'
                    )
                slug = expected.get('task')
                want = expected.get('count')
                if not isinstance(slug, str) or not isinstance(want, int):
                    raise AssertionError(
                        f'{self.id}: flood_count requires task=<slug> and '
                        f'count=<int>, got {expected!r}'
                    )
                want_uuid = uuid5(_NS, f'task:{slug}')
                got = self.process.flood_counts.get(want_uuid, 0)
                if got != want:
                    raise AssertionError(
                        f'{self.id}: flood_count for slug {slug!r} '
                        f'(uuid={want_uuid}) = {got}, expected {want}'
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
    if isinstance(to, list) and to:
        first = to[0]
        return getattr(first, 'nickname', '') or str(getattr(first, 'uuid', first))
    return 'broadcast'


class NegotiationAdapter:
    """Phase E scenario adapter for the negotiation protocol."""

    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root
        self._scratch: tempfile.TemporaryDirectory | None = None
        self._package_hash = PackageHash().digest
        # Slug -> UUID, populated as scenarios reference task slugs.
        self._task_uuids: dict[str, UUID] = {}

    def run_scenario(self, case: Case) -> None:
        self._scratch = tempfile.TemporaryDirectory(prefix='at-conformance-neg-')
        self._task_uuids = {}
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
        raise NotImplementedError('negotiation wire_vector kind not implemented (Phase E: scenarios only)')

    def run_crypto_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('negotiation does not own crypto vectors')

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
        cap_fix: dict[str, list[str]] = fixtures.get('capabilities', {}) or {}
        # Levels: peer-id -> level integer (0 = lowest reputation, 1 = mid).
        level_fix: dict[str, int] = fixtures.get('peer_levels', {}) or {}

        identities: dict[str, Identity] = {}
        for idx, spec in enumerate(spec_participants):
            pid = spec['id']
            sig = hashlib.sha256(b'neg:sig:' + pid.encode()).hexdigest().encode('ascii')
            enc = hashlib.sha256(b'neg:enc:' + pid.encode()).hexdigest().encode('ascii')
            identity = Identity(
                uuid5(_NS, f'neg:{pid}'), f'10.0.50.{idx + 1}',
                f'{pid}.neg', pid,
                Signature(sig, public_only=False),
                Encryptor(enc, public_only=False),
                'me', False, 0, 'authority',
            )
            identities[pid] = identity

        handles: dict[str, ParticipantHandle] = {}
        for spec in spec_participants:
            pid = spec['id']
            role = spec['role']
            identity = identities[pid]

            # Each participant's peers list contains every OTHER participant.
            peers = Peers()
            for other_pid, other_id in identities.items():
                if other_pid == pid:
                    continue
                level = level_fix.get(other_pid)
                if level is None:
                    peers.add(other_id)
                else:
                    peers.add(other_id, level=level)

            # peer_capabilities: which peers can do what. Each YAML capability
            # mapping {peer_id: [cap_name, ...]} populates the requester's view.
            pcap = PeerCapabilities()
            for peer_pid, caps in cap_fix.items():
                if peer_pid == pid:
                    continue
                pcap.register(str(identities[peer_pid].uuid), caps)

            # Local capabilities: what THIS participant can do (drives
            # invitation accept/refuse).
            own_caps = Capabilities()
            for own_cap in cap_fix.get(pid, []):
                own_caps.register_ability(own_cap, None, [], {})

            participant = self._build_one(pid, role, identity, peers, pcap, own_caps)
            handles[pid] = ParticipantHandle(
                id=pid, role=role, impl=participant,
                dispatch=lambda msg, p=participant: self._dispatch(p, msg),
            )
        return handles

    def _build_one(self, pid: str, role: str, identity: Identity, peers: Peers,
                   pcap: PeerCapabilities, own_caps: Capabilities) -> _Participant:
        net_sink: list[Any] = []
        main_sink: list[Any] = []
        id_sink: list[Any] = []
        neg_sink: list[Any] = []

        queues = {
            CfgIds.negotiation: _CapturingQueue(neg_sink),
            CfgIds.network: _CapturingQueue(net_sink),
            CfgIds.main: _CapturingQueue(main_sink),
            CfgIds.identity: _CapturingQueue(id_sink),
        }

        configurations = {
            CfgIds.identity: identity,
            CfgIds.peers: peers,
            CfgIds.capabilities: pcap,
            PackageHash.key: self._package_hash,
            'processes': [
                _FakeDep(CfgIds.network),
                _FakeDep(CfgIds.identity),
            ],
        }

        process = NegotiationProcess(
            configurations,
            ProcessTracker(),
            log_q=queue.Queue(),
            suppress_log=True,
        )
        process.protocol.capabilities = own_caps
        process.lock = threading.RLock()

        captured = _Participant(
            pid=pid, role=role, identity=identity,
            process=process, queues=queues,
        )

        # Hook the network queue. Every Message put becomes a record AND a
        # delivery candidate. Non-Message items (Status updates, etc.)
        # are surfaced via _to_captured's `__ipc__/...` path.
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

        # Slug-based task-uuid resolution: scenarios refer to tasks by slug
        # so cross-step state matches across both sides of a haggle, etc.
        slug = payload.get('task_id', 'default-task')
        task_uuid = self._task_uuids.setdefault(slug, uuid5(_NS, f'task:{slug}'))

        capability_name = payload.get('capability', 'noop')
        cap = Capability(capability_name, None, [], {})

        # Optional `when_offset_secs` lets scenarios pin the parameters.when
        # field — useful for the haggle path where the requester's original
        # `when` is compared against the responder's counter-proposal.
        offset = float(payload.get('when_offset_secs', 0))
        when = datetime.now(timezone.utc) + timedelta(seconds=offset)
        flexible = bool(payload.get('flexible', True))
        params = TaskParameters(cap, _flexible=flexible, when=when)

        if function == 'spawn task':
            task = Task(params, sender_identity, uuid=task_uuid)
            obj = task
        elif function in ('invitation', 'haggle', 'ack', 'nack', 'status request'):
            requestor = recipient if function == 'invitation' else sender_identity
            task = Task(params, requestor, uuid=task_uuid)
            obj = task
        elif function == 'status response':
            from autonomous_trust.core.negotiation.negotiation import Status
            requestor = recipient or sender_identity
            base_task = Task(params, requestor, uuid=task_uuid)
            ts = TaskStatus(task=base_task, status=Status[payload.get('status', 'running')])
            obj = ts
        elif function == 'report results':
            requestor = recipient or sender_identity
            base_task = Task(params, requestor, uuid=task_uuid)
            obj = TaskResult(task=base_task, result=payload.get('result'))
        else:
            raise AssertionError(f'unsupported negotiation function {function!r}')

        msg = Message(
            CfgIds.negotiation, function, obj,
            from_whom=sender_identity,
            to_whom=recipient,
            encrypt=True,
        )
        return msg


class _FakeDep:
    def __init__(self, name: str) -> None:
        self.name = name
