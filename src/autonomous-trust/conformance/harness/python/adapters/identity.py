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

"""Identity-protocol adapter for the AT conformance corpus (Phase C).

Drives `kind: scenario` cases: builds real `IdentityProcess` instances
(with mocked subsystems and synchronous_dispatch flipped on so threading
becomes deterministic), feeds each step's inbound through the protocol's
handler registry, and captures every outbound message via shimmed queues.

Phase C wires the canonical new-node-admission flow plus an amnesia path.
Wire / crypto / negative kinds for the identity protocol are out of scope.
"""

from __future__ import annotations

import logging
import os
import queue
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

from autonomous_trust.core.algorithms.impl import AgreementImpl
from autonomous_trust.core.capabilities import Capabilities, PeerCapabilities
from autonomous_trust.core.config import Configuration, to_json_string
from autonomous_trust.core.identity import Group, Identity, Peers
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.identity.sign import Signature
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


@dataclass
class _Participant:
    """Wraps an IdentityProcess and the captured outbox for a participant."""
    id: str
    role: str
    identity: Identity
    process: IdentityProcess
    queues: dict[str, Any]
    outbox_buffer: list[Message] = field(default_factory=list)

    def drain_outbox(self) -> list[CapturedMessage]:
        captured: list[CapturedMessage] = []
        for msg in self.outbox_buffer:
            captured.append(_to_captured(msg, emitter_id=self.id))
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
            else:
                raise AssertionError(f'{self.id}: unsupported expected_state key {key!r}')


def _to_captured(msg: Any, emitter_id: str) -> CapturedMessage:
    """Project a network-bound `Message` into the engine's CapturedMessage."""
    if not isinstance(msg, Message):
        # Non-Message items (Group, Peers, PeerCapabilities updates) are
        # internal IPC traffic; surface them with a synthetic function name
        # so the engine ignores them in matching but they aren't lost.
        return CapturedMessage(
            from_id=emitter_id, to_id='internal',
            function=f'__ipc__/{type(msg).__name__}', payload=msg, raw=msg,
        )
    to_id = _resolve_to_id(msg)
    return CapturedMessage(
        from_id=emitter_id,
        to_id=to_id,
        function=msg.function,
        payload=msg.obj,
        raw=msg,
    )


def _resolve_to_id(msg: Message) -> str:
    """Map a Message's to_whom into a scenario-level participant id."""
    to = msg.to_whom
    if to == Network.broadcast:
        return 'broadcast'
    if isinstance(to, Group):
        return 'broadcast'  # group-encrypted broadcast; engine treats both alike
    if isinstance(to, Identity):
        return getattr(to, 'nickname', '') or str(to.uuid)
    if isinstance(to, list) and to:
        first = to[0]
        return getattr(first, 'nickname', '') or str(getattr(first, 'uuid', first))
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
                uuid, address, f'{pid}.scenario', pid,
                Signature(sig_seed, public_only=False),
                Encryptor(enc_seed, public_only=False),
                'me', False, 0, _DEFAULT_BLOCK_IMPL,
            )
            identities[pid] = identity

        # All participants except the newcomer share the same group key in
        # Phase C scenarios. Newcomer is detected as the participant with role
        # `new_node`, mirroring the canonical scenario's role naming.
        newcomer_pid = next(
            (s['id'] for s in spec_participants if s.get('role') == 'new_node'),
            None,
        )
        existing_pids = [s['id'] for s in spec_participants if s['id'] != newcomer_pid]
        group: Group | None = None
        if existing_pids:
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
            for other_pid in existing_pids:
                if other_pid == pid:
                    continue
                peers.add(identities[other_pid])
            if amnesia_known and pid in existing_pids and newcomer_pid is not None:
                peers.add(identities[newcomer_pid])
            participant = self._build_one(pid, role, identity, peers, group)
            # Install own-capability allowlist from fixtures.capabilities;
            # mirrors the C adapter's `identity_set_own_capabilities`
            # plumbing. handle_caps_query reads
            # `self.capabilities.to_list()` and emits it as a JSON-array
            # caps_response payload.
            cap_fix: dict[str, list[str]] = fixtures.get('capabilities', {}) or {}
            for cap_name in cap_fix.get(pid, []):
                participant.process.protocol.capabilities.register_ability(
                    cap_name, None, [], {})
            handles[pid] = ParticipantHandle(
                id=pid, role=role, impl=participant,
                dispatch=lambda msg, p=participant: self._dispatch(p, msg),
            )
        return handles

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

    def _build_one(self, pid: str, role: str, identity: Identity,
                   peers: Peers, group: Group | None) -> _Participant:
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
            original_put(item, *args, **kwargs)

        queues[CfgIds.network].put = _record_and_put  # type: ignore[method-assign]

        return captured

    # ------------------------------------------------------------------
    # Step driver
    # ------------------------------------------------------------------

    def _dispatch(self, participant: _Participant, inbound: Any) -> list[CapturedMessage]:
        if not isinstance(inbound, Message):
            raise AssertionError(f'expected a Message, got {type(inbound).__name__}')
        # The protocol's handler dispatch is run synchronously. Threads
        # spawned via _spawn() are inlined because synchronous_dispatch is on.
        participant.process.protocol.run_message_handlers(participant.queues, inbound)
        return participant.drain_outbox()

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
            # (identity, package_hash, capabilities_list)
            caps_list = payload.get('capabilities', [])
            obj = to_json_string((sender_identity.publish(),
                                  self._package_hash, caps_list))
        elif function == IdentityProtocol.accept:
            caps_list = payload.get('capabilities', [])
            obj = to_json_string((sender_identity.publish(),
                                  self._package_hash, caps_list))
        elif function == IdentityProtocol.confirm:
            target_pid = payload.get('peer') or payload.get('candidate')
            target = participants[target_pid].impl.identity
            from autonomous_trust.core.identity.history import IdentityObj
            blob = IdentityObj(target.publish(), target.uuid)
            obj = blob.to_string()
        elif function == IdentityProtocol.update:
            target_group = sender.process.group
            obj = target_group.to_string() if target_group else ''
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
            # handle_caps_response parses `from_json_string(message.obj)`
            # as a list of capability names. Build that native form.
            caps_list = payload.get('caps', []) if isinstance(payload, dict) else []
            obj = to_json_string(caps_list)
        else:
            obj = to_json_string(payload)

        msg = Message(CfgIds.identity, function, obj,
                      from_whom=sender_identity,
                      to_whom=Network.broadcast if to_id == 'broadcast' else None,
                      encrypt=(function != IdentityProtocol.announce))
        return msg


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
