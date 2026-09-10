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

"""Network-protocol adapter for the AT conformance corpus (Phase A).

Handles two case kinds for `protocol: network`:

  - kind: wire_vector   -> exercises encode/decode at the wire boundary
                           (Message and Configuration-subclass round-trips).
  - kind: crypto_vector -> exercises Ed25519 sign/verify and NaCl Box /
                           SecretBox primitives directly via PyNaCl.

State-machine and negative kinds for the network protocol are out of scope
for Phase A and raise NotImplementedError so the runner records them as skip.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

from ...common.canonical import canonicalize
from ...common.scenario_loader import Case, hex_to_bytes, load_testdata_bytes


class NetworkAdapter:
    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    # ------------------------------------------------------------------
    # Wire vectors
    # ------------------------------------------------------------------

    def run_wire_vector(self, case: Case) -> None:
        spec = case.data
        constructor = spec.get('constructor')
        if not constructor:
            raise AssertionError(f'wire_vector missing required field: constructor')
        input_args = self._resolve_input(spec.get('input', {}))

        formats = self._iter_formats(spec.get('wire_format', 'any'))
        modes = self._iter_modes(spec.get('serialize_mode', 'any'))

        # Drive the round-trip across every requested (mode, format) cell.
        # Equivalence checks happen in _round_trip; iteration here proves
        # the impl handles each cell without coupling any of them.
        for mode in modes:
            for fmt in formats:
                self._round_trip(constructor, input_args, mode=mode,
                                 wire_format=fmt, spec=spec)

    def _assert_byte_pin(self, spec: dict[str, Any], actual: bytes, label: str) -> None:
        """Compare implementation-emitted bytes to a JCS-canonical fixture.

        Only fires when the scenario opts in via `byte_pinning: true` AND
        provides `expected.json_wire`. Both inputs are canonicalised before
        comparison so an implementation emitting semantically-equal-but-not-
        byte-equal JSON (different key order, integer vs `.0`, etc.) still
        passes — the contract is canonical-form equality, not lexical.
        """
        if not spec.get('byte_pinning'):
            return
        expected_path = (spec.get('expected') or {}).get('json_wire')
        if not expected_path:
            return
        expected = canonicalize(load_testdata_bytes(self.corpus_root, expected_path))
        actual_canonical = canonicalize(actual)
        if actual_canonical != expected:
            raise AssertionError(
                f'{label}: wire bytes diverge from pinned fixture '
                f'{expected_path!r}\n  expected: {expected!r}\n  actual:   {actual_canonical!r}'
            )

    def _assert_proto_byte_pin(self, spec: dict[str, Any], actual: bytes,
                               label: str) -> None:
        """Compare emitted proto-envelope bytes to the vector's inline hex.

        Compared LITERALLY, unlike the JSON pin's canonical-form comparison:
        protobuf has no canonical encoding to normalize toward, so "equal after
        normalization" is not a thing one could check. That strictness is the
        point -- it is exactly how a runtime whose field order or default-value
        handling drifted gets caught, which is the risk that made byte-pinning
        this worth doing.
        """
        if not spec.get('byte_pinning'):
            return
        expected_hex = (spec.get('expected') or {}).get('proto_wire_hex')
        if not expected_hex:
            return
        actual_hex = actual.hex()
        if actual_hex != expected_hex:
            raise AssertionError(
                f'{label}: proto wire bytes diverge from the pinned hex\n'
                f'  expected: {expected_hex}\n  actual:   {actual_hex}')

    @staticmethod
    def _iter_formats(spec: str) -> list[str]:
        if spec == 'any':
            return ['json', 'binary']
        return [spec]

    @staticmethod
    def _iter_modes(spec: str) -> list[str]:
        # 'any' = the cells the project's existing wire serialization tests
        # cover (PROTO × {JSON, BINARY}). Other (mode, fmt) cells have known
        # impl gaps (e.g. PJSON+BINARY). Authors who want broader coverage
        # specify the mode explicitly.
        if spec == 'any':
            return ['proto']
        return [spec]

    def _resolve_input(self, raw: dict[str, Any]) -> dict[str, Any]:
        if 'python_object' in raw:
            path = (self.corpus_root / raw['python_object']).resolve()
            return json.loads(path.read_text(encoding='utf-8'))
        return dict(raw)

    def _round_trip(self, constructor: str, args: dict[str, Any],
                    mode: str, wire_format: str,
                    spec: dict[str, Any] | None = None) -> None:
        from autonomous_trust.core.config.configuration import (
            Configuration, SerializeMode, WireFormat,
        )

        old_mode, old_fmt = Configuration.mode, Configuration.wire_format
        Configuration.mode = SerializeMode[mode.upper()]
        Configuration.wire_format = WireFormat[wire_format.upper()]
        try:
            self._round_trip_unguarded(constructor, args, spec=spec or {})
        finally:
            Configuration.mode, Configuration.wire_format = old_mode, old_fmt

    def _round_trip_unguarded(self, constructor: str, args: dict[str, Any],
                              spec: dict[str, Any] | None = None) -> None:
        spec = spec or {}
        if constructor == 'AgreementProof':
            from autonomous_trust.core.algorithms.agreement import AgreementProof
            uid = UUID(args['uuid'])
            digest = self._coerce_bytes(args['digest'])
            approval = bool(args['approval'])
            nonce = self._coerce_bytes(args['nonce']) if args.get('nonce') is not None else None
            obj = AgreementProof(uid, digest, approval, nonce)
            data = obj.to_string()
            restored = AgreementProof.from_string(data)
            assert restored.uuid == obj.uuid, 'AgreementProof uuid drift'
            assert restored.digest == obj.digest, 'AgreementProof digest drift'
            assert restored.approval == obj.approval, 'AgreementProof approval drift'
            assert restored.nonce == obj.nonce, 'AgreementProof nonce drift'
            self._assert_byte_pin(spec, data.encode('utf-8') if isinstance(data, str) else data,
                                  'AgreementProof')
            return

        if constructor == 'Signature':
            from autonomous_trust.core.identity.sign import Signature
            # When the scenario supplies `seed_hex` (32-byte seed as a
            # 64-char ASCII hex string), build the Signature from it for
            # byte-pinned determinism.  Without a seed we fall back to
            # Signature.generate() — round-trip equivalence is still
            # checked but byte-pin will refuse without a fixture.
            seed_hex = args.get('seed_hex')
            if seed_hex is not None:
                sig = Signature(seed_hex.encode('ascii'), public_only=False)
            else:
                sig = Signature.generate()
            pub = sig.publish()
            data = sig.to_string()
            restored = Signature.from_string(data)
            assert restored.publish() == pub, 'Signature pub-key drift'
            assert restored.public_only is True
            self._assert_byte_pin(spec, data.encode('utf-8') if isinstance(data, str) else data,
                                  'Signature')
            return

        if constructor == 'Message':
            # Message is not a Configuration subclass; it has its own
            # JSON envelope (process|function|data|signature). The vector
            # round-trips that envelope without exercising mode/wire-format.
            self._message_round_trip(args, spec)
            return

        raise AssertionError(f'unsupported wire_vector constructor: {constructor!r}')

    def _message_round_trip(self, args: dict[str, Any], spec: dict[str, Any]) -> None:
        """Round-trip the Message envelope in the format(s) the case asks for.

        `envelope_format` selects the NETWORK envelope encoding
        (doc/architecture/network-wire-format.md) and is independent of
        `wire_format`/`serialize_mode`, which govern how a Configuration *payload*
        serializes. Default json, so every vector
        written before the proto envelope existed keeps exercising exactly what
        it did.
        """
        from autonomous_trust.core.config import NetWireFormat
        from autonomous_trust.core.network.message import Message

        process = args['process']
        function = args['function']
        obj = args.get('obj', '')
        encrypt = bool(args.get('encrypt', False))
        trace_id = args.get('trace_id')
        msg = Message(process, function, obj, encrypt=encrypt, trace_id=trace_id)

        which = spec.get('envelope_format', 'json')
        formats = ([NetWireFormat.json, NetWireFormat.proto] if which == 'both'
                   else [NetWireFormat.proto] if which == 'proto'
                   else [NetWireFormat.json])

        parsed: dict[str, Any] = {}
        for fmt in formats:
            wire = msg.to_wire(fmt)
            restored = Message.parse(wire, sender=None, validate=False,
                                     wire_format=fmt)
            assert restored.process == msg.process, f'Message.process drift ({fmt})'
            assert restored.function == msg.function, f'Message.function drift ({fmt})'
            # Message.parse re-runs the obj-coercion logic (Configuration auto-deser
            # only fires for objects with __type__); for the simple string case we
            # built, restored.obj should be string-equal.
            assert str(restored.obj) == str(msg.obj), \
                f'Message.obj drift ({fmt}): {restored.obj!r} != {msg.obj!r}'
            assert restored.encrypt == msg.encrypt, f'Message.encrypt drift ({fmt})'
            assert restored.trace_id == msg.trace_id, f'Message.trace_id drift ({fmt})'
            if fmt == NetWireFormat.proto:
                # The marker is not part of the protobuf; a receiver reads it
                # before deciding which parser the frame is eligible for.
                assert wire[:1] == bytes([0xAB]), \
                    f'proto envelope missing its 0xAB marker: got {wire[:1]!r}'
                self._assert_proto_byte_pin(spec, wire, 'Message')
            else:
                self._assert_byte_pin(spec, wire, 'Message')
            parsed[fmt] = restored

        if which == 'both':
            # Cross-format equivalence: the two encodings must mean the same
            # thing, not merely each survive its own round trip.
            j, p = parsed[NetWireFormat.json], parsed[NetWireFormat.proto]
            for field in ('process', 'function', 'encrypt', 'trace_id'):
                jv, pv = getattr(j, field), getattr(p, field)
                assert jv == pv, f'cross-format {field} drift: json={jv!r} proto={pv!r}'
            assert str(j.obj) == str(p.obj), \
                f'cross-format obj drift: json={j.obj!r} proto={p.obj!r}'

    @staticmethod
    def _coerce_bytes(value: Any) -> bytes:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str):
            if value.startswith('0x'):
                return hex_to_bytes(value)
            return value.encode('utf-8')
        raise AssertionError(f'cannot coerce {value!r} to bytes')

    # ------------------------------------------------------------------
    # Crypto vectors
    # ------------------------------------------------------------------

    def run_crypto_vector(self, case: Case) -> None:
        spec = case.data
        primitive = spec['primitive']
        inp = spec['input']
        exp = spec['expected']
        handler = {
            'ed25519_sign':       self._ed25519_sign,
            'ed25519_verify':     self._ed25519_verify,
            'nacl_box':           self._nacl_box,
            'nacl_box_open':      self._nacl_box_open,
            'nacl_secretbox':     self._nacl_secretbox,
            'nacl_secretbox_open': self._nacl_secretbox_open,
        }.get(primitive)
        if handler is None:
            raise AssertionError(f'unknown crypto primitive: {primitive!r}')
        handler(inp, exp)

    @staticmethod
    def _ed25519_sign(inp: dict[str, Any], exp: dict[str, Any]) -> None:
        seed = hex_to_bytes(inp['key_seed'])
        msg = hex_to_bytes(inp['message'])
        key = SigningKey(seed)
        signed = key.sign(msg)
        actual = signed.signature
        expected = hex_to_bytes(exp['signature'])
        assert actual == expected, (
            f'ed25519 signature mismatch: got {actual.hex()}, expected {expected.hex()}'
        )

    @staticmethod
    def _ed25519_verify(inp: dict[str, Any], exp: dict[str, Any]) -> None:
        public = hex_to_bytes(inp['public_key'])
        msg = hex_to_bytes(inp['message'])
        sig = hex_to_bytes(inp['signature'])
        vk = VerifyKey(public)
        should_verify = bool(exp.get('valid', True))
        try:
            vk.verify(msg, sig)
            verified = True
        except BadSignatureError:
            verified = False
        assert verified == should_verify, \
            f'ed25519_verify: got valid={verified}, expected valid={should_verify}'

    @staticmethod
    def _nacl_box(inp: dict[str, Any], exp: dict[str, Any]) -> None:
        sender_priv = PrivateKey(hex_to_bytes(inp['sender_private_key']))
        recipient_pub = PublicKey(hex_to_bytes(inp['recipient_public_key']))
        nonce = hex_to_bytes(inp['nonce'])
        plaintext = hex_to_bytes(inp['plaintext'])
        box = Box(sender_priv, recipient_pub)
        encrypted = box.encrypt(plaintext, nonce)
        actual = bytes(encrypted.ciphertext)
        expected = hex_to_bytes(exp['ciphertext'])
        assert actual == expected, (
            f'nacl_box ciphertext mismatch: got {actual.hex()}, expected {expected.hex()}'
        )

    @staticmethod
    def _nacl_box_open(inp: dict[str, Any], exp: dict[str, Any]) -> None:
        recipient_priv = PrivateKey(hex_to_bytes(inp['recipient_private_key']))
        sender_pub = PublicKey(hex_to_bytes(inp['sender_public_key']))
        nonce = hex_to_bytes(inp['nonce'])
        ciphertext = hex_to_bytes(inp['ciphertext'])
        box = Box(recipient_priv, sender_pub)
        plaintext = box.decrypt(ciphertext, nonce)
        expected = hex_to_bytes(exp['plaintext'])
        assert plaintext == expected, (
            f'nacl_box_open plaintext mismatch: got {plaintext.hex()}, expected {expected.hex()}'
        )

    @staticmethod
    def _nacl_secretbox(inp: dict[str, Any], exp: dict[str, Any]) -> None:
        key = hex_to_bytes(inp['key'])
        nonce = hex_to_bytes(inp['nonce'])
        plaintext = hex_to_bytes(inp['plaintext'])
        box = SecretBox(key)
        encrypted = box.encrypt(plaintext, nonce)
        actual = bytes(encrypted.ciphertext)
        expected = hex_to_bytes(exp['ciphertext'])
        assert actual == expected, (
            f'secretbox ciphertext mismatch: got {actual.hex()}, expected {expected.hex()}'
        )

    @staticmethod
    def _nacl_secretbox_open(inp: dict[str, Any], exp: dict[str, Any]) -> None:
        key = hex_to_bytes(inp['key'])
        nonce = hex_to_bytes(inp['nonce'])
        ciphertext = hex_to_bytes(inp['ciphertext'])
        box = SecretBox(key)
        plaintext = box.decrypt(ciphertext, nonce)
        expected = hex_to_bytes(exp['plaintext'])
        assert plaintext == expected, (
            f'secretbox_open plaintext mismatch: got {plaintext.hex()}, expected {expected.hex()}'
        )

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def run_scenario(self, case: Case) -> None:
        # Peer-encrypted runners all parameterize on fixtures (nonce_hex,
        # obj_json); additional scenarios that exercise the same Box
        # round-trip with different inputs route to the same method.
        if case.name in ('peer-encrypted-roundtrip',
                         'peer-encrypted-structured-payload',
                         'network-canonical'):
            self._run_peer_encrypted_roundtrip(case)
            return
        if case.name == 'group-encrypted-roundtrip':
            self._run_group_encrypted_roundtrip(case)
            return
        if case.name in ('broadcast-fanout',
                         'broadcast-fanout-three-receivers'):
            self._run_broadcast_fanout(case)
            return
        if case.name == 'peer-encrypted-tampered-ciphertext':
            self._run_peer_encrypted_tampered_ciphertext(case)
            return
        if case.name == 'peer-encrypted-truncated-ciphertext':
            self._run_peer_encrypted_truncated_ciphertext(case)
            return
        if case.name == 'peer-encrypted-wrong-recipient':
            self._run_peer_encrypted_wrong_recipient(case)
            return
        if case.name == 'peer-encrypted-wrong-signer':
            self._run_peer_encrypted_wrong_signer(case)
            return
        if case.name == 'group-key-rotation-decrypt-fails':
            self._run_group_key_rotation_decrypt_fails(case)
            return
        if case.name == 'port-resolution':
            self._run_port_resolution(case)
            return
        if case.name == 'tunables-resolution':
            self._run_tunables_resolution(case)
            return
        if case.name == 'wire-format-mismatch-refused':
            self._run_wire_format_mismatch_refused(case)
            return
        if case.name == 'wire-mode-resolution':
            self._run_wire_mode_resolution(case)
            return
        if case.name == 'group-wire-format-canonical':
            self._run_group_wire_format_canonical(case)
            return
        if case.name == 'cross-group-format-fallback':
            self._run_cross_group_format_fallback(case)
            return
        if case.name == 'gateway-boundary-verbs':
            self._run_gateway_boundary_verbs(case)
            return
        if case.name == 'unencrypted-verbs':
            self._run_unencrypted_verbs(case)
            return
        if case.name == 'transport-binds-the-recipient':
            self._run_transport_binds_the_recipient(case)
            return
        raise NotImplementedError(
            f'network scenario {case.name!r} not implemented'
        )

    def _run_port_resolution(self, case: Case) -> None:
        """Base-port resolution: config -> AT_COMM_PORT -> default.

        Runs the scenario's table against the production resolver. The C
        adapter runs the same table against ``net_port_resolve``, so a change
        to either resolution order fails here rather than at a peer that
        cannot be reached. Refusals are part of the contract: a bad override
        must keep the default and never yield 0.
        """
        from autonomous_trust.core._python import system as at_system

        fixtures = case.data.get('fixtures') or {}
        table = fixtures.get('resolutions') or []
        if not table:
            raise AssertionError('scenario: fixtures.resolutions missing or empty')

        # Pinned in the scenario so a drift in either side's constants fails
        # here instead of agreeing on a value neither side got from the other.
        for key, actual in (('default_port', at_system.default_comm_port),
                            ('port_min', at_system.comm_port_min),
                            ('port_max', at_system.comm_port_max)):
            if key in fixtures and fixtures[key] != actual:
                raise AssertionError(
                    f'{key}: scenario says {fixtures[key]}, Python says {actual}')

        saved = os.environ.get('AT_COMM_PORT')
        try:
            for row in table:
                rid = row.get('id', '?')
                cfg_port = row.get('cfg_port') or 0
                env = row.get('env')
                want_port = row['expect_port']
                want_src = row['expect_source']

                if env is None:
                    os.environ.pop('AT_COMM_PORT', None)
                else:
                    os.environ['AT_COMM_PORT'] = str(env)

                got, got_src = at_system.resolve_comm_port(cfg_port)
                shown = '(unset)' if env is None else env
                if got != want_port:
                    raise AssertionError(
                        f'{rid}: cfg_port={cfg_port} AT_COMM_PORT={shown} -> '
                        f'port {got}, want {want_port}')
                if got_src != want_src:
                    raise AssertionError(
                        f'{rid}: cfg_port={cfg_port} AT_COMM_PORT={shown} -> '
                        f"source {got_src!r}, want {want_src!r}")
                if got + 1 > at_system.comm_port_max + 1:
                    raise AssertionError(f'{rid}: group port {got + 1} out of range')
        finally:
            if saved is None:
                os.environ.pop('AT_COMM_PORT', None)
            else:
                os.environ['AT_COMM_PORT'] = saved

    def _run_wire_format_mismatch_refused(self, case: Case) -> None:
        """The strict envelope-format gate, both directions
        (doc/architecture/network-wire-format.md).

        Asserts the four combinations of (frame format, expected format) and,
        for the two mismatches, that the refusal is FORMAT-specific rather than
        generic malformed-input -- the operator-visible difference between "this
        peer is broken" and "this cohort is misprovisioned".
        """
        from autonomous_trust.core.config import NetWireFormat
        from autonomous_trust.core.network.message import Message, WireFormatMismatch

        fx = case.data.get('fixtures') or {}
        msg = Message(fx.get('process', 'identity'), fx.get('function', 'request_access'),
                      fx.get('obj_json', '{}'), encrypt=False,
                      trace_id=fx.get('trace_id'))
        json_wire = msg.to_wire(NetWireFormat.json)
        proto_wire = msg.to_wire(NetWireFormat.proto)

        def accepted(raw, fmt):
            """(ok, format_specific_refusal)"""
            try:
                Message.parse(raw, sender=None, validate=False, wire_format=fmt)
                return True, False
            except WireFormatMismatch:
                return False, True
            except Exception:
                return False, False

        json_as_json_ok, _ = accepted(json_wire, NetWireFormat.json)
        proto_as_proto_ok, _ = accepted(proto_wire, NetWireFormat.proto)
        proto_as_json_ok, p_fmt_specific = accepted(proto_wire, NetWireFormat.json)
        json_as_proto_ok, j_fmt_specific = accepted(json_wire, NetWireFormat.proto)

        state = {
            'json_as_json_ok': json_as_json_ok,
            'proto_as_proto_ok': proto_as_proto_ok,
            'proto_as_json_refused': not proto_as_json_ok,
            'json_as_proto_refused': not json_as_proto_ok,
            'refusal_is_format_specific': p_fmt_specific and j_fmt_specific,
        }
        _assert_expected_flags(case, 'node', state)

    def _run_wire_mode_resolution(self, case: Case) -> None:
        """AT_NET_WIRE_MODE resolution: env -> compile-time default.

        Same shape as _run_tunables_resolution, against the named-value
        resolver. The C adapter runs this identical table against
        net_wire_mode_resolve, so a knob that accepts a spelling on one side
        only fails here rather than at a cohort that cannot form.
        """
        from autonomous_trust.core._python import system as at_system

        fx = case.data.get('fixtures') or {}
        knob = fx.get('knob') or {}
        table = fx.get('resolutions') or []
        if not table:
            raise AssertionError('scenario: fixtures.resolutions missing or empty')

        constants_match = True
        if 'default' in knob and knob['default'] != at_system.default_net_wire_mode:
            constants_match = False
        if 'choices' in knob and tuple(knob['choices']) != tuple(at_system.net_wire_modes):
            constants_match = False

        var = knob.get('env', 'AT_NET_WIRE_MODE')
        saved = os.environ.get(var)
        all_match = True
        try:
            for row in table:
                rid = row.get('id', '?')
                env = row.get('env')
                if env is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = str(env)
                got, got_src = at_system.resolve_net_wire_mode()
                if got != row['expect_value'] or got_src != row['expect_source']:
                    all_match = False
                    raise AssertionError(
                        f'{rid}: {var}={"(unset)" if env is None else env!r} -> '
                        f'({got!r}, {got_src!r}), want '
                        f'({row["expect_value"]!r}, {row["expect_source"]!r})')
        finally:
            if saved is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = saved

        _assert_expected_flags(case, 'node', {
            'knob_constants_match': constants_match,
            'all_resolutions_match': all_match,
        })

    def _run_group_wire_format_canonical(self, case: Case) -> None:
        """The group's envelope format crosses the wire with the group (doc/architecture/network-wire-format.md)."""
        from autonomous_trust.core.config import NetWireFormat
        from autonomous_trust.core.identity.group import Group
        from autonomous_trust.core.identity.encrypt import Encryptor

        fx = case.data.get('fixtures') or {}
        addr_map = dict(fx.get('address_map') or {})

        def make(fmt):
            return Group(fx.get('group_uuid'), addr_map, '',
                         Encryptor.generate(), False, _wire_format=fmt)

        proto_canon = make(NetWireFormat.proto).to_canonical()
        json_canon = make(NetWireFormat.json).to_canonical()

        # Absent field: a group from a peer predating this, or a config written
        # before it. Must read as json, not error and not proto.
        absent = dict(proto_canon)
        absent.pop('wire_format', None)
        # Unrecognized value: a provisioning typo, which must tighten to the
        # format every node can read.
        unknown = dict(proto_canon)
        unknown['wire_format'] = 'yaml'

        state = {
            'canonical_key_present': 'wire_format' in proto_canon,
            'proto_roundtrips':
                Group.from_canonical(proto_canon).wire_format == NetWireFormat.proto,
            'json_roundtrips':
                Group.from_canonical(json_canon).wire_format == NetWireFormat.json,
            'absent_reads_json':
                Group.from_canonical(absent).wire_format == NetWireFormat.json,
            'unknown_reads_json':
                Group.from_canonical(unknown).wire_format == NetWireFormat.json,
        }
        _assert_expected_flags(case, 'node', state)

    def _run_cross_group_format_fallback(self, case: Case) -> None:
        """A group answers with its own format for its own members and with
        JSON for anyone it cannot place -- the rule that lets two
        differently-formatted cohorts complete a merge handshake
        (doc/architecture/network-wire-format.md).
        """
        from autonomous_trust.core.config import NetWireFormat
        from autonomous_trust.core.identity import Group, Encryptor

        fx = case.data.get('fixtures') or {}
        proto_member = fx.get('proto_member', '10.0.0.1')
        json_member = fx.get('json_member', '10.0.1.1')
        stranger = fx.get('stranger', '10.0.9.9')

        def _group(uuid_str, member, fmt):
            # The key is irrelevant here -- this asks only about the address
            # map and the format field -- but Group wants a real Encryptor.
            return Group(uuid_str, {member: member}, 'cohort',
                         Encryptor.generate(), False, _wire_format=fmt)

        proto_grp = _group(fx.get('proto_group_uuid'), proto_member,
                           NetWireFormat.proto)
        json_grp = _group(fx.get('json_group_uuid'), json_member,
                          NetWireFormat.json)

        state = {
            'proto_group_to_own_member_is_proto':
                proto_grp.wire_format_for_address(proto_member) == NetWireFormat.proto,
            'json_group_to_own_member_is_json':
                json_grp.wire_format_for_address(json_member) == NetWireFormat.json,
            # The merge handshake: neither can place the other's member.
            'proto_group_to_foreign_member_is_json':
                proto_grp.wire_format_for_address(json_member) == NetWireFormat.json,
            'json_group_to_foreign_member_is_json':
                json_grp.wire_format_for_address(proto_member) == NetWireFormat.json,
            'proto_group_to_stranger_is_json':
                proto_grp.wire_format_for_address(stranger) == NetWireFormat.json,
        }
        _assert_expected_flags(case, 'node', state)

    def _run_gateway_boundary_verbs(self, case: Case) -> None:
        """The membership of BOOTSTRAP_VERBS -- the verbs the gateway boundary
        refuses to carry (doc/architecture/network-wire-format.md).

        Two hand-maintained lists in two languages, so the negative half is
        what earns this case: a verb added on one side only would otherwise
        open the boundary on one runtime and close it on the other.
        """
        from autonomous_trust.core.identity.protocol import BOOTSTRAP_VERBS

        fx = case.data.get('fixtures') or {}
        boots = list(fx.get('bootstrap_verbs') or [])
        others = list(fx.get('not_bootstrap_verbs') or [])

        state = {
            'all_bootstrap_verbs_recognized':
                all(v in BOOTSTRAP_VERBS for v in boots),
            'no_other_verb_is_bootstrap':
                not any(v in BOOTSTRAP_VERBS for v in others),
            'bootstrap_verb_count_is_three': len(BOOTSTRAP_VERBS) == 3,
            # C's classifier takes NULL; Python's set is asked with None/''.
            'empty_verb_is_not_bootstrap':
                (None not in BOOTSTRAP_VERBS) and ('' not in BOOTSTRAP_VERBS),
        }
        _assert_expected_flags(case, 'node', state)

    def _run_unencrypted_verbs(self, case: Case) -> None:
        """The plaintext allowlist: which verbs a receiver accepts unencrypted
        from a known peer, and how that set relates to the bootstrap set.

        Two hand-maintained lists in two languages, so the negative half is
        where the value is: a verb added on one side only becomes a downgrade
        opening on that runtime alone. The `full_history` assertion is the
        sharpest one -- it is bootstrap yet must never ride in the clear,
        because it carries the group key.
        """
        from autonomous_trust.core.identity.protocol import (
            UNENCRYPTED_VERBS, BOOTSTRAP_VERBS)

        fx = case.data.get('fixtures') or {}
        plain = list(fx.get('unencrypted_verbs') or [])
        enc_only = list(fx.get('encrypted_only_verbs') or [])
        both = list(fx.get('both_bootstrap_and_unencrypted') or [])
        boot_enc = list(fx.get('bootstrap_but_encrypted') or [])

        state = {
            'all_unencrypted_verbs_recognized':
                all(v in UNENCRYPTED_VERBS for v in plain),
            'no_other_verb_is_unencrypted':
                not any(v in UNENCRYPTED_VERBS for v in enc_only),
            'unencrypted_verb_count_is_eleven': len(UNENCRYPTED_VERBS) == 11,
            'empty_verb_is_not_unencrypted':
                (None not in UNENCRYPTED_VERBS) and ('' not in UNENCRYPTED_VERBS),
            'overlap_verbs_are_both':
                bool(both) and all(v in UNENCRYPTED_VERBS and v in BOOTSTRAP_VERBS
                                   for v in both),
            # Bootstrap, but encrypted: the group key never rides in plaintext.
            'full_history_is_bootstrap_but_not_unencrypted':
                bool(boot_enc) and all(v in BOOTSTRAP_VERBS
                                       and v not in UNENCRYPTED_VERBS
                                       for v in boot_enc),
        }
        _assert_expected_flags(case, 'node', state)

    def _run_transport_binds_the_recipient(self, case: Case) -> None:
        """The envelope's `from_*` claim is read ONLY when the transport gave
        no peer (R+D.md §2.6).

        One signed frame, parsed three ways per format: attributed to its true
        signer, attributed to a relayer, and unattributed. The relay row is the
        security property; the override row is what proves the ORDERING rather
        than merely a disagreement being caught.
        """
        from autonomous_trust.core.config import NetWireFormat
        from autonomous_trust.core.network.message import Message

        fx = case.data.get('fixtures') or {}
        signer = _make_test_identity('a', addr='10.0.80.1')
        relayer = _make_test_identity('b', addr='10.0.80.2')
        signer_pub, relayer_pub = signer.publish(), relayer.publish()

        msg = Message(fx.get('process', 'idproc'),
                      fx.get('function', 'peer_caps_query'),
                      fx.get('obj_json', 'payload'),
                      from_whom=signer, encrypt=False,
                      trace_id=fx.get('trace_id'))

        state = {}
        for label, fmt in (('json', NetWireFormat.json),
                           ('proto', NetWireFormat.proto)):
            wire = msg.to_wire(fmt)

            # Row 1: honest. Doubles as the control -- without it a parser that
            # verified nothing would satisfy row 2.
            true_sender = Message.parse(wire, signer_pub, wire_format=fmt)
            # Row 2: the SAME bytes, attributed to someone else. The relay.
            relayed = Message.parse(wire, relayer_pub, wire_format=fmt)
            # Row 3: no transport peer -- the bootstrap channel.
            unattributed = Message.parse(wire, None, wire_format=fmt)

            state['%s_verified_for_true_sender' % label] = true_sender.verified
            state['%s_relay_refused' % label] = not relayed.verified
            # The ordering: with a peer supplied, the parsed sender IS that
            # peer, not the envelope's claim.
            state['%s_transport_peer_overrides_envelope' % label] = (
                str(getattr(relayed.from_whom, 'uuid', None)) == str(relayer.uuid))
            state['%s_unattributed_verified' % label] = unattributed.verified
            state['%s_unattributed_sender_is_envelope_claim' % label] = (
                str(getattr(unattributed.from_whom, 'uuid', None)) == str(signer.uuid))

        _assert_expected_flags(case, 'signer', state)

    def _run_tunables_resolution(self, case: Case) -> None:
        """Network-tunable resolution: env -> compile-time default.

        Runs the scenario's table against the production resolvers. The C
        adapter runs the same table against net_annoy_limit_resolve /
        net_recv_poll_ms_resolve / net_mystery_max_age_resolve, so a knob that
        exists on one side only -- which is exactly what this case was written
        to prevent recurring -- fails here.
        """
        from autonomous_trust.core._python import system as at_system

        fixtures = case.data.get('fixtures') or {}
        knobs = {k['name']: k for k in (fixtures.get('knobs') or [])}
        table = fixtures.get('resolutions') or []
        if not knobs:
            raise AssertionError('scenario: fixtures.knobs missing or empty')
        if not table:
            raise AssertionError('scenario: fixtures.resolutions missing or empty')

        # name -> (resolver, default, min, max) as THIS implementation has them.
        mine = {
            'annoy_limit': (at_system.resolve_annoy_limit,
                            at_system.default_annoy_limit,
                            at_system.annoy_limit_min,
                            at_system.annoy_limit_max),
            'recv_poll_ms': (at_system.resolve_recv_poll_ms,
                             at_system.default_recv_poll_ms,
                             at_system.recv_poll_ms_min,
                             at_system.recv_poll_ms_max),
            'mystery_max_age_s': (at_system.resolve_mystery_max_age_s,
                                  at_system.default_mystery_max_age_s,
                                  at_system.mystery_max_age_s_min,
                                  at_system.mystery_max_age_s_max),
        }

        # Pinned in the scenario so a drift in either side's constants fails
        # here instead of agreeing on a value neither side got from the other.
        for name, spec in knobs.items():
            if name not in mine:
                raise AssertionError(f'scenario knob {name!r} has no Python resolver')
            _, dflt, lo, hi = mine[name]
            for key, actual in (('default', dflt), ('min', lo), ('max', hi)):
                if key in spec and spec[key] != actual:
                    raise AssertionError(
                        f'{name}.{key}: scenario says {spec[key]}, Python says {actual}')

        env_names = {name: knobs[name]['env'] for name in knobs}
        saved = {var: os.environ.get(var) for var in env_names.values()}
        try:
            for row in table:
                rid = row.get('id', '?')
                name = row['knob']
                if name not in mine:
                    raise AssertionError(f'{rid}: unknown knob {name!r}')
                resolver = mine[name][0]
                var = env_names[name]
                env = row.get('env')
                want_value = row['expect_value']
                want_src = row['expect_source']

                if env is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = str(env)

                got, got_src = resolver()
                shown = '(unset)' if env is None else repr(env)
                if got != want_value:
                    raise AssertionError(
                        f'{rid}: {var}={shown} -> {name} {got}, want {want_value}')
                if got_src != want_src:
                    raise AssertionError(
                        f'{rid}: {var}={shown} -> source {got_src!r}, want {want_src!r}')
        finally:
            for var, val in saved.items():
                if val is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = val

    def _run_peer_encrypted_roundtrip(self, case: Case) -> None:
        """Exercise A.encrypt → B.decrypt → Message.parse end-to-end.

        Builds two deterministic Identity instances, runs a Box round-trip
        with the fixture nonce, and asserts the parsed Message exposes
        the expected (process, function, verified) tuple.
        """
        from autonomous_trust.core.identity import Identity
        from autonomous_trust.core.identity.encrypt import Encryptor
        from autonomous_trust.core.identity.sign import Signature
        from autonomous_trust.core.network.message import Message
        from autonomous_trust.core.system import CfgIds

        fixtures = case.data.get('fixtures', {}) or {}
        nonce = hex_to_bytes(fixtures['nonce_hex'])
        obj_json = fixtures.get('obj_json', '{}')

        a = _make_test_identity('a', addr='10.0.80.1')
        b = _make_test_identity('b', addr='10.0.80.2')

        # A signs+serializes a Message addressed to B. encrypt=True flags
        # transport encryption intent but does not encrypt obj inline; the
        # encryption layer runs on the serialized wire bytes below.
        msg = Message(CfgIds.identity, 'request_access', obj_json,
                      from_whom=a, to_whom=b, encrypt=True)
        plaintext = bytes(msg)

        # A encrypts wire bytes for B with the fixture nonce. PyNaCl's
        # EncryptedMessage carries (nonce, ciphertext) and B.decrypt
        # consumes both when handed the EncryptedMessage directly.
        encrypted = a.encrypt(plaintext, b, nonce=nonce)
        decrypted = b.decrypt(encrypted, a)
        if isinstance(decrypted, str):
            decrypted = decrypted.encode('utf-8')

        # Re-parse via production code. Pass A as sender so signature
        # verification runs.
        parsed = Message.parse(decrypted, a)
        _assert_expected_state_b(case, parsed)

    def _run_group_encrypted_roundtrip(self, case: Case) -> None:
        """Exercise Group.encrypt → Group.decrypt → Message.parse.

        Builds A and B Identities plus a shared deterministic Group whose
        keypair seeds the libsodium Box. Both languages must agree on the
        group keypair bytes for the round-trip to succeed.
        """
        import hashlib
        from uuid import UUID, uuid5
        from autonomous_trust.core.identity import Group
        from autonomous_trust.core.identity.encrypt import Encryptor
        from autonomous_trust.core.network.message import Message
        from autonomous_trust.core.system import CfgIds

        fixtures = case.data.get('fixtures', {}) or {}
        nonce = hex_to_bytes(fixtures['nonce_hex'])
        obj_json = fixtures.get('obj_json', '{}')
        group_seed_hex = fixtures['group_encryptor_seed_hex']

        a = _make_test_identity('a', addr='10.0.80.1')
        b = _make_test_identity('b', addr='10.0.80.2')

        # Both group instances share the SAME keypair bytes, mirroring the
        # production model where every group member holds a copy of the
        # group's keypair. The Encryptor constructor expects an ASCII-hex
        # seed (matching Identity's encryptor construction).
        group_seed = group_seed_hex.encode('ascii')
        ns = UUID('00000000-0000-0000-0000-000000000bbb')
        group_uuid = uuid5(ns, 'at-conformance:group:g1')
        a_group = Group(group_uuid, {}, 'g1',
                        Encryptor(group_seed, public_only=False),
                        _public_only=False)
        b_group = Group(group_uuid, {}, 'g1',
                        Encryptor(group_seed, public_only=False),
                        _public_only=False)

        msg = Message(CfgIds.identity, 'request_access', obj_json,
                      from_whom=a, encrypt=True)
        plaintext = bytes(msg)

        # Group.encrypt uses the GROUP as `whom`, so the underlying Box
        # operates over (group_private, group_public) — a shared-secret
        # encryption among all group members. Same on the decrypt side
        # because B has the same keypair.
        encrypted = a_group.encrypt(plaintext, a_group, nonce=nonce)
        decrypted = b_group.decrypt(encrypted, b_group)
        if isinstance(decrypted, str):
            decrypted = decrypted.encode('utf-8')

        parsed = Message.parse(decrypted, a)
        _assert_expected_state_b(case, parsed)

    def _run_broadcast_fanout(self, case: Case) -> None:
        """Exercise sign → broadcast wire bytes → parse, fanned out to N
        independent receivers. All receivers consume the SAME bytes and
        must report identical observables.

        Sender is the first participant with role 'sender'; every other
        participant is a receiver. Supports two receivers
        (broadcast-fanout) and three (broadcast-fanout-three-receivers)
        symmetrically — the only difference is participant count + the
        per-receiver expected_state blocks.
        """
        from autonomous_trust.core.network.message import Message
        from autonomous_trust.core.system import CfgIds

        fixtures = case.data.get('fixtures', {}) or {}
        obj_json = fixtures.get('obj_json', '{}')

        participants = case.data.get('participants', [])
        sender_spec = next((p for p in participants if p['role'] == 'sender'),
                           None)
        if sender_spec is None:
            raise AssertionError('broadcast scenario requires a sender role')
        sender_id = sender_spec['id']

        receivers = [p['id'] for p in participants if p['role'] == 'receiver']
        if not receivers:
            raise AssertionError(
                'broadcast scenario requires at least one receiver role'
            )

        # Each receiver gets a deterministic addr 10.0.80.<index+2>;
        # receiver identities are built only for symmetry with the C
        # adapter (which materializes them); the Python parser uses
        # only the sender identity to verify the signature, so receivers
        # are spectators here.
        sender = _make_test_identity(sender_id, addr='10.0.80.1')
        for idx, rid in enumerate(receivers):
            _make_test_identity(rid, addr=f'10.0.80.{idx + 2}')

        msg = Message(CfgIds.identity, 'request_access', obj_json,
                      from_whom=sender, encrypt=False)
        wire = bytes(msg)

        # Each receiver parses the wire bytes independently with sender
        # as the known signer. All parses must yield identical
        # observables; the per-receiver expected_state block enforces
        # that pin.
        for rid in receivers:
            parsed = Message.parse(wire, sender)
            _assert_expected_state(case, rid, parsed)

    # ------------------------------------------------------------------
    # Crypto-rejection scenarios (failure paths)
    # ------------------------------------------------------------------
    # The roundtrip / fanout runners above test happy paths: parse,
    # signature-verify, expected_state. These runners cover the
    # crypto-rejection corner of the matrix — a properly-formed wire
    # envelope whose ciphertext or key context is wrong, so decryption
    # must fail. Each runner attempts the decryption and asserts that
    # the receiver's box raised CryptoError (Python) / returned non-
    # zero (C). The shared `_assert_decrypt_failed` helper enforces the
    # YAML expected_state.<receiver>.decrypt_failed: true pin.

    def _run_peer_encrypted_tampered_ciphertext(self, case: Case) -> None:
        """Flip one byte of the Box ciphertext; B's decrypt must fail.

        Validates that libsodium's poly1305 MAC catches ciphertext
        tampering — a "wire bytes survived transit but were modified"
        threat. Same as production: PyNaCl raises CryptoError on MAC
        mismatch; C `identity_decrypt` returns non-zero.
        """
        from nacl.exceptions import CryptoError
        from autonomous_trust.core.network.message import Message
        from autonomous_trust.core.system import CfgIds

        fixtures = case.data.get('fixtures', {}) or {}
        nonce = hex_to_bytes(fixtures['nonce_hex'])
        obj_json = fixtures.get('obj_json', '{}')

        a = _make_test_identity('a', addr='10.0.80.1')
        b = _make_test_identity('b', addr='10.0.80.2')

        msg = Message(CfgIds.identity, 'request_access', obj_json,
                      from_whom=a, to_whom=b, encrypt=True)
        plaintext = bytes(msg)

        encrypted = a.encrypt(plaintext, b, nonce=nonce)
        # EncryptedMessage is `nonce || ciphertext`; pick a byte well
        # past the 24-byte nonce so we deterministically corrupt the
        # ciphertext, not the nonce. Flipping the nonce would also
        # cause decrypt to fail but for a different reason — the test
        # intent is "MAC catches ciphertext mutation."
        tampered = bytearray(bytes(encrypted))
        if len(tampered) < 30:
            raise AssertionError(
                f'tampered: encrypted buffer too short ({len(tampered)} bytes)'
            )
        tampered[30] ^= 0x01

        try:
            b.decrypt(bytes(tampered), a)
        except CryptoError:
            _assert_decrypt_failed(case, 'b')
            return
        raise AssertionError(
            'b: decrypt of tampered ciphertext unexpectedly succeeded'
        )

    def _run_peer_encrypted_truncated_ciphertext(self, case: Case) -> None:
        """Drop the trailing 16 bytes of the Box ciphertext; B's decrypt
        must fail.

        Pairs with `_run_peer_encrypted_tampered_ciphertext`: tamper
        catches single-byte mutation, truncate catches end-of-stream
        loss. Both surface as MAC mismatch from libsodium's poly1305
        verification — recomputed MAC over the shortened ciphertext
        no longer matches the embedded MAC tag.
        """
        from nacl.exceptions import CryptoError
        from autonomous_trust.core.network.message import Message
        from autonomous_trust.core.system import CfgIds

        fixtures = case.data.get('fixtures', {}) or {}
        nonce = hex_to_bytes(fixtures['nonce_hex'])
        obj_json = fixtures.get('obj_json', '{}')

        a = _make_test_identity('a', addr='10.0.80.1')
        b = _make_test_identity('b', addr='10.0.80.2')

        msg = Message(CfgIds.identity, 'request_access', obj_json,
                      from_whom=a, to_whom=b, encrypt=True)
        plaintext = bytes(msg)

        encrypted = a.encrypt(plaintext, b, nonce=nonce)
        # PyNaCl's EncryptedMessage bytes form is `nonce(24) || MAC(16)
        # || cipher(N)`. Drop the trailing 16 bytes — leaves nonce and
        # MAC intact but truncates the cipher body. crypto_box_open_easy
        # recomputes MAC over the supplied ciphertext, so the MAC tag
        # no longer matches and decrypt rejects.
        full = bytes(encrypted)
        # 24 nonce + 16 MAC + at least 1 cipher byte after truncation.
        if len(full) < 24 + 16 + 16 + 1:
            raise AssertionError(
                f'truncated: encrypted buffer too short ({len(full)} bytes)'
            )
        truncated = full[:-16]

        try:
            b.decrypt(truncated, a)
        except CryptoError:
            _assert_decrypt_failed(case, 'b')
            return
        raise AssertionError(
            'b: decrypt of truncated ciphertext unexpectedly succeeded'
        )

    def _run_peer_encrypted_wrong_recipient(self, case: Case) -> None:
        """A encrypts for B's public key; C tries to decrypt with C's
        own private key against A's public key. Must fail — wrong
        recipient identity.

        Threat model: an eavesdropper captures the per-peer-encrypted
        envelope but lacks B's private key. Even with A's public key
        (which is fine for verifying signatures, but Box needs B's
        secret to derive the shared secret), decryption rejects.
        """
        from nacl.exceptions import CryptoError
        from autonomous_trust.core.network.message import Message
        from autonomous_trust.core.system import CfgIds

        fixtures = case.data.get('fixtures', {}) or {}
        nonce = hex_to_bytes(fixtures['nonce_hex'])
        obj_json = fixtures.get('obj_json', '{}')

        a = _make_test_identity('a', addr='10.0.80.1')
        b = _make_test_identity('b', addr='10.0.80.2')
        c = _make_test_identity('c', addr='10.0.80.3')

        msg = Message(CfgIds.identity, 'request_access', obj_json,
                      from_whom=a, to_whom=b, encrypt=True)
        plaintext = bytes(msg)
        encrypted = a.encrypt(plaintext, b, nonce=nonce)

        try:
            # Box(c.private, a.public) doesn't share a secret with
            # Box(a.private, b.public). Decrypt must fail.
            c.decrypt(encrypted, a)
        except CryptoError:
            _assert_decrypt_failed(case, 'c')
            return
        raise AssertionError(
            'c: decrypt with wrong recipient key unexpectedly succeeded'
        )

    def _run_peer_encrypted_wrong_signer(self, case: Case) -> None:
        """Z signs+encrypts to B; B parses with claimed sender = A.

        Sig was made with Z's key; verify uses A's key → fails. Pins
        that the network signature check rejects impersonation by
        authorized-but-different peers, not just signature bit-rot.

        Note that decryption SUCCEEDS in this scenario — Z is a legit
        Box-layer sender (B has Z's pubkey). The rejection happens at
        the signature layer inside `Message.parse`, surfaced as
        `parsed.verified = False`.
        """
        from autonomous_trust.core.network.message import Message
        from autonomous_trust.core.system import CfgIds

        fixtures = case.data.get('fixtures', {}) or {}
        nonce = hex_to_bytes(fixtures['nonce_hex'])
        obj_json = fixtures.get('obj_json', '{}')

        a = _make_test_identity('a', addr='10.0.80.1')
        b = _make_test_identity('b', addr='10.0.80.2')
        z = _make_test_identity('z', addr='10.0.80.3')

        # Z constructs+signs the Message. from_whom=z drives the
        # Message ctor's self-signing path (signs with Z's private
        # signing key). The wire envelope embeds Z's from_uuid /
        # from_sig_hex but `Message.parse` uses the externally
        # supplied `sender` arg for verification — so the wire's
        # embedded metadata doesn't affect the verify outcome.
        msg = Message(CfgIds.identity, 'request_access', obj_json,
                      from_whom=z, to_whom=b, encrypt=True)
        plaintext = bytes(msg)

        # Z encrypts to B via Z's box keys. B decrypts using Z's
        # pubkey (the actual Box sender) — this succeeds; the
        # impersonation lives at the inner-signature layer.
        encrypted = z.encrypt(plaintext, b, nonce=nonce)
        decrypted = b.decrypt(encrypted, z)
        if isinstance(decrypted, str):
            decrypted = decrypted.encode('utf-8')

        # B parses with claimed sender = A. The Ed25519 verifier
        # checks Z's signature against A's pubkey → mismatch.
        parsed = Message.parse(decrypted, a)
        if parsed.verified:
            raise AssertionError(
                'b: verify of Z-signed wire against A succeeded '
                '(impersonation NOT rejected)'
            )
        _assert_expected_state_b(case, parsed)

    def _run_group_key_rotation_decrypt_fails(self, case: Case) -> None:
        """A and B were in the same group, but B has rotated to a new
        group key. A still has K1; A's send encrypts with K1; B has
        only K2 → decryption fails. Validates that rotated peers can't
        read pre-rotation ciphertext (a forward-secrecy property of
        the rotation flow).

        Fixture format: two group seeds, `group_encryptor_seed_hex`
        (A's pre-rotation K1) and `group_rotated_seed_hex` (B's new
        K2). Both are 64 hex chars / 32 raw bytes.
        """
        from uuid import UUID, uuid5
        from nacl.exceptions import CryptoError
        from autonomous_trust.core.identity import Group
        from autonomous_trust.core.identity.encrypt import Encryptor
        from autonomous_trust.core.network.message import Message
        from autonomous_trust.core.system import CfgIds

        fixtures = case.data.get('fixtures', {}) or {}
        nonce = hex_to_bytes(fixtures['nonce_hex'])
        obj_json = fixtures.get('obj_json', '{}')
        k1_seed = fixtures['group_encryptor_seed_hex'].encode('ascii')
        k2_seed = fixtures['group_rotated_seed_hex'].encode('ascii')

        a = _make_test_identity('a', addr='10.0.80.1')
        b = _make_test_identity('b', addr='10.0.80.2')

        ns = UUID('00000000-0000-0000-0000-000000000bbb')
        group_uuid = uuid5(ns, 'at-conformance:group:rotate')
        a_group = Group(group_uuid, {}, 'g1',
                        Encryptor(k1_seed, public_only=False),
                        _public_only=False)
        # B's view of the group has rotated to K2 — different keypair.
        b_group = Group(group_uuid, {}, 'g1',
                        Encryptor(k2_seed, public_only=False),
                        _public_only=False)

        msg = Message(CfgIds.identity, 'request_access', obj_json,
                      from_whom=a, encrypt=True)
        plaintext = bytes(msg)

        encrypted = a_group.encrypt(plaintext, a_group, nonce=nonce)
        try:
            b_group.decrypt(encrypted, b_group)
        except CryptoError:
            _assert_decrypt_failed(case, 'b')
            return
        raise AssertionError(
            'b: post-rotation decrypt of pre-rotation ciphertext '
            'unexpectedly succeeded'
        )

    # ------------------------------------------------------------------
    # Negative kind
    # ------------------------------------------------------------------

    def run_negative(self, case: Case) -> None:
        from ...common.negative_runner import run_wire_negative
        expected = case.data['expected']['reason_class']
        observed = run_wire_negative(self.corpus_root, case)
        if observed != expected:
            raise AssertionError(
                f'reason_class mismatch: expected {expected!r}, '
                f'observed {observed!r}'
            )


def _assert_expected_state(case: Case, participant_id: str, parsed) -> None:
    """Compare a parsed Message against `case.expected_state.<participant_id>`.

    Shared by network scenarios so adapters don't redefine the routed_*
    / verified comparison each time. Caller passes the participant id
    to support multi-receiver scenarios (e.g. broadcast fan-out).
    """
    expected = case.data.get('expected_state', {}).get(participant_id, {}) or {}
    rp = expected.get('routed_process')
    rf = expected.get('routed_function')
    ver = expected.get('verified')
    if rp is not None and parsed.process != rp:
        raise AssertionError(
            f'{participant_id}: routed_process mismatch: '
            f'expected {rp!r}, got {parsed.process!r}'
        )
    if rf is not None and parsed.function != rf:
        raise AssertionError(
            f'{participant_id}: routed_function mismatch: '
            f'expected {rf!r}, got {parsed.function!r}'
        )
    if ver is not None and bool(parsed.verified) != bool(ver):
        raise AssertionError(
            f'{participant_id}: verified mismatch: '
            f'expected {ver}, got {parsed.verified}'
        )


def _assert_expected_flags(case: Case, participant_id: str,
                           actual: dict[str, Any]) -> None:
    """Compare a dict of BOOLEAN observables against `expected_state`.

    The sibling of `_assert_expected_state`, which compares a parsed Message.
    Table-driven cases (resolution tables, format gates) observe flags rather
    than a routed message, and their scenarios declare those flags -- so they
    should be CHECKED rather than left as documentation the adapter happens to
    agree with. Every key the scenario declares must be present here: a
    scenario asserting something the adapter never measured would otherwise
    pass vacuously, which is the failure mode that makes a corpus reassuring
    and wrong.
    """
    expected = case.data.get('expected_state', {}).get(participant_id, {}) or {}
    for key, want in expected.items():
        if key not in actual:
            raise AssertionError(
                f'{participant_id}: scenario expects {key!r} but the adapter '
                f'did not measure it')
        if bool(actual[key]) != bool(want):
            raise AssertionError(
                f'{participant_id}: {key} mismatch: expected {want}, '
                f'got {actual[key]}')


def _assert_expected_state_b(case: Case, parsed) -> None:
    """Convenience wrapper for legacy single-receiver scenarios."""
    _assert_expected_state(case, 'b', parsed)


def _assert_decrypt_failed(case: Case, participant_id: str) -> None:
    """For crypto-rejection scenarios: assert the YAML pins
    `expected_state.<pid>.decrypt_failed: true`. The runner caught the
    expected CryptoError before calling this; if the YAML didn't
    declare the expectation, the scenario is misconfigured.
    Symmetric helper exists in the C network adapter.
    """
    expected = case.data.get('expected_state', {}).get(participant_id, {}) or {}
    if not expected.get('decrypt_failed', False):
        raise AssertionError(
            f'{participant_id}: scenario observed decrypt failure but '
            f'expected_state did not declare decrypt_failed: true'
        )


def _make_test_identity(pid: str, addr: str) -> 'Identity':
    """Build a deterministic Identity for the conformance harness.

    Mirrors the seed-derivation used by the identity adapter so two
    invocations produce byte-identical keys.
    """
    import hashlib
    from uuid import UUID, uuid5
    from autonomous_trust.core.algorithms.impl import AgreementImpl
    from autonomous_trust.core.identity import Identity
    from autonomous_trust.core.identity.encrypt import Encryptor
    from autonomous_trust.core.identity.sign import Signature

    sig_seed = hashlib.sha256(b'at-conformance:sig:' + pid.encode()).hexdigest().encode('ascii')
    enc_seed = hashlib.sha256(b'at-conformance:enc:' + pid.encode()).hexdigest().encode('ascii')
    ns = UUID('00000000-0000-0000-0000-000000000aaa')
    uuid = uuid5(ns, f'at-conformance:{pid}')
    return Identity(
        uuid, addr, f'{pid}.scenario',
        Signature(sig_seed, public_only=False),
        Encryptor(enc_seed, public_only=False),
        pid, False, 0, AgreementImpl.POA.value,
    )
