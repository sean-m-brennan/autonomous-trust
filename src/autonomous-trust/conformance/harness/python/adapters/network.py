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
from pathlib import Path
from typing import Any
from uuid import UUID

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

from ...common.scenario_loader import Case, hex_to_bytes


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
                self._round_trip(constructor, input_args, mode=mode, wire_format=fmt)

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
                    mode: str, wire_format: str) -> None:
        from autonomous_trust.core.config.configuration import (
            Configuration, SerializeMode, WireFormat,
        )

        old_mode, old_fmt = Configuration.mode, Configuration.wire_format
        Configuration.mode = SerializeMode[mode.upper()]
        Configuration.wire_format = WireFormat[wire_format.upper()]
        try:
            self._round_trip_unguarded(constructor, args)
        finally:
            Configuration.mode, Configuration.wire_format = old_mode, old_fmt

    def _round_trip_unguarded(self, constructor: str, args: dict[str, Any]) -> None:
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
            return

        if constructor == 'Signature':
            from autonomous_trust.core.identity.sign import Signature
            sig = Signature.generate()
            pub = sig.publish()
            data = sig.to_string()
            restored = Signature.from_string(data)
            assert restored.publish() == pub, 'Signature pub-key drift'
            assert restored.public_only is True
            return

        if constructor == 'Message':
            # Message is not a Configuration subclass; it has its own
            # JSON envelope (process|function|data|signature). The vector
            # round-trips that envelope without exercising mode/wire-format.
            self._message_round_trip(args)
            return

        raise AssertionError(f'unsupported wire_vector constructor: {constructor!r}')

    def _message_round_trip(self, args: dict[str, Any]) -> None:
        from autonomous_trust.core.network.message import Message

        process = args['process']
        function = args['function']
        obj = args.get('obj', '')
        encrypt = bool(args.get('encrypt', False))
        msg = Message(process, function, obj, encrypt=encrypt)
        wire = bytes(msg)
        restored = Message.parse(wire, sender=None, validate=False)
        assert restored.process == msg.process, 'Message.process drift'
        assert restored.function == msg.function, 'Message.function drift'
        # Message.parse re-runs the obj-coercion logic (Configuration auto-deser
        # only fires for objects with __type__); for the simple string case we
        # built, restored.obj should be string-equal.
        assert str(restored.obj) == str(msg.obj), \
            f'Message.obj drift: {restored.obj!r} != {msg.obj!r}'
        assert restored.encrypt == msg.encrypt, 'Message.encrypt drift'

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
    # Out-of-scope kinds for Phase A
    # ------------------------------------------------------------------

    def run_scenario(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError(
            'scenario kind not yet implemented for network protocol (Phase A: vectors only)'
        )

    def run_negative(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError(
            'negative kind not yet implemented for network protocol (Phase A: vectors only)'
        )
