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

"""Shared helpers for `kind: negative` conformance cases.

A negative case takes a clean wire-format buffer produced for some step of a
base scenario, applies a deterministic mutation to it, and asks the real
parser to refuse the result. The expected refusal category is pinned in
`expected.reason_class`.

The mutation and observation routines here are protocol-agnostic and
byte-identical to the C side (`src/c/conformance/negative_runner.c`).
Adapters only own building the clean buffer and feeding the mutated buffer
back into their real parser.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from .scenario_loader import Case, _load_schemas, load_case


def apply_mutation(wire_bytes: bytes, mutation: dict[str, Any]) -> bytes:
    """Apply one mutation directive to a JSON wire-format buffer.

    Supported ops:
      - flip_byte on `signature`
      - flip_byte on `payload`     (flips one byte of the base64 data field)
      - truncate on `wire_bytes`
      - drop_field on `envelope.<name>` (removes a top-level JSON field)
    Other ops raise NotImplementedError; the harness then skips the case.
    """
    op = mutation['op']
    target = mutation['target']

    if op == 'flip_byte' and target == 'signature':
        return _flip_signature_byte(wire_bytes, mutation.get('index', 0))
    if op == 'flip_byte' and target == 'payload':
        return _flip_payload_byte(wire_bytes, mutation.get('index', 0))
    if op == 'truncate' and target == 'wire_bytes':
        n = mutation.get('index')
        if not isinstance(n, int) or n < 0 or n >= len(wire_bytes):
            raise NotImplementedError(
                f'truncate index out of range: {n} (buf is {len(wire_bytes)} bytes)'
            )
        return wire_bytes[:n]
    if op == 'drop_field' and target.startswith('envelope.'):
        return _drop_envelope_field(wire_bytes, target[len('envelope.'):])

    raise NotImplementedError(f'mutation op={op!r} target={target!r} not implemented')


def _flip_signature_byte(wire_bytes: bytes, index: int) -> bytes:
    """Flip one byte of the hex-encoded `signature` field in a JSON wire buffer.

    The signature is stored as an ASCII hex string in the JSON; flipping one
    hex character (xor with 0x01 followed by hex normalization) yields a
    deterministic but still well-formed hex string that decodes to a
    different signature value. Both Python's `Message.parse` and C's
    `net_message_from_wire` see the mutated hex, decode it, and fail the
    Ed25519 verification against the unmodified content string.
    """
    try:
        wire = json.loads(wire_bytes.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NotImplementedError(
            f'cannot flip signature byte: wire buffer is not JSON ({exc})'
        ) from exc
    sig_hex = wire.get('signature')
    if not isinstance(sig_hex, str) or not sig_hex:
        raise NotImplementedError('wire buffer carries no signature field')
    if index < 0 or index >= len(sig_hex):
        raise NotImplementedError(
            f'flip_byte index {index} out of range for {len(sig_hex)}-char signature'
        )
    # Toggle the low bit of the hex nibble. '0'<->'1', 'a'<->'b', etc. Stays
    # within the [0-9a-f] alphabet so the consumer's hex decoder still
    # accepts the byte; the resulting signature just won't verify.
    ch = sig_hex[index]
    if ch in '0123456789':
        flipped = str((int(ch) ^ 1))
    elif ch in 'abcdef':
        flipped = 'abcdef'[(ord(ch) - ord('a')) ^ 1]
    elif ch in 'ABCDEF':
        flipped = 'ABCDEF'[(ord(ch) - ord('A')) ^ 1]
    else:
        raise NotImplementedError(f'non-hex character {ch!r} in signature field')
    new_sig = sig_hex[:index] + flipped + sig_hex[index + 1:]
    wire['signature'] = new_sig
    # Re-serialize with the same separators Python's Message.__bytes__ uses
    # so the output is byte-stable across runs.
    return json.dumps(wire, separators=(',', ':')).encode('utf-8')


def _flip_payload_byte(wire_bytes: bytes, index: int) -> bytes:
    """Flip one byte of the base64 `data` field in a JSON wire buffer.

    The wire envelope carries the original payload as base64 under `data`.
    A flipped base64 character changes the decoded plaintext that the
    parser hashes for signature verification, so the signature must fail.
    Stays within the base64 alphabet so the consumer's b64 decoder still
    accepts the field (the failure mode is signature_verification_failed,
    not envelope_malformed).
    """
    try:
        wire = json.loads(wire_bytes.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NotImplementedError(
            f'cannot flip payload byte: wire buffer is not JSON ({exc})'
        ) from exc
    data_b64 = wire.get('data')
    if not isinstance(data_b64, str) or not data_b64:
        raise NotImplementedError('wire buffer carries no data field to flip')
    if index < 0 or index >= len(data_b64):
        raise NotImplementedError(
            f'flip_byte index {index} out of range for {len(data_b64)}-char payload'
        )
    ch = data_b64[index]
    # Pick a different but still-valid base64 character. Pad chars '=' are
    # left alone (truncating would change length and could affect decode).
    if ch == '=':
        raise NotImplementedError('refusing to flip a base64 pad char')
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    idx_in_alpha = alphabet.find(ch)
    if idx_in_alpha < 0:
        raise NotImplementedError(f'non-base64 character {ch!r} in data field')
    flipped = alphabet[(idx_in_alpha + 1) % len(alphabet)]
    wire['data'] = data_b64[:index] + flipped + data_b64[index + 1:]
    return json.dumps(wire, separators=(',', ':')).encode('utf-8')


def classify_op(mutation: dict[str, Any]) -> str:
    """Return the observable reason_class implied by a mutation op.

    The parser's job is to refuse the buffer; the *category* of refusal is a
    function of what was mutated, not what the parser happens to report.
    Truncation produces `envelope_truncated`; signature/payload corruption
    produces `signature_verification_failed`; everything else producing a
    parse error falls under `envelope_malformed`.
    """
    op = mutation['op']
    target = mutation['target']
    if op == 'truncate':
        return 'envelope_truncated'
    if op == 'flip_byte' and target in ('signature', 'payload'):
        return 'signature_verification_failed'
    return 'envelope_malformed'


def run_wire_negative(corpus_root: Path, case: Case) -> str:
    """Run a `kind: negative` case end-to-end and return the observed reason.

    Loads the base scenario referenced by `case.data['based_on']`, builds
    a deterministic signing Identity for the targeted step's `from` field,
    builds a generic signed Message envelope (process = base case's
    protocol, function = step['function'], payload = '{}'), serializes,
    applies the mutation, re-parses through the production
    `Message.parse`, and returns the observed reason_class.

    Caller compares the return value against
    `case.data['expected']['reason_class']`.

    Protocol-agnostic: the wire envelope is the same for every AT
    protocol; only obj payloads differ in scenarios, and for negative
    cases (which exercise the envelope, signature, or transport-bytes)
    the obj content is irrelevant — a fixed `'{}'` keeps the test
    deterministic.
    """
    # Defer Message import: keeps the common harness importable from
    # tools that don't have autonomous_trust on the path.
    from autonomous_trust.core.network.message import Message

    based_on = case.data.get('based_on')
    if not based_on:
        raise AssertionError('negative case missing based_on')
    base_path = (corpus_root / based_on).resolve()
    if corpus_root.resolve() not in base_path.parents:
        raise AssertionError(f'based_on escapes corpus root: {based_on}')
    schemas = _load_schemas(corpus_root / 'schema')
    base_case = load_case(base_path, schemas)
    if base_case.protocol != case.protocol:
        raise AssertionError(
            f'based_on protocol {base_case.protocol!r} does not match '
            f'negative case protocol {case.protocol!r}'
        )

    mutation = case.data['mutation']
    step_id = mutation.get('step_id', 1)
    step = next(
        (s for s in base_case.data['steps'] if s['id'] == step_id), None,
    )
    if step is None:
        raise AssertionError(f'base scenario has no step with id {step_id}')
    if 'in_response_to' in step:
        raise NotImplementedError(
            f'negative step_id {step_id} is an assertion step; v1 only '
            f'mutates source steps'
        )

    sender = _make_signer_identity(step['from'])
    msg = Message(case.protocol, step['function'], '{}',
                  from_whom=sender, encrypt=False)
    wire = bytes(msg)
    mutated = apply_mutation(wire, mutation)

    try:
        parsed = Message.parse(mutated, sender)
    except Exception:  # noqa: BLE001 — parser raises a variety of types
        return classify_op(mutation)
    if getattr(parsed, 'verified', False) is False:
        return 'signature_verification_failed'
    return 'no_rejection_observed'


def _make_signer_identity(pid: str):
    """Build a deterministic Identity for negative-case wire signing.

    Lives here (rather than in any one protocol adapter) so all five
    protocols' run_negative calls produce identical signing keys for the
    same participant id, simplifying cross-protocol authoring.
    """
    from autonomous_trust.core.algorithms.impl import AgreementImpl
    from autonomous_trust.core.identity import Identity
    from autonomous_trust.core.identity.encrypt import Encryptor
    from autonomous_trust.core.identity.sign import Signature

    ns = UUID('00000000-0000-0000-0000-000000000aaa')
    uuid = uuid5(ns, f'at-conformance:neg:{pid}')
    sig_seed = hashlib.sha256(
        b'at-conformance:neg:sig:' + pid.encode('utf-8'),
    ).hexdigest().encode('ascii')
    enc_seed = hashlib.sha256(
        b'at-conformance:neg:enc:' + pid.encode('utf-8'),
    ).hexdigest().encode('ascii')
    return Identity(
        uuid, '10.0.90.1', f'{pid}.neg', pid,
        Signature(sig_seed, public_only=False),
        Encryptor(enc_seed, public_only=False),
        'me', False, 0, AgreementImpl.POA.value,
    )
